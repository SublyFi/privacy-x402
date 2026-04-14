//! Atomic Service Channel (ASC) Lifecycle Manager — Phase 3
//!
//! Per design doc §5.4 and §5.5 (A402 Algorithm 1 & 2):
//!   Open → Lock (request submitted) → Pending (adaptor verified) → Closed (settled)
//!
//! The ASC manager handles:
//!   - Channel open/close lifecycle
//!   - Fund locking per request
//!   - Adaptor signature verification (pVerify)
//!   - Conditional payment issuance
//!   - Secret extraction and result decryption
//!   - Settlement crediting

use chrono::Utc;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use tracing::info;

use crate::adaptor_sig::{self, AdaptorPreSignature};
use crate::error::EnclaveError;
use crate::state::{
    ChannelBalance, ChannelId, ChannelRequest, ChannelState, ChannelStatus, ProviderCredit,
    VaultState,
};

/// Default request expiry window (seconds)
const REQUEST_EXPIRY_SEC: i64 = 120;

pub struct FinalizeOutcome {
    pub request_id: String,
    pub result_bytes: Vec<u8>,
    pub amount: u64,
    pub request: ChannelRequest,
}

pub struct CloseOutcome {
    pub client: Pubkey,
    pub provider_id: String,
    pub returned_to_client: u64,
    pub provider_earned: u64,
    pub settlement_id: Option<String>,
    pub closed_channel: ChannelState,
    pub previous_provider_credit: Option<ProviderCredit>,
}

/// Open a new ASC between a client and provider.
///
/// Funds remain in client_balance.free; individual requests lock funds.
pub fn open_channel(
    vault: &VaultState,
    client: &Pubkey,
    provider_id: &str,
    initial_deposit: u64,
) -> Result<ChannelId, EnclaveError> {
    let channel_id = format!("ch_{}", uuid::Uuid::now_v7());
    open_channel_with_id(
        vault,
        channel_id.clone(),
        client,
        provider_id,
        initial_deposit,
    )?;
    Ok(channel_id)
}

pub fn open_channel_with_id(
    vault: &VaultState,
    channel_id: ChannelId,
    client: &Pubkey,
    provider_id: &str,
    initial_deposit: u64,
) -> Result<(), EnclaveError> {
    // Validate provider exists
    vault
        .providers
        .get(provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;

    // Validate client has enough free balance
    let balance = vault
        .client_balances
        .get(client)
        .ok_or(EnclaveError::InsufficientBalance)?;
    if balance.free < initial_deposit {
        return Err(EnclaveError::InsufficientBalance);
    }
    drop(balance);

    let now = Utc::now().timestamp();

    let channel = ChannelState {
        channel_id: channel_id.clone(),
        client: *client,
        provider_id: provider_id.to_string(),
        balance: ChannelBalance {
            client_free: initial_deposit,
            client_locked: 0,
            provider_earned: 0,
        },
        status: ChannelStatus::Open,
        nonce: 0,
        created_at: now,
        updated_at: now,
        used_request_ids: std::collections::HashSet::new(),
        active_request: None,
    };

    // Lock the initial deposit from client's free balance
    vault.reserve_balance(client, initial_deposit)?;

    vault.active_channels.insert(channel_id.clone(), channel);

    info!(channel_id = %channel_id, client = %client, provider = %provider_id, deposit = initial_deposit, "ASC opened");

    Ok(())
}

pub fn rollback_open_channel(vault: &VaultState, channel_id: &str) -> Result<(), EnclaveError> {
    let (_, channel) = vault
        .active_channels
        .remove(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;
    let total_channel_amount = channel.balance.client_free
        + channel.balance.client_locked
        + channel.balance.provider_earned;
    if total_channel_amount > 0 {
        vault.release_balance(&channel.client, total_channel_amount)?;
    }
    Ok(())
}

/// Stage 1: Submit a request to the channel — locks funds for this request.
///
/// Transitions: Open → Locked
pub fn submit_request(
    vault: &VaultState,
    channel_id: &str,
    request_id: &str,
    amount: u64,
    request_hash: [u8; 32],
) -> Result<(), EnclaveError> {
    let mut channel = vault
        .active_channels
        .get_mut(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;

    if channel.status != ChannelStatus::Open {
        return Err(EnclaveError::InvalidChannelStatus(format!(
            "expected Open, got {:?}",
            channel.status
        )));
    }

    if channel.used_request_ids.contains(request_id) {
        return Err(EnclaveError::ChannelRequestIdReused);
    }

    if channel.balance.client_free < amount {
        return Err(EnclaveError::InsufficientBalance);
    }

    let now = Utc::now().timestamp();

    // Lock funds within the channel
    channel.balance.client_free -= amount;
    channel.balance.client_locked += amount;
    channel.status = ChannelStatus::Locked;
    channel.nonce += 1;
    channel.updated_at = now;
    channel.used_request_ids.insert(request_id.to_string());

    channel.active_request = Some(ChannelRequest {
        request_id: request_id.to_string(),
        amount,
        request_hash,
        provider_pubkey: None,
        adaptor_point: None,
        provider_pre_sig: None,
        encrypted_result: None,
        result_hash: None,
        created_at: now,
        expires_at: now + REQUEST_EXPIRY_SEC,
    });

    info!(
        channel_id,
        request_id, amount, "Request submitted, funds locked"
    );

    Ok(())
}

pub fn rollback_submit_request(
    vault: &VaultState,
    channel_id: &str,
    request_id: &str,
) -> Result<(), EnclaveError> {
    let mut channel = vault
        .active_channels
        .get_mut(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;

    let request = channel
        .active_request
        .as_ref()
        .ok_or(EnclaveError::ChannelNotFound)?;
    if request.request_id != request_id {
        return Err(EnclaveError::ChannelNotFound);
    }
    let amount = request.amount;

    channel.balance.client_locked = channel.balance.client_locked.saturating_sub(amount);
    channel.balance.client_free += amount;
    channel.status = ChannelStatus::Open;
    channel.active_request = None;
    channel.nonce = channel.nonce.saturating_sub(1);
    channel.updated_at = Utc::now().timestamp();
    channel.used_request_ids.remove(request_id);

    Ok(())
}

/// Stage 2: Provider TEE delivers adaptor pre-signature and encrypted result.
///
/// Verifies the adaptor pre-signature using pVerify.
/// Transitions: Locked → Pending
pub fn deliver_adaptor(
    vault: &VaultState,
    channel_id: &str,
    adaptor_point_bytes: [u8; 32],
    pre_sig: AdaptorPreSignature,
    encrypted_result: Vec<u8>,
    result_hash: [u8; 32],
    provider_pubkey: &[u8; 32],
) -> Result<(), EnclaveError> {
    let mut channel = vault
        .active_channels
        .get_mut(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;

    if channel.status != ChannelStatus::Locked {
        return Err(EnclaveError::InvalidChannelStatus(format!(
            "expected Locked, got {:?}",
            channel.status
        )));
    }

    let request = channel
        .active_request
        .as_ref()
        .ok_or(EnclaveError::ChannelNotFound)?;

    // Check request hasn't expired
    let now = Utc::now().timestamp();
    if now > request.expires_at {
        // Unlock funds and reset to Open
        let amount = request.amount;
        channel.balance.client_locked -= amount;
        channel.balance.client_free += amount;
        channel.status = ChannelStatus::Open;
        channel.active_request = None;
        channel.updated_at = now;
        return Err(EnclaveError::ChannelRequestExpired);
    }

    // Decompress adaptor point T
    let adaptor_point = CompressedEdwardsY(adaptor_point_bytes)
        .decompress()
        .ok_or(EnclaveError::InvalidAdaptorSignature)?;

    // Build the message for signature verification:
    // channel_id:request_id:amount
    let message = build_payment_message(
        &channel.channel_id,
        &request.request_id,
        request.amount,
        &request.request_hash,
    );

    // pVerify: verify the adaptor pre-signature
    if !adaptor_sig::pre_verify(provider_pubkey, &message, &adaptor_point, &pre_sig) {
        return Err(EnclaveError::InvalidAdaptorSignature);
    }

    // Store adaptor data in the request
    let req_mut = channel.active_request.as_mut().unwrap();
    req_mut.provider_pubkey = Some(*provider_pubkey);
    req_mut.adaptor_point = Some(adaptor_point_bytes);
    req_mut.provider_pre_sig = Some(pre_sig);
    req_mut.encrypted_result = Some(encrypted_result);
    req_mut.result_hash = Some(result_hash);

    channel.status = ChannelStatus::Pending;
    channel.nonce += 1;
    channel.updated_at = now;

    info!(
        channel_id,
        "Adaptor pre-signature verified, channel pending"
    );

    Ok(())
}

pub fn rollback_deliver_adaptor(
    vault: &VaultState,
    channel_id: &str,
    request_id: &str,
) -> Result<(), EnclaveError> {
    let mut channel = vault
        .active_channels
        .get_mut(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;

    if channel.status != ChannelStatus::Pending {
        return Err(EnclaveError::InvalidChannelStatus(format!(
            "expected Pending, got {:?}",
            channel.status
        )));
    }

    let request = channel
        .active_request
        .as_mut()
        .ok_or(EnclaveError::ChannelNotFound)?;
    if request.request_id != request_id {
        return Err(EnclaveError::ChannelNotFound);
    }

    request.provider_pubkey = None;
    request.adaptor_point = None;
    request.provider_pre_sig = None;
    request.encrypted_result = None;
    request.result_hash = None;

    channel.status = ChannelStatus::Locked;
    channel.nonce = channel.nonce.saturating_sub(1);
    channel.updated_at = Utc::now().timestamp();

    Ok(())
}

/// Stage 4 (off-chain path): Provider reveals adaptor secret t.
///
/// Vault extracts t, decrypts result, and credits provider.
/// Transitions: Pending → Open (ready for next request)
pub fn finalize_offchain(
    vault: &VaultState,
    channel_id: &str,
    adaptor_secret_bytes: [u8; 32],
) -> Result<FinalizeOutcome, EnclaveError> {
    let mut channel = vault
        .active_channels
        .get_mut(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;

    if channel.status != ChannelStatus::Pending {
        return Err(EnclaveError::InvalidChannelStatus(format!(
            "expected Pending, got {:?}",
            channel.status
        )));
    }

    let request = channel
        .active_request
        .as_ref()
        .ok_or(EnclaveError::ChannelNotFound)?;

    let pre_sig = request
        .provider_pre_sig
        .as_ref()
        .ok_or(EnclaveError::InvalidAdaptorSignature)?;
    let adaptor_point_bytes = request
        .adaptor_point
        .ok_or(EnclaveError::InvalidAdaptorSignature)?;
    let provider_pubkey = request
        .provider_pubkey
        .ok_or(EnclaveError::InvalidAdaptorSignature)?;
    let request_id = request.request_id.clone();
    let request_snapshot = request.clone();

    // Reconstruct adaptor point
    let adaptor_point = CompressedEdwardsY(adaptor_point_bytes)
        .decompress()
        .ok_or(EnclaveError::InvalidAdaptorSignature)?;

    // Verify that t·G == T (the provided secret matches the adaptor point)
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;

    let t = Scalar::from_canonical_bytes(adaptor_secret_bytes)
        .into_option()
        .ok_or(EnclaveError::InvalidAdaptorSignature)?;

    let expected_t_point = &t * ED25519_BASEPOINT_POINT;
    if expected_t_point != adaptor_point {
        return Err(EnclaveError::InvalidAdaptorSignature);
    }

    // Defense-in-depth: adapt pre-signature with t and verify as valid Ed25519 signature
    let full_sig = adaptor_sig::adapt(pre_sig, &t, &adaptor_point)
        .ok_or(EnclaveError::InvalidAdaptorSignature)?;

    let message = build_payment_message(
        &channel.channel_id,
        &request.request_id,
        request.amount,
        &request.request_hash,
    );

    // Retrieve provider pubkey from channel to verify adapted signature
    if !adaptor_sig::verify_adapted(&provider_pubkey, &message, &full_sig) {
        return Err(EnclaveError::InvalidAdaptorSignature);
    }

    // Decrypt result using t as symmetric key
    let encrypted_result = request
        .encrypted_result
        .clone()
        .ok_or(EnclaveError::ChannelNotFound)?;
    let decrypted = decrypt_with_scalar(&encrypted_result, &adaptor_secret_bytes);

    // Verify result hash
    if let Some(expected_hash) = request.result_hash {
        let actual_hash = sha256_hash(&decrypted);
        if actual_hash != expected_hash {
            return Err(EnclaveError::Internal(
                "Result hash mismatch after decryption".into(),
            ));
        }
    }

    let amount = request.amount;
    let now = Utc::now().timestamp();

    // Credit provider, unlock client_locked
    channel.balance.client_locked -= amount;
    channel.balance.provider_earned += amount;
    channel.status = ChannelStatus::Open;
    channel.active_request = None;
    channel.nonce += 1;
    channel.updated_at = now;

    info!(channel_id, amount, "Off-chain finalization complete");

    Ok(FinalizeOutcome {
        request_id,
        result_bytes: decrypted,
        amount,
        request: request_snapshot,
    })
}

pub fn rollback_finalize_offchain(
    vault: &VaultState,
    channel_id: &str,
    request: ChannelRequest,
) -> Result<(), EnclaveError> {
    let mut channel = vault
        .active_channels
        .get_mut(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;

    if channel.status != ChannelStatus::Open || channel.active_request.is_some() {
        return Err(EnclaveError::InvalidChannelStatus(format!(
            "expected Open without active request, got {:?}",
            channel.status
        )));
    }

    channel.balance.client_locked += request.amount;
    channel.balance.provider_earned = channel
        .balance
        .provider_earned
        .saturating_sub(request.amount);
    channel.status = ChannelStatus::Pending;
    channel.active_request = Some(request);
    channel.nonce = channel.nonce.saturating_sub(1);
    channel.updated_at = Utc::now().timestamp();

    Ok(())
}

pub fn finalize_replayed_request(
    vault: &VaultState,
    channel_id: &str,
    request_id: &str,
    amount_paid: u64,
) -> Result<(), EnclaveError> {
    let mut channel = vault
        .active_channels
        .get_mut(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;

    if channel.status != ChannelStatus::Pending {
        return Err(EnclaveError::InvalidChannelStatus(format!(
            "expected Pending, got {:?}",
            channel.status
        )));
    }

    let request = channel
        .active_request
        .as_ref()
        .ok_or(EnclaveError::ChannelNotFound)?;

    if request.request_id != request_id {
        return Err(EnclaveError::ChannelNotFound);
    }
    if request.amount != amount_paid {
        return Err(EnclaveError::Internal(
            "WAL replay amount mismatch for finalized channel request".into(),
        ));
    }

    channel.balance.client_locked = channel.balance.client_locked.saturating_sub(amount_paid);
    channel.balance.provider_earned += amount_paid;
    channel.status = ChannelStatus::Open;
    channel.active_request = None;
    channel.nonce += 1;
    channel.updated_at = Utc::now().timestamp();

    Ok(())
}

/// Close a channel and settle accumulated provider earnings.
///
/// Returns the total provider earnings to be batched on-chain.
pub fn close_channel(vault: &VaultState, channel_id: &str) -> Result<CloseOutcome, EnclaveError> {
    close_channel_with_settlement_id(vault, channel_id, None)
}

pub fn close_channel_with_settlement_id(
    vault: &VaultState,
    channel_id: &str,
    settlement_id_override: Option<String>,
) -> Result<CloseOutcome, EnclaveError> {
    let channel = vault
        .active_channels
        .get(channel_id)
        .ok_or(EnclaveError::ChannelNotFound)?;

    if channel.status != ChannelStatus::Open {
        return Err(EnclaveError::InvalidChannelStatus(format!(
            "expected Open, got {:?} (close only from Open)",
            channel.status
        )));
    }

    let client = channel.client;
    let provider_id = channel.provider_id.clone();
    let remaining_free = channel.balance.client_free;
    let provider_earned = channel.balance.provider_earned;
    let channel_snapshot = channel.clone();
    let previous_provider_credit = if provider_earned > 0 {
        vault
            .provider_credits
            .get(&provider_id)
            .map(|credit| credit.clone())
    } else {
        None
    };
    let settlement_id = if provider_earned > 0 {
        Some(settlement_id_override.unwrap_or_else(|| format!("asc_{}", uuid::Uuid::now_v7())))
    } else {
        None
    };

    drop(channel);

    // Remove channel
    vault.active_channels.remove(channel_id);

    // Release the full channel amount (free + earned) from client_balances.locked
    let total_channel_amount = remaining_free + provider_earned;
    if total_channel_amount > 0 {
        let mut balance = vault
            .client_balances
            .get_mut(&client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.locked = balance.locked.saturating_sub(total_channel_amount);
        // Return only the remaining_free portion back to client's free balance
        balance.free += remaining_free;
    }

    // Credit provider with total earnings (will be batched on-chain)
    if provider_earned > 0 {
        let now = Utc::now().timestamp();
        let provider_reg = vault
            .providers
            .get(&provider_id)
            .ok_or(EnclaveError::ProviderNotFound)?;
        let settlement_id = settlement_id
            .clone()
            .ok_or(EnclaveError::Internal("missing settlement id".into()))?;

        vault
            .provider_credits
            .entry(provider_id.clone())
            .and_modify(|credit| {
                credit.credited_amount += provider_earned;
                credit.settlement_ids.push(settlement_id.clone());
            })
            .or_insert_with(|| crate::state::ProviderCredit {
                provider_id: provider_id.clone(),
                settlement_token_account: provider_reg.settlement_token_account,
                credited_amount: provider_earned,
                oldest_credit_at: now,
                settlement_ids: vec![settlement_id.clone()],
            });
    }

    info!(
        channel_id,
        client = %client,
        provider = %provider_id,
        returned = remaining_free,
        earned = provider_earned,
        "ASC closed"
    );

    Ok(CloseOutcome {
        client,
        provider_id,
        returned_to_client: remaining_free,
        provider_earned,
        settlement_id,
        closed_channel: channel_snapshot,
        previous_provider_credit,
    })
}

pub fn rollback_close_channel(
    vault: &VaultState,
    outcome: CloseOutcome,
) -> Result<(), EnclaveError> {
    let total_channel_amount = outcome.returned_to_client + outcome.provider_earned;
    if total_channel_amount > 0 {
        let mut balance = vault
            .client_balances
            .get_mut(&outcome.client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.locked += total_channel_amount;
        balance.free = balance.free.saturating_sub(outcome.returned_to_client);
    }

    if outcome.provider_earned > 0 {
        match outcome.previous_provider_credit {
            Some(previous_credit) => {
                vault
                    .provider_credits
                    .insert(outcome.provider_id.clone(), previous_credit);
            }
            None => {
                vault.provider_credits.remove(&outcome.provider_id);
            }
        }
    }

    vault.active_channels.insert(
        outcome.closed_channel.channel_id.clone(),
        outcome.closed_channel,
    );

    Ok(())
}

/// Expire timed-out requests in locked channels.
/// Called from the background task loop.
pub fn expire_stale_requests(vault: &VaultState) {
    let now = Utc::now().timestamp();

    for mut entry in vault.active_channels.iter_mut() {
        let channel = entry.value_mut();
        if channel.status != ChannelStatus::Locked && channel.status != ChannelStatus::Pending {
            continue;
        }

        if let Some(ref request) = channel.active_request {
            if now > request.expires_at {
                let amount = request.amount;
                info!(
                    channel_id = %channel.channel_id,
                    request_id = %request.request_id,
                    "Expiring stale channel request"
                );

                channel.balance.client_locked -= amount;
                channel.balance.client_free += amount;
                channel.status = ChannelStatus::Open;
                channel.active_request = None;
                channel.nonce += 1;
                channel.updated_at = now;
            }
        }
    }
}

// ── Helpers ──

/// Build the canonical payment message for adaptor signature.
fn build_payment_message(
    channel_id: &str,
    request_id: &str,
    amount: u64,
    request_hash: &[u8; 32],
) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        channel_id,
        request_id,
        amount,
        hex::encode(request_hash)
    )
    .into_bytes()
}

/// Decrypt data encrypted with adaptor secret t as XOR key (SHA256-CTR stream).
fn decrypt_with_scalar(ciphertext: &[u8], key_bytes: &[u8; 32]) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut block_idx = 0u64;

    for chunk in ciphertext.chunks(32) {
        // Derive keystream block: SHA256(key || block_index)
        let mut hasher = Sha256::new();
        hasher.update(b"a402-asc-enc-v1");
        hasher.update(key_bytes);
        hasher.update(block_idx.to_le_bytes());
        let keystream = hasher.finalize();

        for (i, &byte) in chunk.iter().enumerate() {
            plaintext.push(byte ^ keystream[i]);
        }

        block_idx += 1;
    }

    plaintext
}

/// Encrypt data with adaptor secret (same as decrypt — XOR is symmetric).
pub fn encrypt_with_scalar(plaintext: &[u8], key_bytes: &[u8; 32]) -> Vec<u8> {
    decrypt_with_scalar(plaintext, key_bytes)
}

fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptor_sig::{self, AdaptorKeyPair};
    use crate::state::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn setup_vault() -> VaultState {
        let signing_key = SigningKey::generate(&mut OsRng);
        let usdc_mint = Pubkey::new_unique();
        let solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        VaultState::new(
            Pubkey::new_unique(),
            signing_key,
            usdc_mint,
            [0u8; 32],
            solana,
        )
    }

    fn register_provider(vault: &VaultState, provider_id: &str) -> Pubkey {
        let provider_pubkey = Pubkey::new_unique();
        vault.providers.insert(
            provider_id.to_string(),
            ProviderRegistration {
                provider_id: provider_id.to_string(),
                display_name: "Test Provider".to_string(),
                participant_pubkey: Some(provider_pubkey),
                settlement_token_account: provider_pubkey,
                network: "solana-localnet".to_string(),
                asset_mint: Pubkey::new_unique(),
                allowed_origins: vec!["*".to_string()],
                auth_mode: "api-key".to_string(),
                api_key_hash: Some(vec![0; 32]),
                mtls_cert_fingerprint: None,
            },
        );
        provider_pubkey
    }

    #[test]
    fn test_open_channel() {
        let vault = setup_vault();
        let client = Pubkey::new_unique();
        register_provider(&vault, "provider-1");

        // Seed client balance
        vault.apply_deposit(client, 10_000_000);

        let channel_id = open_channel(&vault, &client, "provider-1", 5_000_000).unwrap();

        // Check channel exists
        let ch = vault.active_channels.get(&channel_id).unwrap();
        assert_eq!(ch.status, ChannelStatus::Open);
        assert_eq!(ch.balance.client_free, 5_000_000);
        assert_eq!(ch.balance.client_locked, 0);
        assert_eq!(ch.balance.provider_earned, 0);

        // Check client balance was locked
        let bal = vault.client_balances.get(&client).unwrap();
        assert_eq!(bal.free, 5_000_000); // 10M - 5M
        assert_eq!(bal.locked, 5_000_000);
    }

    #[test]
    fn test_submit_request() {
        let vault = setup_vault();
        let client = Pubkey::new_unique();
        register_provider(&vault, "provider-1");
        vault.apply_deposit(client, 10_000_000);

        let channel_id = open_channel(&vault, &client, "provider-1", 5_000_000).unwrap();
        submit_request(&vault, &channel_id, "req-1", 1_000_000, [1u8; 32]).unwrap();

        let ch = vault.active_channels.get(&channel_id).unwrap();
        assert_eq!(ch.status, ChannelStatus::Locked);
        assert_eq!(ch.balance.client_free, 4_000_000);
        assert_eq!(ch.balance.client_locked, 1_000_000);
    }

    #[test]
    fn test_submit_request_insufficient_channel_balance() {
        let vault = setup_vault();
        let client = Pubkey::new_unique();
        register_provider(&vault, "provider-1");
        vault.apply_deposit(client, 1_000_000);

        let channel_id = open_channel(&vault, &client, "provider-1", 1_000_000).unwrap();
        let result = submit_request(&vault, &channel_id, "req-1", 2_000_000, [1u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_request_rejects_reused_request_id() {
        let vault = setup_vault();
        let client = Pubkey::new_unique();
        register_provider(&vault, "provider-1");
        vault.apply_deposit(client, 2_000_000);

        let channel_id = open_channel(&vault, &client, "provider-1", 2_000_000).unwrap();
        submit_request(&vault, &channel_id, "req-1", 1_000_000, [1u8; 32]).unwrap();
        rollback_submit_request(&vault, &channel_id, "req-1").unwrap();

        let result = submit_request(&vault, &channel_id, "req-1", 500_000, [2u8; 32]).unwrap();
        assert_eq!(result, ());

        let provider_signing_key = SigningKey::generate(&mut OsRng);
        let provider_pubkey = provider_signing_key.verifying_key().to_bytes();
        let adaptor = AdaptorKeyPair::generate();
        let message = build_payment_message(&channel_id, "req-1", 500_000, &[2u8; 32]);
        let pre_sig =
            adaptor_sig::pre_sign(&provider_signing_key.to_bytes(), &message, &adaptor.public);
        let plaintext = b"reused request".to_vec();
        let encrypted_result = encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());
        let result_hash = sha256_hash(&plaintext);

        deliver_adaptor(
            &vault,
            &channel_id,
            adaptor.public_compressed,
            pre_sig,
            encrypted_result,
            result_hash,
            &provider_pubkey,
        )
        .unwrap();
        finalize_offchain(&vault, &channel_id, adaptor.secret.to_bytes()).unwrap();

        let reuse = submit_request(&vault, &channel_id, "req-1", 250_000, [3u8; 32]).unwrap_err();
        assert!(matches!(reuse, EnclaveError::ChannelRequestIdReused));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"hello world, this is a test of the encryption";
        let ciphertext = encrypt_with_scalar(plaintext, &key);
        let decrypted = decrypt_with_scalar(&ciphertext, &key);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_deliver_and_finalize_roundtrip_uses_request_provider_key() {
        let vault = setup_vault();
        let client = Pubkey::new_unique();
        register_provider(&vault, "provider-1");
        vault.apply_deposit(client, 10_000_000);

        let channel_id = open_channel(&vault, &client, "provider-1", 5_000_000).unwrap();
        submit_request(&vault, &channel_id, "req-1", 1_000_000, [7u8; 32]).unwrap();

        let provider_signing_key = SigningKey::generate(&mut OsRng);
        let provider_pubkey = provider_signing_key.verifying_key().to_bytes();
        let adaptor = AdaptorKeyPair::generate();
        let message = build_payment_message(&channel_id, "req-1", 1_000_000, &[7u8; 32]);
        let pre_sig =
            adaptor_sig::pre_sign(&provider_signing_key.to_bytes(), &message, &adaptor.public);

        let plaintext = b"encrypted provider result".to_vec();
        let encrypted_result = encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());
        let result_hash = sha256_hash(&plaintext);

        deliver_adaptor(
            &vault,
            &channel_id,
            adaptor.public_compressed,
            pre_sig,
            encrypted_result,
            result_hash,
            &provider_pubkey,
        )
        .unwrap();

        let outcome = finalize_offchain(&vault, &channel_id, adaptor.secret.to_bytes()).unwrap();

        assert_eq!(outcome.request_id, "req-1");
        assert_eq!(outcome.result_bytes, plaintext);
        assert_eq!(outcome.amount, 1_000_000);

        let ch = vault.active_channels.get(&channel_id).unwrap();
        assert_eq!(ch.status, ChannelStatus::Open);
        assert_eq!(ch.balance.client_free, 4_000_000);
        assert_eq!(ch.balance.client_locked, 0);
        assert_eq!(ch.balance.provider_earned, 1_000_000);
        assert!(ch.active_request.is_none());
    }

    #[test]
    fn test_close_channel_no_earnings() {
        let vault = setup_vault();
        let client = Pubkey::new_unique();
        register_provider(&vault, "provider-1");
        vault.apply_deposit(client, 10_000_000);

        let channel_id = open_channel(&vault, &client, "provider-1", 5_000_000).unwrap();

        let outcome = close_channel(&vault, &channel_id).unwrap();
        assert_eq!(outcome.client, client);
        assert_eq!(outcome.provider_id, "provider-1");
        assert_eq!(outcome.returned_to_client, 5_000_000);
        assert_eq!(outcome.provider_earned, 0);

        // Channel should be removed
        assert!(vault.active_channels.get(&channel_id).is_none());

        // Client balance should be fully restored
        let bal = vault.client_balances.get(&client).unwrap();
        assert_eq!(bal.free, 10_000_000);
        assert_eq!(bal.locked, 0);
    }

    #[test]
    fn test_close_channel_with_earnings() {
        let vault = setup_vault();
        let client = Pubkey::new_unique();
        register_provider(&vault, "provider-1");
        vault.apply_deposit(client, 10_000_000);

        let channel_id = open_channel(&vault, &client, "provider-1", 5_000_000).unwrap();

        // Simulate provider earning 1M by directly modifying channel balance
        {
            let mut ch = vault.active_channels.get_mut(&channel_id).unwrap();
            ch.balance.client_free -= 1_000_000;
            ch.balance.provider_earned += 1_000_000;
        }

        let outcome = close_channel(&vault, &channel_id).unwrap();
        assert_eq!(outcome.returned_to_client, 4_000_000);
        assert_eq!(outcome.provider_earned, 1_000_000);

        // Client locked should be fully released (5M total channel amount)
        let bal = vault.client_balances.get(&client).unwrap();
        assert_eq!(bal.free, 9_000_000); // 5M free + 4M returned
        assert_eq!(bal.locked, 0); // All locked released

        // Provider should have credit
        let credit = vault.provider_credits.get("provider-1").unwrap();
        assert_eq!(credit.credited_amount, 1_000_000);
    }
}
