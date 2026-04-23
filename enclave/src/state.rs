use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::adaptor_sig::AdaptorPreSignature;
use crate::error::EnclaveError;

// ── ASC Types (Phase 3) ──

/// Unique channel identifier
pub type ChannelId = String;

/// ASC channel status (Subly402 Algorithm 1)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStatus {
    /// Channel open, accepting requests
    Open,
    /// Request in progress, funds locked, awaiting adaptor signature
    Locked,
    /// Adaptor pre-signature verified, conditional payment issued
    Pending,
    /// Channel settled and closed
    Closed,
}

/// ASC channel balance triple
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBalance {
    pub client_free: u64,
    pub client_locked: u64,
    pub provider_earned: u64,
}

/// Active Service Channel state (enclave-only, per design doc §5.4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelState {
    pub channel_id: ChannelId,
    pub client: Pubkey,
    pub provider_id: String,
    pub balance: ChannelBalance,
    pub status: ChannelStatus,
    /// Monotonic state counter
    pub nonce: u64,
    pub created_at: i64,
    pub updated_at: i64,
    /// Request IDs already consumed by this channel (replay protection)
    pub used_request_ids: HashSet<String>,
    /// Current request being processed (if status == Locked or Pending)
    pub active_request: Option<ChannelRequest>,
}

/// A single request within an ASC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRequest {
    pub request_id: String,
    pub amount: u64,
    pub request_hash: [u8; 32],
    /// Provider TEE signing key used for this request
    pub provider_pubkey: Option<[u8; 32]>,
    /// Adaptor point T = t·G from provider TEE
    pub adaptor_point: Option<[u8; 32]>,
    /// Provider's adaptor pre-signature σ̂_S
    pub provider_pre_sig: Option<AdaptorPreSignature>,
    /// Encrypted result from provider TEE
    pub encrypted_result: Option<Vec<u8>>,
    /// Result hash h = H(res)
    pub result_hash: Option<[u8; 32]>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Payment reservation state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReservationStatus {
    Reserved,
    SettledOffchain,
    Cancelled,
    Expired,
    BatchedOnchain,
}

/// Client balance tracked inside the enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientBalance {
    pub free: u64,
    pub locked: u64,
    pub max_lock_expires_at: i64,
    pub total_deposited: u64,
    pub total_withdrawn: u64,
}

impl Default for ClientBalance {
    fn default() -> Self {
        Self {
            free: 0,
            locked: 0,
            max_lock_expires_at: 0,
            total_deposited: 0,
            total_withdrawn: 0,
        }
    }
}

/// Registered provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRegistration {
    pub provider_id: String,
    pub display_name: String,
    #[serde(default)]
    pub participant_pubkey: Option<Pubkey>,
    #[serde(default)]
    pub participant_attestation_policy_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub participant_attestation_verified_at_ms: Option<i64>,
    #[serde(default)]
    pub participant_attestation_mode: Option<String>,
    pub settlement_token_account: Pubkey,
    pub network: String,
    pub asset_mint: Pubkey,
    pub allowed_origins: Vec<String>,
    pub auth_mode: String,
    #[serde(default)]
    pub api_key_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub mtls_cert_fingerprint: Option<Vec<u8>>,
}

/// A single payment reservation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reservation {
    pub verification_id: String,
    pub reservation_id: String,
    pub payment_id: String,
    pub client: Pubkey,
    pub provider_id: String,
    pub amount: u64,
    pub request_hash: [u8; 32],
    pub payment_details_hash: [u8; 32],
    pub status: ReservationStatus,
    pub created_at: i64,
    pub expires_at: i64,
    pub settlement_id: Option<String>,
    pub settled_at: Option<i64>,
}

/// Provider credit (accumulated off-chain settlements awaiting batch)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCredit {
    pub provider_id: String,
    pub settlement_token_account: Pubkey,
    pub credited_amount: u64,
    pub oldest_credit_at: i64,
    pub settlement_ids: Vec<String>,
}

/// Pending client withdrawal authorized by the enclave but not yet finalized on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingWithdrawal {
    pub client: Pubkey,
    pub recipient_ata: Pubkey,
    pub amount: u64,
    pub withdraw_nonce: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Solana RPC + account configuration required for on-chain operations.
#[derive(Debug, Clone)]
pub struct SolanaRuntimeConfig {
    pub program_id: Pubkey,
    pub vault_token_account: Pubkey,
    pub rpc_url: String,
    pub ws_url: String,
}

/// Last synchronized view of the on-chain vault lifecycle state.
#[derive(Debug, Clone)]
pub struct VaultLifecycle {
    pub status: u8,
    pub successor_vault: Pubkey,
    pub exit_deadline: i64,
    pub synced_at_ms: i64,
}

/// Core enclave vault state
pub struct VaultState {
    pub vault_config: Pubkey,
    pub vault_signer: Arc<SigningKey>,
    pub vault_signer_pubkey: Pubkey,
    pub usdc_mint: Pubkey,
    pub attestation_policy_hash: [u8; 32],
    pub solana: SolanaRuntimeConfig,
    /// Auditor master secret for ElGamal encryption (Phase 2)
    pub auditor_master_secret: RwLock<[u8; 32]>,
    /// Current auditor epoch (u32 to match on-chain AuditRecord.auditor_epoch)
    pub auditor_epoch: AtomicU32,
    pub client_balances: DashMap<Pubkey, ClientBalance>,
    pub reservations: DashMap<String, Reservation>,
    pub payment_id_index: DashMap<String, String>,
    pub provider_credits: DashMap<String, ProviderCredit>,
    pub providers: DashMap<String, ProviderRegistration>,
    /// Settlement history for audit record generation
    pub settlement_history: DashMap<String, SettlementRecord>,
    /// Batch confirmation lookup keyed by settlement_id
    pub settlement_batches: DashMap<String, SettlementBatchInfo>,
    pub pending_withdrawals: DashMap<u64, PendingWithdrawal>,
    /// Active Service Channels (Phase 3 ASC)
    pub active_channels: DashMap<ChannelId, ChannelState>,
    pub receipt_nonce: AtomicU64,
    pub withdraw_nonce: AtomicU64,
    pub snapshot_seqno: AtomicU64,
    pub last_batch_at: RwLock<i64>,
    pub last_finalized_slot: AtomicU64,
    pub lifecycle: RwLock<VaultLifecycle>,
}

/// Record of a completed settlement (for audit record generation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: String,
    pub client: Pubkey,
    pub provider: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

/// Batch confirmation metadata for a completed settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementBatchInfo {
    pub batch_id: u64,
    pub tx_signature: String,
}

impl VaultState {
    pub fn new(
        vault_config: Pubkey,
        signing_key: SigningKey,
        usdc_mint: Pubkey,
        attestation_policy_hash: [u8; 32],
        solana: SolanaRuntimeConfig,
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        let vault_signer_pubkey = Pubkey::new_from_array(verifying_key.to_bytes());

        Self {
            vault_config,
            vault_signer: Arc::new(signing_key),
            vault_signer_pubkey,
            usdc_mint,
            attestation_policy_hash,
            solana,
            auditor_master_secret: RwLock::new([0u8; 32]),
            auditor_epoch: AtomicU32::new(0),
            client_balances: DashMap::new(),
            reservations: DashMap::new(),
            payment_id_index: DashMap::new(),
            provider_credits: DashMap::new(),
            providers: DashMap::new(),
            settlement_history: DashMap::new(),
            settlement_batches: DashMap::new(),
            pending_withdrawals: DashMap::new(),
            active_channels: DashMap::new(),
            receipt_nonce: AtomicU64::new(1),
            withdraw_nonce: AtomicU64::new(1),
            snapshot_seqno: AtomicU64::new(0),
            last_batch_at: RwLock::new(0),
            last_finalized_slot: AtomicU64::new(0),
            lifecycle: RwLock::new(VaultLifecycle {
                status: subly402_vault::constants::VAULT_STATUS_ACTIVE,
                successor_vault: Pubkey::default(),
                exit_deadline: 0,
                synced_at_ms: if cfg!(test) {
                    chrono::Utc::now().timestamp_millis()
                } else {
                    0
                },
            }),
        }
    }

    pub fn next_receipt_nonce(&self) -> u64 {
        self.receipt_nonce.fetch_add(1, Ordering::SeqCst)
    }

    pub fn next_withdraw_nonce(&self) -> u64 {
        self.withdraw_nonce.fetch_add(1, Ordering::SeqCst)
    }

    /// Apply a deposit (called when on-chain deposit is observed)
    pub fn apply_deposit(&self, client: Pubkey, amount: u64) {
        let mut balance = self.client_balances.entry(client).or_default();
        balance.free += amount;
        balance.total_deposited += amount;
    }

    pub fn rollback_deposit(&self, client: &Pubkey, amount: u64) -> Result<(), EnclaveError> {
        let mut balance = self
            .client_balances
            .get_mut(client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.free = balance.free.saturating_sub(amount);
        balance.total_deposited = balance.total_deposited.saturating_sub(amount);
        Ok(())
    }

    /// Reserve funds for a payment
    pub fn reserve_balance(&self, client: &Pubkey, amount: u64) -> Result<(), EnclaveError> {
        let mut balance = self
            .client_balances
            .get_mut(client)
            .ok_or(EnclaveError::InsufficientBalance)?;
        if balance.free < amount {
            return Err(EnclaveError::InsufficientBalance);
        }
        balance.free -= amount;
        balance.locked += amount;
        Ok(())
    }

    /// Release reserved funds (on cancel/expiry)
    pub fn release_balance(&self, client: &Pubkey, amount: u64) -> Result<(), EnclaveError> {
        let mut balance = self
            .client_balances
            .get_mut(client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.locked = balance.locked.saturating_sub(amount);
        balance.free += amount;
        Ok(())
    }

    /// Recompute the latest outstanding reservation expiry for a client.
    pub fn refresh_client_max_lock_expires_at(&self, client: &Pubkey) -> Result<i64, EnclaveError> {
        let reservation_max_lock_expires_at = self
            .reservations
            .iter()
            .filter(|reservation| {
                reservation.client == *client && reservation.status == ReservationStatus::Reserved
            })
            .map(|reservation| reservation.expires_at)
            .max()
            .unwrap_or(0);
        let withdrawal_max_lock_expires_at = self
            .pending_withdrawals
            .iter()
            .filter(|withdrawal| withdrawal.client == *client)
            .map(|withdrawal| withdrawal.expires_at)
            .max()
            .unwrap_or(0);
        let channel_request_max_lock_expires_at = self
            .active_channels
            .iter()
            .filter(|channel| channel.client == *client)
            .filter_map(|channel| {
                channel
                    .active_request
                    .as_ref()
                    .map(|request| request.expires_at)
            })
            .max()
            .unwrap_or(0);
        let max_lock_expires_at = reservation_max_lock_expires_at
            .max(withdrawal_max_lock_expires_at)
            .max(channel_request_max_lock_expires_at);

        let mut balance = self
            .client_balances
            .get_mut(client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.max_lock_expires_at = max_lock_expires_at;
        Ok(max_lock_expires_at)
    }

    pub fn authorize_withdrawal(&self, withdrawal: PendingWithdrawal) -> Result<(), EnclaveError> {
        let mut balance = self
            .client_balances
            .get_mut(&withdrawal.client)
            .ok_or(EnclaveError::ClientNotFound)?;
        if balance.free < withdrawal.amount {
            return Err(EnclaveError::InsufficientBalance);
        }
        balance.free -= withdrawal.amount;
        balance.locked += withdrawal.amount;
        drop(balance);

        self.pending_withdrawals
            .insert(withdrawal.withdraw_nonce, withdrawal);
        Ok(())
    }

    pub fn rollback_authorized_withdrawal(
        &self,
        withdraw_nonce: u64,
    ) -> Result<PendingWithdrawal, EnclaveError> {
        self.expire_pending_withdrawal(withdraw_nonce)
    }

    pub fn expire_pending_withdrawal(
        &self,
        withdraw_nonce: u64,
    ) -> Result<PendingWithdrawal, EnclaveError> {
        let (_, withdrawal) = self
            .pending_withdrawals
            .remove(&withdraw_nonce)
            .ok_or(EnclaveError::ReservationNotFound)?;
        let mut balance = self
            .client_balances
            .get_mut(&withdrawal.client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.locked = balance.locked.saturating_sub(withdrawal.amount);
        balance.free += withdrawal.amount;
        Ok(withdrawal)
    }

    pub fn apply_withdrawal(&self, withdraw_nonce: u64) -> Result<PendingWithdrawal, EnclaveError> {
        let (_, withdrawal) = self
            .pending_withdrawals
            .remove(&withdraw_nonce)
            .ok_or(EnclaveError::ReservationNotFound)?;
        let mut balance = self
            .client_balances
            .get_mut(&withdrawal.client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.locked = balance.locked.saturating_sub(withdrawal.amount);
        balance.total_withdrawn = balance
            .total_withdrawn
            .checked_add(withdrawal.amount)
            .ok_or_else(|| EnclaveError::Internal("Withdrawal total overflow".into()))?;
        Ok(withdrawal)
    }

    pub fn rollback_applied_withdrawal(
        &self,
        withdrawal: PendingWithdrawal,
    ) -> Result<(), EnclaveError> {
        let mut balance = self
            .client_balances
            .get_mut(&withdrawal.client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.locked += withdrawal.amount;
        balance.total_withdrawn = balance.total_withdrawn.saturating_sub(withdrawal.amount);
        drop(balance);

        self.pending_withdrawals
            .insert(withdrawal.withdraw_nonce, withdrawal);
        Ok(())
    }

    /// Settle: move from locked to provider credit
    pub fn settle_payment(
        &self,
        client: &Pubkey,
        amount: u64,
        provider_id: &str,
        settlement_id: &str,
        now: i64,
    ) -> Result<(), EnclaveError> {
        // Reduce client locked balance
        {
            let mut balance = self
                .client_balances
                .get_mut(client)
                .ok_or(EnclaveError::ClientNotFound)?;
            balance.locked = balance.locked.saturating_sub(amount);
        }

        // Credit provider
        let provider = self
            .providers
            .get(provider_id)
            .ok_or(EnclaveError::ProviderNotFound)?;

        let mut credit = self
            .provider_credits
            .entry(provider_id.to_string())
            .or_insert_with(|| ProviderCredit {
                provider_id: provider_id.to_string(),
                settlement_token_account: provider.settlement_token_account,
                credited_amount: 0,
                oldest_credit_at: now,
                settlement_ids: Vec::new(),
            });

        credit.credited_amount += amount;
        credit.settlement_ids.push(settlement_id.to_string());

        Ok(())
    }

    pub fn rollback_settle_payment(
        &self,
        client: &Pubkey,
        amount: u64,
        provider_id: &str,
        settlement_id: &str,
    ) -> Result<(), EnclaveError> {
        {
            let mut balance = self
                .client_balances
                .get_mut(client)
                .ok_or(EnclaveError::ClientNotFound)?;
            balance.locked += amount;
        }

        let remove_credit = {
            let mut credit = self
                .provider_credits
                .get_mut(provider_id)
                .ok_or(EnclaveError::ProviderNotFound)?;
            credit.credited_amount = credit.credited_amount.saturating_sub(amount);
            credit.settlement_ids.retain(|value| value != settlement_id);
            credit.credited_amount == 0 || credit.settlement_ids.is_empty()
        };
        if remove_credit {
            self.provider_credits.remove(provider_id);
        }

        Ok(())
    }

    /// Apply a confirmed on-chain batch to local reservation/provider-credit state.
    pub fn apply_batch_confirmation(
        &self,
        settlement_ids: &[String],
        batch_id: u64,
        tx_signature: &str,
    ) {
        let mut affected_provider_ids = HashSet::new();

        for settlement_id in settlement_ids {
            self.settlement_history.remove(settlement_id);
            self.settlement_batches.insert(
                settlement_id.clone(),
                SettlementBatchInfo {
                    batch_id,
                    tx_signature: tx_signature.to_string(),
                },
            );

            if let Some(mut reservation) = self.reservations.iter_mut().find(|entry| {
                entry
                    .settlement_id
                    .as_ref()
                    .map(|value| value == settlement_id)
                    .unwrap_or(false)
            }) {
                affected_provider_ids.insert(reservation.provider_id.clone());
                if let Some(mut credit) = self.provider_credits.get_mut(&reservation.provider_id) {
                    credit.credited_amount =
                        credit.credited_amount.saturating_sub(reservation.amount);
                    credit.settlement_ids.retain(|sid| sid != settlement_id);
                }
                reservation.status = ReservationStatus::BatchedOnchain;
                continue;
            }

            for mut credit in self.provider_credits.iter_mut() {
                if credit.settlement_ids.iter().any(|sid| sid == settlement_id) {
                    affected_provider_ids.insert(credit.provider_id.clone());
                    credit.settlement_ids.retain(|sid| sid != settlement_id);
                    break;
                }
            }
        }

        let provider_ids_to_remove: Vec<String> = affected_provider_ids
            .iter()
            .filter_map(|provider_id| {
                self.provider_credits.get(provider_id).and_then(|credit| {
                    if credit.credited_amount == 0 || credit.settlement_ids.is_empty() {
                        Some(provider_id.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();
        for provider_id in provider_ids_to_remove {
            self.provider_credits.remove(&provider_id);
            affected_provider_ids.remove(&provider_id);
        }

        for provider_id in affected_provider_ids {
            if let Some(mut credit) = self.provider_credits.get_mut(&provider_id) {
                if let Some(oldest_credit_at) = credit
                    .settlement_ids
                    .iter()
                    .filter_map(|settlement_id| {
                        self.settlement_history
                            .get(settlement_id)
                            .map(|record| record.timestamp)
                    })
                    .min()
                {
                    credit.oldest_credit_at = oldest_credit_at;
                }
            }
        }
    }

    /// Sign a message with the vault signer key
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let signature = self.vault_signer.sign(message);
        signature.to_bytes()
    }

    /// Build a ParticipantReceipt message for signing
    pub fn build_participant_receipt_message(
        &self,
        participant: &Pubkey,
        participant_kind: u8,
        recipient_ata: &Pubkey,
        free_balance: u64,
        locked_balance: u64,
        max_lock_expires_at: i64,
        nonce: u64,
        timestamp: i64,
        snapshot_seqno: u64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(145);
        msg.extend_from_slice(participant.as_ref());
        msg.push(participant_kind);
        msg.extend_from_slice(recipient_ata.as_ref());
        msg.extend_from_slice(&free_balance.to_le_bytes());
        msg.extend_from_slice(&locked_balance.to_le_bytes());
        msg.extend_from_slice(&max_lock_expires_at.to_le_bytes());
        msg.extend_from_slice(&nonce.to_le_bytes());
        msg.extend_from_slice(&timestamp.to_le_bytes());
        msg.extend_from_slice(&snapshot_seqno.to_le_bytes());
        msg.extend_from_slice(self.vault_config.as_ref());
        msg
    }

    /// Build a WithdrawAuthorization message for signing
    pub fn build_withdraw_authorization_message(
        &self,
        client: &Pubkey,
        recipient_ata: &Pubkey,
        amount: u64,
        withdraw_nonce: u64,
        expires_at: i64,
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(120);
        msg.extend_from_slice(client.as_ref());
        msg.extend_from_slice(recipient_ata.as_ref());
        msg.extend_from_slice(&amount.to_le_bytes());
        msg.extend_from_slice(&withdraw_nonce.to_le_bytes());
        msg.extend_from_slice(&expires_at.to_le_bytes());
        msg.extend_from_slice(self.vault_config.as_ref());
        msg
    }

    /// Build a verification receipt message for signing.
    pub fn build_verification_receipt_message(
        &self,
        verification_id: &str,
        reservation_id: &str,
        payment_id: &str,
        client: &Pubkey,
        provider_id: &str,
        amount: u64,
        request_hash_hex: &str,
        payment_details_hash_hex: &str,
        reservation_expires_at: i64,
    ) -> Vec<u8> {
        format!(
            "SUBLY402-VERIFY-RECEIPT\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            verification_id,
            reservation_id,
            payment_id,
            client,
            provider_id,
            amount,
            request_hash_hex,
            payment_details_hash_hex,
            reservation_expires_at,
            self.vault_config,
        )
        .into_bytes()
    }
}
