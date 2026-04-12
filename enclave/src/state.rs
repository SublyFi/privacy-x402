use dashmap::DashMap;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::EnclaveError;

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
    pub settlement_token_account: Pubkey,
    pub network: String,
    pub asset_mint: Pubkey,
    pub allowed_origins: Vec<String>,
    pub auth_mode: String,
    pub api_key_hash: Vec<u8>,
}

/// A single payment reservation
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct ProviderCredit {
    pub provider_id: String,
    pub settlement_token_account: Pubkey,
    pub credited_amount: u64,
    pub oldest_credit_at: i64,
    pub settlement_ids: Vec<String>,
}

/// Core enclave vault state
pub struct VaultState {
    pub vault_config: Pubkey,
    pub vault_signer: Arc<SigningKey>,
    pub vault_signer_pubkey: Pubkey,
    pub usdc_mint: Pubkey,
    pub attestation_policy_hash: [u8; 32],
    pub client_balances: DashMap<Pubkey, ClientBalance>,
    pub reservations: DashMap<String, Reservation>,
    pub payment_id_index: DashMap<String, String>,
    pub provider_credits: DashMap<String, ProviderCredit>,
    pub providers: DashMap<String, ProviderRegistration>,
    pub receipt_nonce: AtomicU64,
    pub withdraw_nonce: AtomicU64,
    pub snapshot_seqno: AtomicU64,
    pub last_batch_at: RwLock<i64>,
    pub last_finalized_slot: AtomicU64,
}

impl VaultState {
    pub fn new(
        vault_config: Pubkey,
        signing_key: SigningKey,
        usdc_mint: Pubkey,
        attestation_policy_hash: [u8; 32],
    ) -> Self {
        let verifying_key = signing_key.verifying_key();
        let vault_signer_pubkey = Pubkey::new_from_array(verifying_key.to_bytes());

        Self {
            vault_config,
            vault_signer: Arc::new(signing_key),
            vault_signer_pubkey,
            usdc_mint,
            attestation_policy_hash,
            client_balances: DashMap::new(),
            reservations: DashMap::new(),
            payment_id_index: DashMap::new(),
            provider_credits: DashMap::new(),
            providers: DashMap::new(),
            receipt_nonce: AtomicU64::new(1),
            withdraw_nonce: AtomicU64::new(1),
            snapshot_seqno: AtomicU64::new(0),
            last_batch_at: RwLock::new(0),
            last_finalized_slot: AtomicU64::new(0),
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

    /// Reserve funds for a payment
    pub fn reserve_balance(
        &self,
        client: &Pubkey,
        amount: u64,
    ) -> Result<(), EnclaveError> {
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
    pub fn release_balance(
        &self,
        client: &Pubkey,
        amount: u64,
    ) -> Result<(), EnclaveError> {
        let mut balance = self
            .client_balances
            .get_mut(client)
            .ok_or(EnclaveError::ClientNotFound)?;
        balance.locked = balance.locked.saturating_sub(amount);
        balance.free += amount;
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
        let mut msg = Vec::with_capacity(153);
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
}
