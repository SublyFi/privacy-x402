use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::info;

use crate::adaptor_sig::AdaptorPreSignature;
use crate::asc_manager;
use crate::error::EnclaveError;
use crate::handlers::AppState;
use crate::snapshot_store::SnapshotStoreClient;
use crate::state::{
    ArciumAuthorityMode, ArciumBudgetGrant, ArciumWithdrawalGrant, ClientBalance,
    PendingWithdrawal, ProviderRegistration, Reservation, ReservationStatus, SettlementRecord,
};

/// WAL entry types for Phase 1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WalEntry {
    DepositApplied {
        client: String,
        amount: u64,
        slot: u64,
        tx_signature: String,
    },
    WithdrawAuthorized {
        client: String,
        recipient_ata: String,
        amount: u64,
        withdraw_nonce: u64,
        issued_at: i64,
        expires_at: i64,
        #[serde(default)]
        arcium_grant_id: Option<String>,
    },
    WithdrawApplied {
        client: String,
        recipient_ata: String,
        amount: u64,
        withdraw_nonce: u64,
        expires_at: i64,
        slot: u64,
        tx_signature: String,
    },
    WithdrawExpired {
        client: String,
        withdraw_nonce: u64,
    },
    ReservationCreated {
        verification_id: String,
        #[serde(default)]
        reservation_id: Option<String>,
        payment_id: String,
        client: String,
        provider_id: String,
        amount: u64,
        #[serde(default)]
        request_hash: Option<String>,
        #[serde(default)]
        payment_details_hash: Option<String>,
        #[serde(default)]
        created_at: Option<i64>,
        #[serde(default)]
        expires_at: Option<i64>,
        #[serde(default)]
        arcium_grant_id: Option<String>,
    },
    ReservationCancelled {
        verification_id: String,
        reason: String,
    },
    ReservationExpired {
        verification_id: String,
    },
    SettlementCommitted {
        settlement_id: String,
        verification_id: String,
        provider_id: String,
        amount: u64,
        #[serde(default)]
        settled_at: Option<i64>,
    },
    ParticipantReceiptIssued {
        participant: String,
        participant_kind: u8,
        nonce: u64,
    },
    ParticipantReceiptMirrored {
        participant: String,
        participant_kind: u8,
        nonce: u64,
    },
    ProviderRegistered {
        provider_id: String,
        display_name: String,
        #[serde(default)]
        participant_pubkey: Option<String>,
        #[serde(default)]
        participant_attestation_policy_hash: Option<String>,
        #[serde(default)]
        participant_attestation_verified_at_ms: Option<i64>,
        #[serde(default)]
        participant_attestation_mode: Option<String>,
        settlement_token_account: String,
        network: String,
        asset_mint: String,
        allowed_origins: Vec<String>,
        auth_mode: String,
        #[serde(default)]
        api_key_hash: Option<String>,
        #[serde(default)]
        mtls_cert_fingerprint: Option<String>,
    },
    ClientBalanceSeeded {
        client: String,
        free: u64,
        locked: u64,
        max_lock_expires_at: i64,
        total_deposited: u64,
        total_withdrawn: u64,
    },
    ArciumModeSet {
        mode: String,
    },
    ArciumBudgetGrantLoaded {
        grant_id: String,
        client: String,
        budget_id: u64,
        request_nonce: u64,
        remaining: u64,
        expires_at: i64,
    },
    ArciumWithdrawalGrantLoaded {
        grant_id: String,
        client: String,
        withdrawal_id: u64,
        recipient_ata: String,
        amount: u64,
        expires_at: i64,
        #[serde(default)]
        consumed: bool,
    },
    BatchSubmitted {
        batch_id: u64,
        provider_count: usize,
        total_amount: u64,
    },
    BatchConfirmed {
        batch_id: u64,
        tx_signature: String,
        #[serde(default)]
        settlement_ids: Vec<String>,
    },
    // Phase 3: ASC events
    ChannelOpened {
        channel_id: String,
        client: String,
        provider_id: String,
        initial_deposit: u64,
    },
    ChannelRequestSubmitted {
        channel_id: String,
        request_id: String,
        amount: u64,
        #[serde(default)]
        request_hash: Option<String>,
    },
    ChannelRequestExpired {
        channel_id: String,
        request_id: String,
        amount: u64,
    },
    ChannelAdaptorDelivered {
        channel_id: String,
        request_id: String,
        #[serde(default)]
        adaptor_point: Option<String>,
        #[serde(default)]
        pre_sig_r_prime: Option<String>,
        #[serde(default)]
        pre_sig_s_prime: Option<String>,
        #[serde(default)]
        encrypted_result: Option<String>,
        #[serde(default)]
        result_hash: Option<String>,
        #[serde(default)]
        provider_pubkey: Option<String>,
    },
    ChannelFinalized {
        channel_id: String,
        request_id: String,
        amount_paid: u64,
    },
    ChannelClosed {
        channel_id: String,
        returned_to_client: u64,
        provider_earned: u64,
        #[serde(default)]
        settlement_id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    pub seqno: u64,
    pub timestamp: i64,
    pub entry: WalEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedWalEnvelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone)]
enum WalBackend {
    LocalFile {
        path: PathBuf,
    },
    SnapshotStore {
        client: SnapshotStoreClient,
        prefix: String,
    },
}

/// Write-Ahead Log for durable state changes.
/// State transitions are encrypted before leaving the enclave.
pub struct Wal {
    backend: WalBackend,
    key: [u8; 32],
    seqno: std::sync::atomic::AtomicU64,
}

impl Wal {
    pub async fn new_with_key(path: PathBuf, key: [u8; 32]) -> Self {
        Self::new_with_backend(WalBackend::LocalFile { path }, key).await
    }

    pub async fn new_with_snapshot_store(
        path: PathBuf,
        key: [u8; 32],
        snapshot_store: SnapshotStoreClient,
        prefix: String,
    ) -> Self {
        let backend = if prefix.is_empty() {
            WalBackend::LocalFile { path }
        } else {
            WalBackend::SnapshotStore {
                client: snapshot_store,
                prefix,
            }
        };
        Self::new_with_backend(backend, key).await
    }

    pub async fn new(path: PathBuf) -> Self {
        Self::new_with_key(path, [0x41; 32]).await
    }

    async fn new_with_backend(backend: WalBackend, key: [u8; 32]) -> Self {
        let seqno = match &backend {
            WalBackend::LocalFile { path } => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).await.ok();
                }
                if path.exists() {
                    let content = fs::read_to_string(path).await.unwrap_or_default();
                    content
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .count() as u64
                } else {
                    0
                }
            }
            WalBackend::SnapshotStore { client, prefix } => client
                .list(prefix)
                .await
                .map(|items| items.len() as u64)
                .unwrap_or(0),
        };
        Self {
            backend,
            key,
            seqno: std::sync::atomic::AtomicU64::new(seqno),
        }
    }

    /// Durably append a WAL entry. Returns only after write is flushed.
    pub async fn append(&self, entry: WalEntry) -> Result<u64, std::io::Error> {
        let seqno = self.seqno.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now = chrono::Utc::now().timestamp();

        let record = WalRecord {
            seqno,
            timestamp: now,
            entry,
        };

        let record_bytes = serde_json::to_vec(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        let envelope = encrypt_record(self.key, &record_bytes)?;

        match &self.backend {
            WalBackend::LocalFile { path } => {
                let mut line = serde_json::to_string(&envelope)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                line.push('\n');

                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .await?;
                file.write_all(line.as_bytes()).await?;
                file.flush().await?;
                file.sync_all().await?;
            }
            WalBackend::SnapshotStore { client, prefix } => {
                let blob = serde_json::to_vec(&envelope)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                let key = wal_object_key(prefix, seqno);
                client.put(&key, &blob).await?;
            }
        }

        info!(seqno, "WAL entry appended");
        Ok(seqno)
    }

    pub async fn read_records(&self) -> Result<Vec<WalRecord>, std::io::Error> {
        let mut records = match &self.backend {
            WalBackend::LocalFile { path } => read_local_records(path, self.key).await?,
            WalBackend::SnapshotStore { client, prefix } => {
                read_snapshot_records(client, prefix, self.key).await?
            }
        };

        records.sort_by_key(|record| record.seqno);
        Ok(records)
    }

    pub async fn read_records_after(
        &self,
        min_exclusive: Option<u64>,
    ) -> Result<Vec<WalRecord>, std::io::Error> {
        let mut records = self.read_records().await?;
        if let Some(min_seqno) = min_exclusive {
            records.retain(|record| record.seqno > min_seqno);
        }
        Ok(records)
    }

    pub fn last_seqno(&self) -> Option<u64> {
        let next = self.seqno.load(std::sync::atomic::Ordering::SeqCst);
        next.checked_sub(1)
    }
}

async fn read_local_records(
    path: &PathBuf,
    key: [u8; 32],
) -> Result<Vec<WalRecord>, std::io::Error> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = OpenOptions::new().read(true).open(path).await?;
    let mut lines = BufReader::new(file).lines();
    let mut records = Vec::new();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        records.push(parse_stored_record(&line, key)?);
    }

    Ok(records)
}

async fn read_snapshot_records(
    client: &SnapshotStoreClient,
    prefix: &str,
    key: [u8; 32],
) -> Result<Vec<WalRecord>, std::io::Error> {
    let mut items = client.list(prefix).await?;
    items.sort();

    let mut records = Vec::with_capacity(items.len());
    for item in items {
        let Some(blob) = client.get(&item).await? else {
            continue;
        };
        let line = String::from_utf8(blob).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        })?;
        records.push(parse_stored_record(&line, key)?);
    }
    Ok(records)
}

fn parse_stored_record(line: &str, key: [u8; 32]) -> Result<WalRecord, std::io::Error> {
    if let Ok(record) = serde_json::from_str::<WalRecord>(line) {
        return Ok(record);
    }

    let envelope = serde_json::from_str::<EncryptedWalEnvelope>(line)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let plaintext = decrypt_record(key, &envelope)?;
    serde_json::from_slice::<WalRecord>(&plaintext)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))
}

fn encrypt_record(key: [u8; 32], plaintext: &[u8]) -> Result<EncryptedWalEnvelope, std::io::Error> {
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    })?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))?;

    Ok(EncryptedWalEnvelope {
        version: 1,
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn decrypt_record(
    key: [u8; 32],
    envelope: &EncryptedWalEnvelope,
) -> Result<Vec<u8>, std::io::Error> {
    if envelope.version != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported WAL envelope version {}", envelope.version),
        ));
    }

    let nonce_bytes = BASE64
        .decode(&envelope.nonce)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    if nonce_bytes.len() != 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "WAL nonce must be 12 bytes",
        ));
    }

    let ciphertext = BASE64
        .decode(&envelope.ciphertext)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    })?;
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))
}

fn wal_object_key(prefix: &str, seqno: u64) -> String {
    format!("{}/wal-{seqno:020}.json", prefix.trim_end_matches('/'))
}

pub async fn replay_app_state(state: &AppState) -> Result<(), String> {
    replay_app_state_from(state, None).await
}

pub async fn replay_app_state_from(
    state: &AppState,
    min_seqno_exclusive: Option<u64>,
) -> Result<(), String> {
    let records = state
        .wal
        .read_records_after(min_seqno_exclusive)
        .await
        .map_err(|error| format!("failed to read WAL: {error}"))?;

    for record in records {
        replay_entry(state, record.entry).await?;
    }

    let clients: Vec<Pubkey> = state
        .vault
        .client_balances
        .iter()
        .map(|entry| *entry.key())
        .collect();
    for client in clients {
        state
            .vault
            .refresh_client_max_lock_expires_at(&client)
            .map_err(wal_replay_error)?;
    }

    Ok(())
}

async fn replay_entry(state: &AppState, entry: WalEntry) -> Result<(), String> {
    match entry {
        WalEntry::DepositApplied {
            client,
            amount,
            slot,
            tx_signature,
        } => {
            let client = parse_pubkey("client", &client)?;
            state.vault.apply_deposit(client, amount);
            state.deposit_detector.mark_processed(&tx_signature).await;
            *state
                .deposit_detector
                .last_processed_signature
                .write()
                .await = Some(tx_signature);
            state
                .vault
                .last_finalized_slot
                .fetch_max(slot, Ordering::SeqCst);
        }
        WalEntry::WithdrawAuthorized {
            client,
            recipient_ata,
            amount,
            withdraw_nonce,
            issued_at,
            expires_at,
            arcium_grant_id,
        } => {
            let client = parse_pubkey("client", &client)?;
            let recipient_ata = parse_pubkey("recipient_ata", &recipient_ata)?;
            let withdrawal = PendingWithdrawal {
                client,
                recipient_ata,
                amount,
                withdraw_nonce,
                issued_at,
                expires_at,
                arcium_grant_id: arcium_grant_id.clone(),
            };
            if let Some(grant_id) = arcium_grant_id.as_deref() {
                state
                    .vault
                    .authorize_arcium_withdrawal_from_grant(grant_id, withdrawal, issued_at)
                    .map_err(wal_replay_error)?;
            } else {
                state
                    .vault
                    .authorize_withdrawal(withdrawal)
                    .map_err(wal_replay_error)?;
            }
            state
                .vault
                .withdraw_nonce
                .fetch_max(withdraw_nonce.saturating_add(1), Ordering::SeqCst);
            if arcium_grant_id.is_none() {
                state
                    .vault
                    .refresh_client_max_lock_expires_at(&client)
                    .map_err(wal_replay_error)?;
            }
        }
        WalEntry::WithdrawApplied {
            client,
            recipient_ata,
            amount,
            withdraw_nonce,
            expires_at,
            slot,
            tx_signature,
        } => {
            let client = parse_pubkey("client", &client)?;
            let recipient_ata = parse_pubkey("recipient_ata", &recipient_ata)?;
            let applied = state
                .vault
                .apply_withdrawal(withdraw_nonce)
                .map_err(wal_replay_error)?;
            if applied.client != client
                || applied.recipient_ata != recipient_ata
                || applied.amount != amount
                || applied.expires_at != expires_at
            {
                return Err(format!(
                    "withdraw replay mismatch for nonce {withdraw_nonce}: state={:?} wal=({}, {}, {}, {})",
                    applied,
                    client,
                    recipient_ata,
                    amount,
                    expires_at
                ));
            }
            state.deposit_detector.mark_processed(&tx_signature).await;
            *state
                .deposit_detector
                .last_processed_signature
                .write()
                .await = Some(tx_signature);
            state
                .vault
                .last_finalized_slot
                .fetch_max(slot, Ordering::SeqCst);
            state
                .vault
                .withdraw_nonce
                .fetch_max(withdraw_nonce.saturating_add(1), Ordering::SeqCst);
            if applied.arcium_grant_id.is_none() {
                state
                    .vault
                    .refresh_client_max_lock_expires_at(&client)
                    .map_err(wal_replay_error)?;
            }
        }
        WalEntry::WithdrawExpired {
            client,
            withdraw_nonce,
        } => {
            let client = parse_pubkey("client", &client)?;
            let expired = state
                .vault
                .expire_pending_withdrawal(withdraw_nonce)
                .map_err(wal_replay_error)?;
            if expired.client != client {
                return Err(format!(
                    "withdraw expiry client mismatch for nonce {withdraw_nonce}: state={} wal={client}",
                    expired.client
                ));
            }
            if expired.arcium_grant_id.is_none() {
                state
                    .vault
                    .refresh_client_max_lock_expires_at(&client)
                    .map_err(wal_replay_error)?;
            }
        }
        WalEntry::ReservationCreated {
            verification_id,
            reservation_id,
            payment_id,
            client,
            provider_id,
            amount,
            request_hash,
            payment_details_hash,
            created_at,
            expires_at,
            arcium_grant_id,
        } => {
            let client = parse_pubkey("client", &client)?;
            let reservation_id = reservation_id.ok_or_else(|| {
                "legacy ReservationCreated WAL entry missing reservation_id".to_string()
            })?;
            let request_hash = request_hash
                .ok_or_else(|| {
                    "legacy ReservationCreated WAL entry missing request_hash".to_string()
                })
                .and_then(|value| decode_fixed_hex_32("request_hash", &value))?;
            let payment_details_hash = payment_details_hash
                .ok_or_else(|| {
                    "legacy ReservationCreated WAL entry missing payment_details_hash".to_string()
                })
                .and_then(|value| decode_fixed_hex_32("payment_details_hash", &value))?;
            let created_at = created_at.ok_or_else(|| {
                "legacy ReservationCreated WAL entry missing created_at".to_string()
            })?;
            let expires_at = expires_at.ok_or_else(|| {
                "legacy ReservationCreated WAL entry missing expires_at".to_string()
            })?;

            if let Some(grant_id) = arcium_grant_id.as_deref() {
                state
                    .vault
                    .reserve_arcium_budget_from_grant(grant_id, &client, amount, created_at)
                    .map_err(wal_replay_error)?;
            } else {
                state
                    .vault
                    .reserve_balance(&client, amount)
                    .map_err(wal_replay_error)?;
            }
            state
                .vault
                .payment_id_index
                .insert(payment_id.clone(), verification_id.clone());
            state.vault.reservations.insert(
                verification_id.clone(),
                Reservation {
                    verification_id,
                    reservation_id,
                    payment_id,
                    client,
                    provider_id,
                    amount,
                    request_hash,
                    payment_details_hash,
                    status: ReservationStatus::Reserved,
                    created_at,
                    expires_at,
                    settlement_id: None,
                    settled_at: None,
                    arcium_grant_id,
                },
            );
        }
        WalEntry::ReservationCancelled {
            verification_id, ..
        } => {
            let mut reservation = state
                .vault
                .reservations
                .get_mut(&verification_id)
                .ok_or_else(|| {
                    format!(
                        "missing reservation {verification_id} for ReservationCancelled WAL entry"
                    )
                })?;
            if reservation.status == ReservationStatus::Reserved {
                let client = reservation.client;
                let amount = reservation.amount;
                let arcium_grant_id = reservation.arcium_grant_id.clone();
                reservation.status = ReservationStatus::Cancelled;
                drop(reservation);
                if let Some(grant_id) = arcium_grant_id {
                    state
                        .vault
                        .release_arcium_budget(&grant_id, amount)
                        .map_err(wal_replay_error)?;
                } else {
                    state
                        .vault
                        .release_balance(&client, amount)
                        .map_err(wal_replay_error)?;
                }
            } else {
                reservation.status = ReservationStatus::Cancelled;
            }
        }
        WalEntry::ReservationExpired { verification_id } => {
            let mut reservation = state
                .vault
                .reservations
                .get_mut(&verification_id)
                .ok_or_else(|| {
                    format!(
                        "missing reservation {verification_id} for ReservationExpired WAL entry"
                    )
                })?;
            if reservation.status == ReservationStatus::Reserved {
                let client = reservation.client;
                let amount = reservation.amount;
                let arcium_grant_id = reservation.arcium_grant_id.clone();
                reservation.status = ReservationStatus::Expired;
                drop(reservation);
                if let Some(grant_id) = arcium_grant_id {
                    state
                        .vault
                        .release_arcium_budget(&grant_id, amount)
                        .map_err(wal_replay_error)?;
                } else {
                    state
                        .vault
                        .release_balance(&client, amount)
                        .map_err(wal_replay_error)?;
                }
            } else {
                reservation.status = ReservationStatus::Expired;
            }
        }
        WalEntry::SettlementCommitted {
            settlement_id,
            verification_id,
            provider_id,
            amount,
            settled_at,
        } => {
            let (client, provider_id, amount, timestamp, arcium_grant_id) = {
                let mut reservation = state
                    .vault
                    .reservations
                    .get_mut(&verification_id)
                    .ok_or_else(|| {
                        format!(
                            "missing reservation {verification_id} for SettlementCommitted WAL entry"
                        )
                    })?;
                let client = reservation.client;
                if reservation.provider_id != provider_id {
                    return Err(format!(
                        "provider_id mismatch for settlement {settlement_id}: reservation={} wal={provider_id}",
                        reservation.provider_id
                    ));
                }
                if reservation.amount != amount {
                    return Err(format!(
                        "amount mismatch for settlement {settlement_id}: reservation={} wal={amount}",
                        reservation.amount
                    ));
                }
                let provider_id = reservation.provider_id.clone();
                let amount = reservation.amount;
                let timestamp = settled_at.unwrap_or(reservation.created_at);
                let arcium_grant_id = reservation.arcium_grant_id.clone();
                if reservation.status == ReservationStatus::Reserved {
                    reservation.status = ReservationStatus::SettledOffchain;
                    reservation.settlement_id = Some(settlement_id.clone());
                    reservation.settled_at = Some(timestamp);
                }
                (client, provider_id, amount, timestamp, arcium_grant_id)
            };

            if arcium_grant_id.is_some() {
                state
                    .vault
                    .credit_provider(amount, &provider_id, &settlement_id, timestamp)
                    .map_err(wal_replay_error)?;
            } else {
                state
                    .vault
                    .settle_payment(&client, amount, &provider_id, &settlement_id, timestamp)
                    .map_err(wal_replay_error)?;
            }
            let provider_pubkey = state
                .vault
                .providers
                .get(&provider_id)
                .map(|provider| provider.settlement_token_account)
                .ok_or_else(|| {
                    format!("missing provider {provider_id} for SettlementCommitted WAL entry")
                })?;
            state.vault.settlement_history.insert(
                settlement_id.clone(),
                SettlementRecord {
                    settlement_id,
                    client,
                    provider: provider_pubkey,
                    amount,
                    timestamp,
                },
            );
        }
        WalEntry::ProviderRegistered {
            provider_id,
            display_name,
            participant_pubkey,
            participant_attestation_policy_hash,
            participant_attestation_verified_at_ms,
            participant_attestation_mode,
            settlement_token_account,
            network,
            asset_mint,
            allowed_origins,
            auth_mode,
            api_key_hash,
            mtls_cert_fingerprint,
        } => {
            let settlement_token_account =
                parse_pubkey("settlement_token_account", &settlement_token_account)?;
            let asset_mint = parse_pubkey("asset_mint", &asset_mint)?;
            let participant_pubkey = participant_pubkey
                .as_deref()
                .map(|value| parse_pubkey("participant_pubkey", value))
                .transpose()?;
            let participant_attestation_policy_hash = participant_attestation_policy_hash
                .map(|value| {
                    let bytes = hex::decode(&value).map_err(|error| {
                        format!(
                            "invalid provider participant_attestation_policy_hash in WAL: {error}"
                        )
                    })?;
                    bytes.try_into().map_err(|_| {
                        "invalid provider participant_attestation_policy_hash length in WAL"
                            .to_string()
                    })
                })
                .transpose()?;
            let api_key_hash = api_key_hash
                .map(|value| {
                    hex::decode(&value)
                        .map_err(|error| format!("invalid provider api_key_hash in WAL: {error}"))
                })
                .transpose()?;
            let mtls_cert_fingerprint = mtls_cert_fingerprint
                .map(|value| {
                    hex::decode(&value).map_err(|error| {
                        format!("invalid provider mtls_cert_fingerprint in WAL: {error}")
                    })
                })
                .transpose()?;

            state.vault.providers.insert(
                provider_id.clone(),
                ProviderRegistration {
                    provider_id,
                    display_name,
                    participant_pubkey,
                    participant_attestation_policy_hash,
                    participant_attestation_verified_at_ms,
                    participant_attestation_mode,
                    settlement_token_account,
                    network,
                    asset_mint,
                    allowed_origins,
                    auth_mode,
                    api_key_hash,
                    mtls_cert_fingerprint,
                },
            );
        }
        WalEntry::ParticipantReceiptIssued { nonce, .. }
        | WalEntry::ParticipantReceiptMirrored { nonce, .. } => {
            state
                .vault
                .receipt_nonce
                .fetch_max(nonce.saturating_add(1), Ordering::SeqCst);
        }
        WalEntry::ClientBalanceSeeded {
            client,
            free,
            locked,
            max_lock_expires_at,
            total_deposited,
            total_withdrawn,
        } => {
            let client = parse_pubkey("client", &client)?;
            state.vault.client_balances.insert(
                client,
                ClientBalance {
                    free,
                    locked,
                    max_lock_expires_at,
                    total_deposited,
                    total_withdrawn,
                },
            );
        }
        WalEntry::ArciumModeSet { mode } => {
            let mode =
                ArciumAuthorityMode::from_env_value(Some(&mode)).map_err(wal_replay_error)?;
            state.vault.set_arcium_mode(mode);
        }
        WalEntry::ArciumBudgetGrantLoaded {
            grant_id,
            client,
            budget_id,
            request_nonce,
            remaining,
            expires_at,
        } => {
            let client = parse_pubkey("client", &client)?;
            state
                .vault
                .load_arcium_budget_grant(ArciumBudgetGrant {
                    grant_id,
                    client,
                    budget_id,
                    request_nonce,
                    remaining,
                    expires_at,
                })
                .map_err(wal_replay_error)?;
        }
        WalEntry::ArciumWithdrawalGrantLoaded {
            grant_id,
            client,
            withdrawal_id,
            recipient_ata,
            amount,
            expires_at,
            consumed,
        } => {
            let client = parse_pubkey("client", &client)?;
            let recipient_ata = parse_pubkey("recipient_ata", &recipient_ata)?;
            state
                .vault
                .load_arcium_withdrawal_grant(ArciumWithdrawalGrant {
                    grant_id,
                    client,
                    withdrawal_id,
                    recipient_ata,
                    amount,
                    expires_at,
                    consumed,
                })
                .map_err(wal_replay_error)?;
        }
        WalEntry::BatchConfirmed {
            batch_id,
            tx_signature,
            settlement_ids,
        } => {
            state
                .vault
                .apply_batch_confirmation(&settlement_ids, batch_id, &tx_signature);
        }
        WalEntry::ChannelOpened {
            channel_id,
            client,
            provider_id,
            initial_deposit,
        } => {
            let client = parse_pubkey("client", &client)?;
            asc_manager::open_channel_with_id(
                &state.vault,
                channel_id,
                &client,
                &provider_id,
                initial_deposit,
            )
            .map_err(wal_replay_error)?;
        }
        WalEntry::ChannelRequestSubmitted {
            channel_id,
            request_id,
            amount,
            request_hash,
        } => {
            let request_hash = request_hash
                .ok_or_else(|| {
                    "missing request_hash in ChannelRequestSubmitted WAL entry".to_string()
                })
                .and_then(|value| decode_fixed_hex_32("request_hash", &value))?;
            asc_manager::submit_request(
                &state.vault,
                &channel_id,
                &request_id,
                amount,
                request_hash,
            )
            .map_err(wal_replay_error)?;
        }
        WalEntry::ChannelRequestExpired {
            channel_id,
            request_id,
            amount,
        } => {
            asc_manager::expire_replayed_request(&state.vault, &channel_id, &request_id, amount)
                .map_err(wal_replay_error)?;
        }
        WalEntry::ChannelAdaptorDelivered {
            channel_id,
            request_id: _,
            adaptor_point,
            pre_sig_r_prime,
            pre_sig_s_prime,
            encrypted_result,
            result_hash,
            provider_pubkey,
        } => {
            let adaptor_point = adaptor_point
                .ok_or_else(|| {
                    "missing adaptor_point in ChannelAdaptorDelivered WAL entry".to_string()
                })
                .and_then(|value| decode_fixed_hex_32("adaptor_point", &value))?;
            let r_prime = pre_sig_r_prime
                .ok_or_else(|| {
                    "missing pre_sig_r_prime in ChannelAdaptorDelivered WAL entry".to_string()
                })
                .and_then(|value| decode_fixed_hex_32("pre_sig_r_prime", &value))?;
            let s_prime = pre_sig_s_prime
                .ok_or_else(|| {
                    "missing pre_sig_s_prime in ChannelAdaptorDelivered WAL entry".to_string()
                })
                .and_then(|value| decode_fixed_hex_32("pre_sig_s_prime", &value))?;
            let encrypted_result = encrypted_result
                .ok_or_else(|| {
                    "missing encrypted_result in ChannelAdaptorDelivered WAL entry".to_string()
                })
                .and_then(|value| {
                    BASE64
                        .decode(value)
                        .map_err(|error| format!("invalid encrypted_result base64 in WAL: {error}"))
                })?;
            let result_hash = result_hash
                .ok_or_else(|| {
                    "missing result_hash in ChannelAdaptorDelivered WAL entry".to_string()
                })
                .and_then(|value| decode_fixed_hex_32("result_hash", &value))?;
            let provider_pubkey = provider_pubkey
                .ok_or_else(|| {
                    "missing provider_pubkey in ChannelAdaptorDelivered WAL entry".to_string()
                })
                .and_then(|value| decode_fixed_hex_32("provider_pubkey", &value))?;

            asc_manager::deliver_adaptor(
                &state.vault,
                &channel_id,
                adaptor_point,
                AdaptorPreSignature { r_prime, s_prime },
                encrypted_result,
                result_hash,
                &provider_pubkey,
            )
            .map_err(wal_replay_error)?;
        }
        WalEntry::ChannelFinalized {
            channel_id,
            request_id,
            amount_paid,
        } => {
            asc_manager::finalize_replayed_request(
                &state.vault,
                &channel_id,
                &request_id,
                amount_paid,
            )
            .map_err(wal_replay_error)?;
        }
        WalEntry::ChannelClosed {
            channel_id,
            settlement_id,
            ..
        } => {
            asc_manager::close_channel_with_settlement_id(&state.vault, &channel_id, settlement_id)
                .map_err(wal_replay_error)?;
        }
        _ => {}
    }

    Ok(())
}

fn parse_pubkey(field: &str, value: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(value).map_err(|error| format!("invalid {field} in WAL: {error}"))
}

fn decode_fixed_hex_32(field: &str, value: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .map_err(|error| format!("invalid {field} hex in WAL: {error}"))?
        .try_into()
        .map_err(|_| format!("{field} must decode to 32 bytes in WAL"))
}

fn wal_replay_error(error: EnclaveError) -> String {
    format!("WAL replay failed: {error}")
}
