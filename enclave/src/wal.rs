use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
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
use crate::state::{ClientBalance, ProviderRegistration};

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
    ReservationCreated {
        verification_id: String,
        payment_id: String,
        client: String,
        provider_id: String,
        amount: u64,
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
    },
    ParticipantReceiptIssued {
        participant: String,
        participant_kind: u8,
        nonce: u64,
    },
    ProviderRegistered {
        provider_id: String,
        display_name: String,
        settlement_token_account: String,
        network: String,
        asset_mint: String,
        allowed_origins: Vec<String>,
        auth_mode: String,
        api_key_hash: String,
    },
    ClientBalanceSeeded {
        client: String,
        free: u64,
        locked: u64,
        max_lock_expires_at: i64,
        total_deposited: u64,
        total_withdrawn: u64,
    },
    BatchSubmitted {
        batch_id: u64,
        provider_count: usize,
        total_amount: u64,
    },
    BatchConfirmed {
        batch_id: u64,
        tx_signature: String,
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

/// Write-Ahead Log for durable state changes.
/// Phase 1: Simple file-based append-only log (not encrypted).
/// Production: encrypted via KMS, stored on parent instance.
pub struct Wal {
    path: PathBuf,
    seqno: std::sync::atomic::AtomicU64,
}

impl Wal {
    pub async fn new(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.ok();
        }
        // Count existing entries to set seqno
        let seqno = if path.exists() {
            let content = fs::read_to_string(&path).await.unwrap_or_default();
            content.lines().count() as u64
        } else {
            0
        };

        Self {
            path,
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

        let mut line = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        file.sync_all().await?;

        info!(seqno, "WAL entry appended");
        Ok(seqno)
    }

    pub async fn read_records(&self) -> Result<Vec<WalRecord>, std::io::Error> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = OpenOptions::new().read(true).open(&self.path).await?;
        let mut lines = BufReader::new(file).lines();
        let mut records = Vec::new();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            let record = serde_json::from_str::<WalRecord>(&line).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })?;
            records.push(record);
        }

        records.sort_by_key(|record| record.seqno);
        Ok(records)
    }
}

pub async fn replay_app_state(state: &AppState) -> Result<(), String> {
    let records = state
        .wal
        .read_records()
        .await
        .map_err(|error| format!("failed to read WAL: {error}"))?;

    for record in records {
        replay_entry(state, record.entry).await?;
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
        WalEntry::ProviderRegistered {
            provider_id,
            display_name,
            settlement_token_account,
            network,
            asset_mint,
            allowed_origins,
            auth_mode,
            api_key_hash,
        } => {
            let settlement_token_account =
                parse_pubkey("settlement_token_account", &settlement_token_account)?;
            let asset_mint = parse_pubkey("asset_mint", &asset_mint)?;
            let api_key_hash = hex::decode(api_key_hash)
                .map_err(|error| format!("invalid provider api_key_hash in WAL: {error}"))?;

            state.vault.providers.insert(
                provider_id.clone(),
                ProviderRegistration {
                    provider_id,
                    display_name,
                    settlement_token_account,
                    network,
                    asset_mint,
                    allowed_origins,
                    auth_mode,
                    api_key_hash,
                },
            );
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
