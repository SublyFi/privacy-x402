use solana_sdk::pubkey::Pubkey;
use std::sync::Arc;
use tokio::time::{self, Duration};
use tracing::{info, warn};

use crate::audit::{self, EncryptedAuditRecord};
use crate::handlers::AppState;
use crate::state::ReservationStatus;
use crate::wal::WalEntry;

const BATCH_WINDOW_SEC: u64 = 120;
const MAX_SETTLEMENT_DELAY_SEC: i64 = 900;
const MAX_SETTLEMENTS_PER_TX: usize = 20;
/// Max audit records per tx (settlement + audit in same tx)
const MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT: usize = 4;
const MIN_BATCH_PROVIDERS: usize = 2;
const RESERVATION_TIMEOUT_SEC: i64 = 60;

/// Settlement entry ready for on-chain batch
#[derive(Debug, Clone)]
pub struct BatchSettlementEntry {
    pub provider_token_account: Pubkey,
    pub amount: u64,
}

/// Audit record paired with a settlement entry
#[derive(Debug, Clone)]
pub struct BatchAuditEntry {
    pub encrypted_sender: [u8; 64],
    pub encrypted_amount: [u8; 64],
    pub provider: Pubkey,
    pub timestamp: i64,
}

/// Spawns the batch settlement loop and reservation expiry checker
pub fn spawn_background_tasks(state: Arc<AppState>) {
    let state_batch = state.clone();
    tokio::spawn(async move {
        batch_settlement_loop(state_batch).await;
    });

    let state_expiry = state.clone();
    tokio::spawn(async move {
        reservation_expiry_loop(state_expiry).await;
    });
}

/// Periodically checks if a batch should be fired
async fn batch_settlement_loop(state: Arc<AppState>) {
    let mut interval = time::interval(Duration::from_secs(10));

    loop {
        interval.tick().await;

        let now = chrono::Utc::now().timestamp();
        let last_batch = *state.vault.last_batch_at.read().await;
        let elapsed = now - last_batch;

        let mut should_batch = false;
        let mut oldest_credit_age: i64 = 0;
        let mut provider_count = 0;

        for entry in state.vault.provider_credits.iter() {
            if entry.credited_amount > 0 {
                provider_count += 1;
                let age = now - entry.oldest_credit_at;
                if age > oldest_credit_age {
                    oldest_credit_age = age;
                }
            }
        }

        if provider_count == 0 {
            continue;
        }

        // Batch triggers
        if elapsed >= BATCH_WINDOW_SEC as i64 {
            should_batch = true;
        }
        if provider_count >= MAX_SETTLEMENTS_PER_TX {
            should_batch = true;
        }
        if oldest_credit_age >= MAX_SETTLEMENT_DELAY_SEC {
            should_batch = true;
        }

        // Privacy: wait for MIN_BATCH_PROVIDERS unless MAX_SETTLEMENT_DELAY_SEC exceeded
        if should_batch && provider_count < MIN_BATCH_PROVIDERS && oldest_credit_age < MAX_SETTLEMENT_DELAY_SEC {
            continue;
        }

        if should_batch {
            fire_batch(&state, now).await;
        }
    }
}

/// Execute a batch settlement with audit record generation
async fn fire_batch(state: &Arc<AppState>, now: i64) {
    let mut entries: Vec<BatchSettlementEntry> = Vec::new();
    let mut provider_ids: Vec<String> = Vec::new();
    let mut settlement_ids_per_provider: Vec<Vec<String>> = Vec::new();
    let mut total_amount: u64 = 0;

    // Collect provider credits (up to MAX_SETTLEMENTS_PER_TX)
    for mut entry in state.vault.provider_credits.iter_mut() {
        if entry.credited_amount == 0 {
            continue;
        }
        if entries.len() >= MAX_SETTLEMENTS_PER_TX {
            break;
        }

        entries.push(BatchSettlementEntry {
            provider_token_account: entry.settlement_token_account,
            amount: entry.credited_amount,
        });
        total_amount += entry.credited_amount;
        provider_ids.push(entry.provider_id.clone());
        settlement_ids_per_provider.push(entry.settlement_ids.clone());

        // Reset credit
        entry.credited_amount = 0;
        entry.settlement_ids.clear();
        entry.oldest_credit_at = now;
    }

    if entries.is_empty() {
        return;
    }

    let batch_id = now as u64;

    // Phase 2: Generate encrypted audit records for each settlement
    let auditor_secret = *state.vault.auditor_master_secret.read().await;
    let auditor_epoch = state
        .vault
        .auditor_epoch
        .load(std::sync::atomic::Ordering::SeqCst) as u32;

    let mut audit_entries: Vec<BatchAuditEntry> = Vec::new();

    for settlement_ids in &settlement_ids_per_provider {
        for sid in settlement_ids {
            if let Some(record) = state.vault.settlement_history.get(sid) {
                let encrypted = audit::generate_audit_record(
                    &record.client,
                    &record.provider,
                    record.amount,
                    auditor_epoch,
                    &auditor_secret,
                );
                audit_entries.push(BatchAuditEntry {
                    encrypted_sender: encrypted.encrypted_sender,
                    encrypted_amount: encrypted.encrypted_amount,
                    provider: encrypted.provider,
                    timestamp: encrypted.timestamp,
                });
            }
        }
    }

    info!(
        batch_id,
        provider_count = entries.len(),
        audit_count = audit_entries.len(),
        total_amount,
        "Batch settlement ready for on-chain submission"
    );

    // Phase 2: Submit atomic settle_vault + record_audit chunks
    // Per design doc §6.3:
    //   - Without audit: up to 20 settlements per tx
    //   - With audit: up to 4-5 settlements per tx (AuditRecord PDA creation is expensive)
    //
    // TODO: Submit to on-chain via Solana RPC
    // For each chunk:
    //   1. Build settle_vault instruction with chunk of settlements
    //   2. Build record_audit instruction with corresponding audit records
    //   3. Combine in same transaction for atomic execution
    //   4. Sign with vault_signer and submit

    if let Err(e) = state
        .wal
        .append(WalEntry::BatchSubmitted {
            batch_id,
            provider_count: entries.len(),
            total_amount,
        })
        .await
    {
        warn!("Failed to append batch WAL entry: {e}");
    }

    // Clean up settlement history for processed records
    for settlement_ids in &settlement_ids_per_provider {
        for sid in settlement_ids {
            state.vault.settlement_history.remove(sid);
        }
    }

    // Update last batch time
    *state.vault.last_batch_at.write().await = now;
}

/// Periodically expire stale reservations
async fn reservation_expiry_loop(state: Arc<AppState>) {
    let mut interval = time::interval(Duration::from_secs(5));

    loop {
        interval.tick().await;
        let now = chrono::Utc::now().timestamp();

        let expired_ids: Vec<String> = state
            .vault
            .reservations
            .iter()
            .filter(|r| r.status == ReservationStatus::Reserved && now > r.expires_at)
            .map(|r| r.verification_id.clone())
            .collect();

        for ver_id in expired_ids {
            if let Some(mut reservation) = state.vault.reservations.get_mut(&ver_id) {
                reservation.status = ReservationStatus::Expired;
                let _ = state
                    .vault
                    .release_balance(&reservation.client, reservation.amount);

                let _ = state
                    .wal
                    .append(WalEntry::ReservationExpired {
                        verification_id: ver_id.clone(),
                    })
                    .await;

                info!(verification_id = %ver_id, "Reservation expired, balance released");
            }
        }
    }
}
