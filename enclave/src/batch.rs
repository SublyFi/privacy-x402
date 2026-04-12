use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use std::sync::Arc;
use tokio::time::{self, Duration};
use tracing::{info, warn};

use crate::audit;
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
/// Max age (seconds) for orphaned settlement_history entries before cleanup
const SETTLEMENT_HISTORY_MAX_AGE_SEC: i64 = 1800;

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
        .load(std::sync::atomic::Ordering::SeqCst);

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

    // Validate 1:1 pairing between settlements and audit records (design doc §6.3 l.800)
    if entries.len() != audit_entries.len() {
        warn!(
            settlements = entries.len(),
            audits = audit_entries.len(),
            "Settlement/audit count mismatch — skipping batch"
        );
        return;
    }

    info!(
        batch_id,
        provider_count = entries.len(),
        audit_count = audit_entries.len(),
        total_amount,
        "Batch settlement ready for on-chain submission"
    );

    // Phase 2: Submit atomic settle_vault + record_audit in chunks
    // Per design doc §6.3:
    //   - With audit: up to MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT per tx
    //   - Each chunk gets its own batch_chunk_hash for atomic pairing verification
    let chunks = build_batch_chunks(&entries, &audit_entries);

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let batch_chunk_hash = compute_batch_chunk_hash(batch_id, &chunk.settlements, &chunk.audits);

        info!(
            batch_id,
            chunk_idx,
            chunk_size = chunk.settlements.len(),
            chunk_hash = hex::encode(batch_chunk_hash),
            "Submitting atomic settle_vault + record_audit chunk"
        );

        // TODO: Build and submit Solana transaction via RPC:
        //   1. Build settle_vault instruction with chunk.settlements
        //   2. Build record_audit instruction with chunk.audits
        //   3. Add AuditRecord PDA accounts to remaining_accounts
        //   4. Combine in same VersionedTransaction
        //   5. Sign with vault_signer and send via RPC
        //
        // This requires Solana RPC client integration which depends on
        // enclave networking setup (vsock relay in production).

        if let Err(e) = state
            .wal
            .append(WalEntry::BatchSubmitted {
                batch_id,
                provider_count: chunk.settlements.len(),
                total_amount: chunk.settlements.iter().map(|s| s.amount).sum(),
            })
            .await
        {
            warn!(chunk_idx, "Failed to append batch chunk WAL entry: {e}");
        }
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

/// A chunk of settlements + audits to be submitted in a single atomic transaction.
struct BatchChunk {
    settlements: Vec<BatchSettlementEntry>,
    audits: Vec<BatchAuditEntry>,
}

/// Split settlements and audits into chunks of MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT.
fn build_batch_chunks(
    settlements: &[BatchSettlementEntry],
    audits: &[BatchAuditEntry],
) -> Vec<BatchChunk> {
    settlements
        .chunks(MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT)
        .zip(audits.chunks(MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT))
        .map(|(s_chunk, a_chunk)| BatchChunk {
            settlements: s_chunk.to_vec(),
            audits: a_chunk.to_vec(),
        })
        .collect()
}

/// Compute a deterministic hash for an atomic chunk (settle + audit pair).
/// Used as batch_chunk_hash in both settle_vault and record_audit instructions
/// to ensure they reference the same data.
fn compute_batch_chunk_hash(
    batch_id: u64,
    settlements: &[BatchSettlementEntry],
    audits: &[BatchAuditEntry],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"a402-batch-chunk-v1");
    hasher.update(batch_id.to_le_bytes());
    for s in settlements {
        hasher.update(s.provider_token_account.as_ref());
        hasher.update(s.amount.to_le_bytes());
    }
    for a in audits {
        hasher.update(&a.encrypted_sender);
        hasher.update(&a.encrypted_amount);
        hasher.update(a.provider.as_ref());
        hasher.update(a.timestamp.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Periodically expire stale reservations and clean up old settlement history
async fn reservation_expiry_loop(state: Arc<AppState>) {
    let mut interval = time::interval(Duration::from_secs(5));

    loop {
        interval.tick().await;
        let now = chrono::Utc::now().timestamp();

        // Expire stale reservations
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

        // Clean up orphaned settlement_history entries that are older than the max age.
        // These can accumulate when batches don't fire (e.g., provider count < MIN_BATCH_PROVIDERS).
        let stale_sids: Vec<String> = state
            .vault
            .settlement_history
            .iter()
            .filter(|r| now - r.timestamp > SETTLEMENT_HISTORY_MAX_AGE_SEC)
            .map(|r| r.settlement_id.clone())
            .collect();

        for sid in &stale_sids {
            state.vault.settlement_history.remove(sid);
        }
        if !stale_sids.is_empty() {
            warn!(
                count = stale_sids.len(),
                "Cleaned up stale settlement_history entries"
            );
        }
    }
}
