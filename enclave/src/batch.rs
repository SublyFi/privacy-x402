use a402_vault::accounts::{RecordAudit, SettleVault};
use a402_vault::instruction::{RecordAudit as RecordAuditIx, SettleVault as SettleVaultIx};
use a402_vault::instructions::record_audit::AuditRecordData;
use a402_vault::instructions::settle_vault::SettlementEntry;
use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_sdk::instruction::AccountMeta;
use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::solana_sdk::{system_program, sysvar};
use anchor_client::{Client, Cluster};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;
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

#[derive(Debug, Clone)]
struct PreparedSettlement {
    settlement_id: String,
    provider_id: String,
    settlement: BatchSettlementEntry,
    audit: BatchAuditEntry,
}

#[derive(Debug, Clone)]
pub struct BatchSubmitResult {
    pub submitted: bool,
    pub batch_id: Option<u64>,
    pub provider_count: usize,
    pub settlement_count: usize,
    pub total_amount: u64,
    pub tx_signatures: Vec<String>,
}

impl BatchSubmitResult {
    fn no_op() -> Self {
        Self {
            submitted: false,
            batch_id: None,
            provider_count: 0,
            settlement_count: 0,
            total_amount: 0,
            tx_signatures: Vec::new(),
        }
    }
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
        if should_batch
            && provider_count < MIN_BATCH_PROVIDERS
            && oldest_credit_age < MAX_SETTLEMENT_DELAY_SEC
        {
            continue;
        }

        if should_batch {
            if let Err(error) = fire_batch_at(&state, now).await {
                warn!(error = %error, "Automatic batch submission failed");
            }
        }
    }
}

/// Trigger a batch immediately, bypassing timing/privacy gates.
pub async fn fire_batch_now(state: &Arc<AppState>) -> Result<BatchSubmitResult, String> {
    fire_batch_at(state, chrono::Utc::now().timestamp()).await
}

/// Execute a batch settlement with audit record generation.
async fn fire_batch_at(state: &Arc<AppState>, now: i64) -> Result<BatchSubmitResult, String> {
    let prepared = prepare_batch(state).await?;
    if prepared.is_empty() {
        return Ok(BatchSubmitResult::no_op());
    }

    let provider_count = prepared
        .iter()
        .map(|entry| entry.provider_id.clone())
        .collect::<HashSet<_>>()
        .len();
    let total_amount: u64 = prepared.iter().map(|entry| entry.settlement.amount).sum();
    let batch_id = now as u64;

    info!(
        batch_id,
        provider_count,
        audit_count = prepared.len(),
        total_amount,
        "Batch settlement ready for on-chain submission"
    );

    let chunks = build_batch_chunks(&prepared);
    let mut tx_signatures = Vec::with_capacity(chunks.len());

    for (chunk_idx, chunk) in chunks.iter().cloned().enumerate() {
        let settlements = chunk.settlements();
        let audits = chunk.audits();
        let batch_chunk_hash = compute_batch_chunk_hash(batch_id, &settlements, &audits);

        info!(
            batch_id,
            chunk_idx,
            chunk_size = settlements.len(),
            start_index = chunk.start_index,
            chunk_hash = hex::encode(batch_chunk_hash),
            "Submitting atomic settle_vault + record_audit chunk"
        );

        let state_for_submit = state.clone();
        let chunk_for_submit = chunk.clone();
        let signature = tokio::task::spawn_blocking(move || {
            submit_atomic_chunk(
                &state_for_submit,
                batch_id,
                &chunk_for_submit,
                batch_chunk_hash,
            )
        })
        .await
        .map_err(|error| {
            format!("chunk {chunk_idx} task join failed for batch {batch_id}: {error}")
        })?
        .map_err(|error| {
            format!("chunk {chunk_idx} submission failed for batch {batch_id}: {error}")
        })?;

        apply_submitted_chunk(state, &chunk, now).await;
        state
            .wal
            .append(WalEntry::BatchConfirmed {
                batch_id,
                tx_signature: signature.clone(),
            })
            .await
            .map_err(|error| format!("failed to append BatchConfirmed WAL entry: {error}"))?;

        tx_signatures.push(signature);
    }

    state
        .wal
        .append(WalEntry::BatchSubmitted {
            batch_id,
            provider_count,
            total_amount,
        })
        .await
        .map_err(|error| format!("failed to append BatchSubmitted WAL entry: {error}"))?;

    Ok(BatchSubmitResult {
        submitted: true,
        batch_id: Some(batch_id),
        provider_count,
        settlement_count: prepared.len(),
        total_amount,
        tx_signatures,
    })
}

async fn prepare_batch(state: &Arc<AppState>) -> Result<Vec<PreparedSettlement>, String> {
    let auditor_secret = *state.vault.auditor_master_secret.read().await;
    let auditor_epoch = state
        .vault
        .auditor_epoch
        .load(std::sync::atomic::Ordering::SeqCst);
    let mut prepared: Vec<PreparedSettlement> = Vec::new();

    'credits: for entry in state.vault.provider_credits.iter() {
        if entry.credited_amount == 0 {
            continue;
        }

        for sid in &entry.settlement_ids {
            if prepared.len() >= MAX_SETTLEMENTS_PER_TX {
                break 'credits;
            }

            let Some(record) = state.vault.settlement_history.get(sid) else {
                return Err(format!(
                    "missing settlement_history entry for settlement_id={sid} provider_id={}",
                    entry.provider_id
                ));
            };

            let encrypted = audit::generate_audit_record(
                &record.client,
                &record.provider,
                record.amount,
                auditor_epoch,
                &auditor_secret,
            );

            prepared.push(PreparedSettlement {
                settlement_id: sid.clone(),
                provider_id: entry.provider_id.clone(),
                settlement: BatchSettlementEntry {
                    provider_token_account: record.provider,
                    amount: record.amount,
                },
                audit: BatchAuditEntry {
                    encrypted_sender: encrypted.encrypted_sender,
                    encrypted_amount: encrypted.encrypted_amount,
                    provider: encrypted.provider,
                    timestamp: encrypted.timestamp,
                },
            });
        }
    }

    Ok(prepared)
}

/// A chunk of settlements + audits to be submitted in a single atomic transaction.
#[derive(Clone)]
struct BatchChunk {
    start_index: u8,
    entries: Vec<PreparedSettlement>,
}

impl BatchChunk {
    fn settlements(&self) -> Vec<BatchSettlementEntry> {
        self.entries
            .iter()
            .map(|entry| entry.settlement.clone())
            .collect()
    }

    fn audits(&self) -> Vec<BatchAuditEntry> {
        self.entries
            .iter()
            .map(|entry| entry.audit.clone())
            .collect()
    }
}

fn build_batch_chunks(entries: &[PreparedSettlement]) -> Vec<BatchChunk> {
    entries
        .chunks(MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT)
        .enumerate()
        .map(|(chunk_idx, chunk)| BatchChunk {
            start_index: (chunk_idx * MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT) as u8,
            entries: chunk.to_vec(),
        })
        .collect()
}

fn submit_atomic_chunk(
    state: &Arc<AppState>,
    batch_id: u64,
    chunk: &BatchChunk,
    batch_chunk_hash: [u8; 32],
) -> Result<String, String> {
    let payer = Rc::new(Keypair::new_from_array(state.vault.vault_signer.to_bytes()));
    let client = Client::new_with_options(
        Cluster::Custom(
            state.vault.solana.rpc_url.clone(),
            state.vault.solana.ws_url.clone(),
        ),
        payer,
        CommitmentConfig::confirmed(),
    );
    let program = client
        .program(state.vault.solana.program_id)
        .map_err(|error| format!("failed to create Anchor program client: {error}"))?;

    let settlements: Vec<SettlementEntry> = chunk
        .entries
        .iter()
        .map(|entry| SettlementEntry {
            provider_token_account: entry.settlement.provider_token_account,
            amount: entry.settlement.amount,
        })
        .collect();
    let settlement_accounts: Vec<AccountMeta> = chunk
        .entries
        .iter()
        .map(|entry| AccountMeta::new(entry.settlement.provider_token_account, false))
        .collect();

    let settle_ix = program
        .request()
        .accounts(SettleVault {
            vault_signer: state.vault.vault_signer_pubkey,
            vault_config: state.vault.vault_config,
            vault_token_account: state.vault.solana.vault_token_account,
            instructions_sysvar: sysvar::instructions::ID,
            token_program: spl_token::ID,
        })
        .accounts(settlement_accounts)
        .args(SettleVaultIx {
            batch_id,
            batch_chunk_hash,
            settlements,
        })
        .instructions()
        .map_err(|error| format!("failed to build settle_vault instruction: {error}"))?
        .into_iter()
        .next()
        .ok_or_else(|| "failed to extract settle_vault instruction".to_string())?;

    let records: Vec<AuditRecordData> = chunk
        .entries
        .iter()
        .map(|entry| AuditRecordData {
            encrypted_sender: entry.audit.encrypted_sender,
            encrypted_amount: entry.audit.encrypted_amount,
            provider: entry.audit.provider,
            timestamp: entry.audit.timestamp,
        })
        .collect();
    let audit_accounts: Vec<AccountMeta> = chunk
        .entries
        .iter()
        .enumerate()
        .map(|(offset, _)| {
            let (audit_pda, _) = Pubkey::find_program_address(
                &[
                    b"audit",
                    state.vault.vault_config.as_ref(),
                    &batch_id.to_le_bytes(),
                    &[chunk.start_index + offset as u8],
                ],
                &state.vault.solana.program_id,
            );
            AccountMeta::new(audit_pda, false)
        })
        .collect();

    let record_audit_ix = program
        .request()
        .accounts(RecordAudit {
            vault_signer: state.vault.vault_signer_pubkey,
            vault_config: state.vault.vault_config,
            instructions_sysvar: sysvar::instructions::ID,
            system_program: system_program::ID,
        })
        .accounts(audit_accounts)
        .args(RecordAuditIx {
            batch_id,
            batch_chunk_hash,
            records,
        })
        .instructions()
        .map_err(|error| format!("failed to build record_audit instruction: {error}"))?
        .into_iter()
        .next()
        .ok_or_else(|| "failed to extract record_audit instruction".to_string())?;

    let submit_result = program
        .request()
        .instruction(settle_ix)
        .instruction(record_audit_ix)
        .send()
        .map(|signature| signature.to_string())
        .map_err(|error| format!("failed to submit atomic chunk: {error}"));

    submit_result
}

async fn apply_submitted_chunk(state: &Arc<AppState>, chunk: &BatchChunk, now: i64) {
    let submitted_ids: HashSet<String> = chunk
        .entries
        .iter()
        .map(|entry| entry.settlement_id.clone())
        .collect();

    for entry in &chunk.entries {
        state.vault.settlement_history.remove(&entry.settlement_id);

        if let Some(mut credit) = state.vault.provider_credits.get_mut(&entry.provider_id) {
            credit.credited_amount = credit
                .credited_amount
                .saturating_sub(entry.settlement.amount);
            credit
                .settlement_ids
                .retain(|sid| sid != &entry.settlement_id);
        }
    }

    let provider_ids_to_remove: Vec<String> = state
        .vault
        .provider_credits
        .iter()
        .filter(|credit| credit.credited_amount == 0 || credit.settlement_ids.is_empty())
        .map(|credit| credit.provider_id.clone())
        .collect();
    for provider_id in provider_ids_to_remove {
        state.vault.provider_credits.remove(&provider_id);
    }

    let remaining_oldest_by_provider = recompute_oldest_credit_times(state);
    for (provider_id, oldest_credit_at) in remaining_oldest_by_provider {
        if let Some(mut credit) = state.vault.provider_credits.get_mut(&provider_id) {
            credit.oldest_credit_at = oldest_credit_at;
        }
    }

    for mut reservation in state.vault.reservations.iter_mut() {
        if reservation
            .settlement_id
            .as_ref()
            .map(|settlement_id| submitted_ids.contains(settlement_id))
            .unwrap_or(false)
        {
            reservation.status = ReservationStatus::BatchedOnchain;
        }
    }

    *state.vault.last_batch_at.write().await = now;
}

fn recompute_oldest_credit_times(state: &Arc<AppState>) -> HashMap<String, i64> {
    state
        .vault
        .provider_credits
        .iter()
        .filter_map(|credit| {
            credit
                .settlement_ids
                .iter()
                .filter_map(|settlement_id| {
                    state
                        .vault
                        .settlement_history
                        .get(settlement_id)
                        .map(|record| record.timestamp)
                })
                .min()
                .map(|oldest| (credit.provider_id.clone(), oldest))
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

        // Expire stale ASC channel requests (Phase 3)
        crate::asc_manager::expire_stale_requests(&state.vault);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(index: u8) -> PreparedSettlement {
        PreparedSettlement {
            settlement_id: format!("set-{index}"),
            provider_id: format!("provider-{index}"),
            settlement: BatchSettlementEntry {
                provider_token_account: Pubkey::new_unique(),
                amount: (index as u64) + 1,
            },
            audit: BatchAuditEntry {
                encrypted_sender: [index; 64],
                encrypted_amount: [index.wrapping_add(1); 64],
                provider: Pubkey::new_unique(),
                timestamp: index as i64,
            },
        }
    }

    #[test]
    fn build_batch_chunks_preserves_global_indices() {
        let entries: Vec<PreparedSettlement> = (0..6).map(sample_entry).collect();
        let chunks = build_batch_chunks(&entries);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].start_index, 0);
        assert_eq!(chunks[0].entries.len(), 4);
        assert_eq!(chunks[1].start_index, 4);
        assert_eq!(chunks[1].entries.len(), 2);
        assert_eq!(chunks[1].entries[0].settlement_id, "set-4");
    }

    #[test]
    fn compute_batch_chunk_hash_depends_on_order() {
        let entry_a = sample_entry(1);
        let entry_b = sample_entry(2);

        let hash_ab = compute_batch_chunk_hash(
            42,
            &[entry_a.settlement.clone(), entry_b.settlement.clone()],
            &[entry_a.audit.clone(), entry_b.audit.clone()],
        );
        let hash_ba = compute_batch_chunk_hash(
            42,
            &[entry_b.settlement.clone(), entry_a.settlement.clone()],
            &[entry_b.audit.clone(), entry_a.audit.clone()],
        );

        assert_ne!(hash_ab, hash_ba);
    }
}
