use a402_vault::accounts::{RecordAudit, SettleVault};
use a402_vault::asc_claim::hash_identifier;
use a402_vault::instruction::{RecordAudit as RecordAuditIx, SettleVault as SettleVaultIx};
use a402_vault::instructions::record_audit::AuditRecordData;
use a402_vault::instructions::settle_vault::SettlementEntry;
use a402_vault::state::AscCloseClaim as OnChainAscCloseClaim;
use anchor_client::anchor_lang::AccountDeserialize;
use anchor_client::solana_sdk::commitment_config::CommitmentConfig;
use anchor_client::solana_sdk::instruction::AccountMeta;
use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::solana_sdk::sysvar;
use anchor_client::solana_sdk::transaction::Transaction;
use anchor_client::{Client, Cluster};
use rand::Rng;
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use solana_sdk_ids::system_program;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use tokio::time::{self, Duration};
use tracing::{info, warn};

use crate::audit;
use crate::handlers::AppState;
use crate::state::{PendingWithdrawal, ReservationStatus, SettlementRecord};
use crate::wal::WalEntry;

const BATCH_WINDOW_SEC: u64 = 120;
const MAX_SETTLEMENT_DELAY_SEC: i64 = 900;
const MAX_SETTLEMENTS_PER_TX: usize = 20;
/// Max audit records per tx (settlement + audit in same tx)
const MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT: usize = 4;
const MIN_BATCH_PROVIDERS: usize = 2;
const MAX_BATCH_JITTER_SEC: i64 = 30;
/// Max age (seconds) for orphaned settlement_history entries before cleanup
const SETTLEMENT_HISTORY_MAX_AGE_SEC: i64 = 1800;
const DEFAULT_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC: u64 = 1_000_000;

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
struct ProviderBatchCursor {
    provider_id: String,
    oldest_credit_at: i64,
    settlement_ids: Vec<String>,
    next_index: usize,
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

#[derive(Debug, Clone, Copy)]
pub struct BatchPrivacyConfig {
    /// Automatic batches defer provider payouts smaller than this floor unless
    /// `MAX_SETTLEMENT_DELAY_SEC` is hit. Set to 0 to disable.
    pub auto_batch_min_provider_payout_atomic: u64,
}

impl Default for BatchPrivacyConfig {
    fn default() -> Self {
        Self {
            auto_batch_min_provider_payout_atomic: DEFAULT_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC,
        }
    }
}

impl BatchPrivacyConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(value) = std::env::var("A402_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC") {
            config.auto_batch_min_provider_payout_atomic = value.parse().unwrap_or_else(|_| {
                panic!("A402_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC must be a valid u64")
            });
        }
        config
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchBuildMode {
    Auto,
    Flush,
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
    let mut jitter_deadline: Option<i64> = None;
    let batch_privacy = state.batch_privacy;

    loop {
        interval.tick().await;

        let now = chrono::Utc::now().timestamp();
        let last_batch = *state.vault.last_batch_at.read().await;
        let elapsed = now - last_batch;

        let mut oldest_credit_age: i64 = 0;
        let mut provider_count = 0;

        for entry in state.vault.provider_credits.iter() {
            if entry.credited_amount > 0 {
                let age = now - entry.oldest_credit_at;
                if age > oldest_credit_age {
                    oldest_credit_age = age;
                }
                if provider_is_auto_batchable(entry.credited_amount, age, batch_privacy) {
                    provider_count += 1;
                }
            }
        }

        let sampled_jitter_sec = rand::thread_rng().gen_range(0..=MAX_BATCH_JITTER_SEC);
        let (decision, next_deadline) = decide_batch_action(
            now,
            elapsed,
            provider_count,
            oldest_credit_age,
            jitter_deadline,
            sampled_jitter_sec,
        );

        if matches!(decision, BatchLoopDecision::Wait) && jitter_deadline != next_deadline {
            if let Some(deadline) = next_deadline {
                info!(
                    provider_count,
                    oldest_credit_age,
                    jitter_deadline = deadline,
                    "Privacy jitter delaying automatic batch submission"
                );
            }
        }

        jitter_deadline = next_deadline;

        if matches!(decision, BatchLoopDecision::Fire) {
            if let Err(error) = fire_batch_at(&state, now, BatchBuildMode::Auto).await {
                warn!(error = %error, "Automatic batch submission failed");
            }
        }
    }
}

/// Trigger a batch immediately, bypassing timing/privacy gates.
pub async fn fire_batch_now(state: &Arc<AppState>) -> Result<BatchSubmitResult, String> {
    fire_batch_at(state, chrono::Utc::now().timestamp(), BatchBuildMode::Flush).await
}

/// Execute a batch settlement with audit record generation.
async fn fire_batch_at(
    state: &Arc<AppState>,
    now: i64,
    mode: BatchBuildMode,
) -> Result<BatchSubmitResult, String> {
    let prepared = prepare_batch(state, now, mode).await?;
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
        let settlements = aggregate_settlements(&chunk.entries)?;
        let audits = chunk.audits();
        let batch_chunk_hash = compute_batch_chunk_hash(batch_id, &settlements, &audits);

        info!(
            batch_id,
            chunk_idx,
            onchain_transfer_count = settlements.len(),
            audit_count = audits.len(),
            start_index = chunk.start_index,
            chunk_hash = hex::encode(batch_chunk_hash),
            "Submitting atomic settle_vault + record_audit chunk"
        );

        let signature =
            submit_atomic_chunk(state, batch_id, &chunk, &settlements, batch_chunk_hash)
                .await
                .map_err(|error| {
                    format!("chunk {chunk_idx} submission failed for batch {batch_id}: {error}")
                })?;

        let settlement_ids: Vec<String> = chunk
            .entries
            .iter()
            .map(|entry| entry.settlement_id.clone())
            .collect();

        let affected_provider_ids = {
            let _persist_guard = state.persistence_lock.lock().await;
            state
                .wal
                .append(WalEntry::BatchConfirmed {
                    batch_id,
                    tx_signature: signature.clone(),
                    settlement_ids: settlement_ids.clone(),
                })
                .await
                .map_err(|error| format!("failed to append BatchConfirmed WAL entry: {error}"))?;
            apply_submitted_chunk(state, &chunk, now, batch_id, &signature).await
        };

        for provider_id in affected_provider_ids {
            if let Err(error) = retry_provider_receipt_mirror(state, &provider_id, 3).await {
                warn!(
                    %provider_id,
                    batch_id,
                    error = %error,
                    "Failed to mirror provider receipt after batch confirmation"
                );
            }
        }

        tx_signatures.push(signature);
    }

    {
        let _persist_guard = state.persistence_lock.lock().await;
        state
            .wal
            .append(WalEntry::BatchSubmitted {
                batch_id,
                provider_count,
                total_amount,
            })
            .await
            .map_err(|error| format!("failed to append BatchSubmitted WAL entry: {error}"))?;
    }

    Ok(BatchSubmitResult {
        submitted: true,
        batch_id: Some(batch_id),
        provider_count,
        settlement_count: prepared.len(),
        total_amount,
        tx_signatures,
    })
}

async fn prepare_batch(
    state: &Arc<AppState>,
    batch_timestamp: i64,
    mode: BatchBuildMode,
) -> Result<Vec<PreparedSettlement>, String> {
    let auditor_secret = *state.vault.auditor_master_secret.read().await;
    let auditor_epoch = state
        .vault
        .auditor_epoch
        .load(std::sync::atomic::Ordering::SeqCst);
    let batch_privacy = state.batch_privacy;
    let cursors: Vec<ProviderBatchCursor> = state
        .vault
        .provider_credits
        .iter()
        .filter(|entry| {
            if entry.credited_amount == 0 {
                return false;
            }
            match mode {
                BatchBuildMode::Flush => true,
                BatchBuildMode::Auto => provider_is_auto_batchable(
                    entry.credited_amount,
                    batch_timestamp - entry.oldest_credit_at,
                    batch_privacy,
                ),
            }
        })
        .map(|entry| ProviderBatchCursor {
            provider_id: entry.provider_id.clone(),
            oldest_credit_at: entry.oldest_credit_at,
            settlement_ids: entry.settlement_ids.clone(),
            next_index: 0,
        })
        .collect();

    let mut prepared: Vec<PreparedSettlement> = Vec::new();
    for (provider_id, sid) in select_batch_settlement_ids(cursors, MAX_SETTLEMENTS_PER_TX) {
        let record = if let Some(record) = state.vault.settlement_history.get(&sid) {
            record.clone()
        } else if let Some(record) = reconstruct_settlement_record(state, &provider_id, &sid) {
            warn!(
                settlement_id = %sid,
                provider_id = %provider_id,
                "Reconstructed missing settlement_history entry from reservation state"
            );
            state
                .vault
                .settlement_history
                .insert(sid.clone(), record.clone());
            record
        } else {
            warn!(
                settlement_id = %sid,
                provider_id = %provider_id,
                "Pruning provider credit with missing settlement_history and reservation state"
            );
            prune_missing_settlement_reference(state, &provider_id, &sid);
            continue;
        };

        let encrypted = audit::generate_audit_record_at(
            &record.client,
            &record.provider,
            record.amount,
            auditor_epoch,
            &auditor_secret,
            batch_timestamp,
        );

        prepared.push(PreparedSettlement {
            settlement_id: sid,
            provider_id,
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

    Ok(prepared)
}

fn reconstruct_settlement_record(
    state: &Arc<AppState>,
    provider_id: &str,
    settlement_id: &str,
) -> Option<SettlementRecord> {
    let reservation = state
        .vault
        .reservations
        .iter()
        .find(|entry| entry.settlement_id.as_deref() == Some(settlement_id))?
        .clone();
    if reservation.provider_id != provider_id
        || reservation.status != ReservationStatus::SettledOffchain
    {
        return None;
    }

    let provider = state.vault.providers.get(provider_id)?;
    Some(SettlementRecord {
        settlement_id: settlement_id.to_string(),
        client: reservation.client,
        provider: provider.settlement_token_account,
        amount: reservation.amount,
        timestamp: reservation.settled_at.unwrap_or(reservation.created_at),
    })
}

fn prune_missing_settlement_reference(
    state: &Arc<AppState>,
    provider_id: &str,
    settlement_id: &str,
) {
    let Some(mut credit) = state.vault.provider_credits.get_mut(provider_id) else {
        return;
    };

    credit.settlement_ids.retain(|sid| sid != settlement_id);

    let mut credited_amount = 0u64;
    let mut oldest_credit_at: Option<i64> = None;
    for sid in &credit.settlement_ids {
        if let Some(record) = state.vault.settlement_history.get(sid) {
            credited_amount = credited_amount.saturating_add(record.amount);
            oldest_credit_at = Some(
                oldest_credit_at
                    .map(|current| current.min(record.timestamp))
                    .unwrap_or(record.timestamp),
            );
        }
    }

    credit.credited_amount = credited_amount;
    if let Some(oldest_credit_at) = oldest_credit_at {
        credit.oldest_credit_at = oldest_credit_at;
    }

    let should_remove = credit.credited_amount == 0 || credit.settlement_ids.is_empty();
    drop(credit);
    if should_remove {
        state.vault.provider_credits.remove(provider_id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchLoopDecision {
    Skip,
    Wait,
    Fire,
}

fn decide_batch_action(
    now: i64,
    elapsed: i64,
    provider_count: usize,
    oldest_credit_age: i64,
    jitter_deadline: Option<i64>,
    sampled_jitter_sec: i64,
) -> (BatchLoopDecision, Option<i64>) {
    if provider_count == 0 {
        return (BatchLoopDecision::Skip, None);
    }

    let should_batch = elapsed >= BATCH_WINDOW_SEC as i64
        || provider_count >= MAX_SETTLEMENTS_PER_TX
        || oldest_credit_age >= MAX_SETTLEMENT_DELAY_SEC;
    if !should_batch {
        return (BatchLoopDecision::Skip, None);
    }

    let deadline_reached = oldest_credit_age >= MAX_SETTLEMENT_DELAY_SEC;
    if provider_count < MIN_BATCH_PROVIDERS && !deadline_reached {
        return (BatchLoopDecision::Skip, None);
    }

    if deadline_reached {
        return (BatchLoopDecision::Fire, None);
    }

    let jitter_deadline = jitter_deadline.or(Some(now + sampled_jitter_sec));
    if now < jitter_deadline.unwrap_or(now) {
        return (BatchLoopDecision::Wait, jitter_deadline);
    }

    (BatchLoopDecision::Fire, None)
}

fn provider_is_auto_batchable(
    credited_amount: u64,
    oldest_credit_age: i64,
    config: BatchPrivacyConfig,
) -> bool {
    if credited_amount == 0 {
        return false;
    }
    if oldest_credit_age >= MAX_SETTLEMENT_DELAY_SEC {
        return true;
    }

    config.auto_batch_min_provider_payout_atomic == 0
        || credited_amount >= config.auto_batch_min_provider_payout_atomic
}

/// A chunk of settlements + audits to be submitted in a single atomic transaction.
#[derive(Clone)]
struct BatchChunk {
    start_index: u8,
    entries: Vec<PreparedSettlement>,
}

impl BatchChunk {
    fn audits(&self) -> Vec<BatchAuditEntry> {
        self.entries
            .iter()
            .map(|entry| entry.audit.clone())
            .collect()
    }
}

fn select_batch_settlement_ids(
    mut cursors: Vec<ProviderBatchCursor>,
    max_entries: usize,
) -> Vec<(String, String)> {
    cursors.retain(|cursor| !cursor.settlement_ids.is_empty());
    cursors.sort_by(|a, b| {
        a.oldest_credit_at
            .cmp(&b.oldest_credit_at)
            .then_with(|| a.provider_id.cmp(&b.provider_id))
    });

    let mut selected = Vec::with_capacity(max_entries);
    while selected.len() < max_entries {
        let mut advanced = false;

        for cursor in &mut cursors {
            if selected.len() >= max_entries {
                break;
            }

            let Some(settlement_id) = cursor.settlement_ids.get(cursor.next_index) else {
                continue;
            };

            selected.push((cursor.provider_id.clone(), settlement_id.clone()));
            cursor.next_index += 1;
            advanced = true;
        }

        if !advanced {
            break;
        }
    }

    selected
}

fn build_batch_chunks(entries: &[PreparedSettlement]) -> Vec<BatchChunk> {
    if entries.is_empty() {
        return Vec::new();
    }

    let chunk_count =
        (entries.len() + MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT - 1) / MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT;
    let base_chunk_size = entries.len() / chunk_count;
    let extra_entries = entries.len() % chunk_count;

    let mut start = 0usize;
    let mut chunks = Vec::with_capacity(chunk_count);
    for chunk_idx in 0..chunk_count {
        let chunk_size = base_chunk_size + usize::from(chunk_idx < extra_entries);
        let end = start + chunk_size;
        chunks.push(BatchChunk {
            start_index: start as u8,
            entries: entries[start..end].to_vec(),
        });
        start = end;
    }

    chunks
}

fn aggregate_settlements(
    entries: &[PreparedSettlement],
) -> Result<Vec<BatchSettlementEntry>, String> {
    let mut aggregated = BTreeMap::<Pubkey, u64>::new();

    for entry in entries {
        let total = aggregated
            .entry(entry.settlement.provider_token_account)
            .or_insert(0);
        *total = total.checked_add(entry.settlement.amount).ok_or_else(|| {
            format!(
                "aggregated provider amount overflow for {}",
                entry.settlement.provider_token_account
            )
        })?;
    }

    Ok(aggregated
        .into_iter()
        .map(|(provider_token_account, amount)| BatchSettlementEntry {
            provider_token_account,
            amount,
        })
        .collect())
}

async fn submit_atomic_chunk(
    state: &Arc<AppState>,
    batch_id: u64,
    chunk: &BatchChunk,
    aggregated_settlements: &[BatchSettlementEntry],
    batch_chunk_hash: [u8; 32],
) -> Result<String, String> {
    let signer_bytes = state.vault.vault_signer.to_bytes();
    let payer = Keypair::new_from_array(signer_bytes);
    let settlements: Vec<SettlementEntry> = aggregated_settlements
        .iter()
        .map(|entry| SettlementEntry {
            provider_token_account: entry.provider_token_account,
            amount: entry.amount,
        })
        .collect();
    let settlement_accounts: Vec<AccountMeta> = aggregated_settlements
        .iter()
        .map(|entry| AccountMeta::new(entry.provider_token_account, false))
        .collect();

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

    let instructions = {
        let program_payer = Rc::new(Keypair::new_from_array(signer_bytes));
        let client = Client::new_with_options(
            Cluster::Custom(
                state.vault.solana.rpc_url.clone(),
                state.vault.solana.ws_url.clone(),
            ),
            program_payer,
            CommitmentConfig::confirmed(),
        );
        let program = client
            .program(state.vault.solana.program_id)
            .map_err(|error| format!("failed to create Anchor program client: {error}"))?;

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

        let instructions = program
            .request()
            .instruction(settle_ix)
            .instruction(record_audit_ix)
            .instructions()
            .map_err(|error| format!("failed to build atomic chunk instructions: {error}"))?;
        instructions
    };

    let rpc = state.outbound.solana_rpc_client(
        state.vault.solana.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );
    let recent_blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|error| format!("failed to fetch recent blockhash: {error}"))?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&state.vault.vault_signer_pubkey),
        &[&payer],
        recent_blockhash,
    );
    rpc.send_and_confirm_transaction(&transaction)
        .await
        .map(|signature| signature.to_string())
        .map_err(|error| format!("failed to submit atomic chunk: {error}"))
}

async fn apply_submitted_chunk(
    state: &Arc<AppState>,
    chunk: &BatchChunk,
    now: i64,
    batch_id: u64,
    tx_signature: &str,
) -> Vec<String> {
    let affected_provider_ids: HashSet<String> = chunk
        .entries
        .iter()
        .map(|entry| entry.provider_id.clone())
        .collect();
    let submitted_ids: Vec<String> = chunk
        .entries
        .iter()
        .map(|entry| entry.settlement_id.clone())
        .collect();
    state
        .vault
        .apply_batch_confirmation(&submitted_ids, batch_id, tx_signature);

    *state.vault.last_batch_at.write().await = now;

    affected_provider_ids.into_iter().collect()
}

async fn retry_provider_receipt_mirror(
    state: &Arc<AppState>,
    provider_id: &str,
    attempts: usize,
) -> Result<(), crate::error::EnclaveError> {
    let attempts = attempts.max(1);
    let mut delay = Duration::from_millis(100);
    let mut last_error = None;

    for attempt in 1..=attempts {
        match crate::handlers::issue_provider_receipt(state, provider_id).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt < attempts {
                    time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(2));
                }
            }
        }
    }

    Err(last_error.expect("provider receipt retry must record an error"))
}

async fn retry_client_receipt_mirror(
    state: &Arc<AppState>,
    client: Pubkey,
    attempts: usize,
) -> Result<(), crate::error::EnclaveError> {
    let attempts = attempts.max(1);
    let mut delay = Duration::from_millis(100);
    let mut last_error = None;

    for attempt in 1..=attempts {
        match crate::handlers::issue_client_receipt(state, client).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt < attempts {
                    time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(2));
                }
            }
        }
    }

    Err(last_error.expect("client receipt retry must record an error"))
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

async fn recover_pending_channel_claims(state: &Arc<AppState>) {
    let pending_channels: Vec<(String, String)> = state
        .vault
        .active_channels
        .iter()
        .filter_map(|channel| {
            (channel.status == crate::state::ChannelStatus::Pending)
                .then_some(channel)
                .and_then(|channel| {
                    channel
                        .active_request
                        .as_ref()
                        .map(|request| (channel.channel_id.clone(), request.request_id.clone()))
                })
        })
        .collect();

    if pending_channels.is_empty() {
        return;
    }

    let rpc = state.outbound.solana_rpc_client(
        state.vault.solana.rpc_url.clone(),
        CommitmentConfig::confirmed(),
    );

    for (channel_id, request_id) in pending_channels {
        let channel_id_hash = hash_identifier(&channel_id);
        let request_id_hash = hash_identifier(&request_id);
        let (claim_pda, _) = Pubkey::find_program_address(
            &[
                b"asc_close_claim",
                state.vault.vault_config.as_ref(),
                channel_id_hash.as_ref(),
                request_id_hash.as_ref(),
            ],
            &state.vault.solana.program_id,
        );

        let account = match rpc
            .get_account_with_commitment(&claim_pda, CommitmentConfig::confirmed())
            .await
        {
            Ok(response) => response.value,
            Err(error) => {
                warn!(
                    %channel_id,
                    %request_id,
                    %claim_pda,
                    error = %error,
                    "Failed to fetch ASC close claim account"
                );
                continue;
            }
        };
        let Some(account) = account else {
            continue;
        };

        let mut slice: &[u8] = account.data.as_slice();
        let claim = match OnChainAscCloseClaim::try_deserialize(&mut slice) {
            Ok(claim) => claim,
            Err(error) => {
                warn!(
                    %channel_id,
                    %request_id,
                    %claim_pda,
                    error = %error,
                    "Failed to decode ASC close claim account"
                );
                continue;
            }
        };

        let (client, recovered_amount) = {
            let _guard = state.asc_ops_lock.lock().await;
            let _persist_guard = state.persistence_lock.lock().await;
            let outcome = match crate::asc_manager::finalize_onchain_claim(
                &state.vault,
                &channel_id,
                claim.full_sig_r,
                claim.full_sig_s,
            ) {
                Ok(outcome) => outcome,
                Err(crate::error::EnclaveError::ChannelNotFound)
                | Err(crate::error::EnclaveError::InvalidChannelStatus(_)) => {
                    continue;
                }
                Err(error) => {
                    warn!(
                        %channel_id,
                        %request_id,
                        %claim_pda,
                        error = %error,
                        "Failed to finalize pending ASC from on-chain claim"
                    );
                    continue;
                }
            };

            if let Err(error) = state
                .wal
                .append(WalEntry::ChannelFinalized {
                    channel_id: channel_id.clone(),
                    request_id: outcome.request_id.clone(),
                    amount_paid: outcome.amount,
                })
                .await
            {
                let _ = crate::asc_manager::rollback_finalize_offchain(
                    &state.vault,
                    &channel_id,
                    outcome.request.clone(),
                );
                warn!(
                    %channel_id,
                    %request_id,
                    %claim_pda,
                    error = %error,
                    "WAL append failed after on-chain ASC recovery"
                );
                continue;
            }

            let client = match state.vault.active_channels.get(&channel_id) {
                Some(channel) => channel.client,
                None => {
                    warn!(
                        %channel_id,
                        %request_id,
                        %claim_pda,
                        "Recovered ASC claim but channel disappeared before receipt refresh"
                    );
                    continue;
                }
            };
            if let Err(error) = state.vault.refresh_client_max_lock_expires_at(&client) {
                warn!(
                    %channel_id,
                    %request_id,
                    %claim_pda,
                    error = %error,
                    "Failed to refresh client lock expiry after on-chain ASC recovery"
                );
            }
            (client, outcome.amount)
        };

        if let Err(error) = retry_client_receipt_mirror(state, client, 3).await {
            warn!(
                %channel_id,
                %request_id,
                %claim_pda,
                error = %error,
                "Failed to mirror client receipt after on-chain ASC recovery"
            );
        }

        info!(
            %channel_id,
            %request_id,
            %claim_pda,
            amount = recovered_amount,
            "Recovered pending ASC from on-chain close claim"
        );
    }
}

async fn withdraw_nonce_recorded_onchain(
    state: &Arc<AppState>,
    withdrawal: &PendingWithdrawal,
) -> Result<bool, String> {
    let rpc = state.outbound.solana_rpc_client(
        state.vault.solana.rpc_url.clone(),
        CommitmentConfig::finalized(),
    );
    let (used_withdraw_nonce, _) = Pubkey::find_program_address(
        &[
            b"withdraw_nonce",
            state.vault.vault_config.as_ref(),
            withdrawal.client.as_ref(),
            &withdrawal.withdraw_nonce.to_le_bytes(),
        ],
        &state.vault.solana.program_id,
    );

    rpc.get_account_with_commitment(&used_withdraw_nonce, CommitmentConfig::finalized())
        .await
        .map(|response| response.value.is_some())
        .map_err(|error| {
            format!(
                "failed to fetch UsedWithdrawNonce {}: {error}",
                used_withdraw_nonce
            )
        })
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
            if let Err(error) =
                crate::handlers::expire_reserved_reservation(&state, &ver_id, now).await
            {
                warn!(
                    verification_id = %ver_id,
                    error = %error,
                    "Failed to expire reservation"
                );
            }
        }

        let expired_withdrawals: Vec<PendingWithdrawal> = state
            .vault
            .pending_withdrawals
            .iter()
            .filter(|withdrawal| now > withdrawal.expires_at)
            .map(|withdrawal| withdrawal.clone())
            .collect();

        for withdrawal in expired_withdrawals {
            match withdraw_nonce_recorded_onchain(&state, &withdrawal).await {
                Ok(true) => {
                    info!(
                        client = %withdrawal.client,
                        amount = withdrawal.amount,
                        withdraw_nonce = withdrawal.withdraw_nonce,
                        "Skipping withdrawal expiry because UsedWithdrawNonce already exists on-chain"
                    );
                }
                Ok(false) => {
                    if let Err(error) = crate::handlers::expire_pending_withdrawal(
                        &state,
                        withdrawal.withdraw_nonce,
                        now,
                    )
                    .await
                    {
                        warn!(
                            withdraw_nonce = withdrawal.withdraw_nonce,
                            error = %error,
                            "Failed to expire pending withdrawal"
                        );
                    }
                }
                Err(error) => {
                    warn!(
                        withdraw_nonce = withdrawal.withdraw_nonce,
                        error = %error,
                        "Failed to verify UsedWithdrawNonce before expiry; leaving withdrawal locked"
                    );
                }
            }
        }

        // Clean up orphaned settlement_history entries that are older than the max age.
        // These can accumulate when batches don't fire (e.g., provider count < MIN_BATCH_PROVIDERS).
        let referenced_settlement_ids: HashSet<String> = state
            .vault
            .provider_credits
            .iter()
            .flat_map(|credit| credit.settlement_ids.clone())
            .collect();
        let stale_sids: Vec<String> = state
            .vault
            .settlement_history
            .iter()
            .filter(|r| {
                now - r.timestamp > SETTLEMENT_HISTORY_MAX_AGE_SEC
                    && !referenced_settlement_ids.contains(&r.settlement_id)
            })
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

        // Expire stale ASC channel requests (Phase 3) durably.
        let expired_channel_ids: Vec<String> = state
            .vault
            .active_channels
            .iter()
            .filter(|channel| {
                matches!(
                    channel.status,
                    crate::state::ChannelStatus::Locked | crate::state::ChannelStatus::Pending
                )
            })
            .filter_map(|channel| {
                channel
                    .active_request
                    .as_ref()
                    .filter(|request| now > request.expires_at)
                    .map(|_| channel.channel_id.clone())
            })
            .collect();
        for channel_id in expired_channel_ids {
            if let Err(error) =
                crate::handlers::expire_stale_channel_request(&state, &channel_id, now).await
            {
                warn!(
                    %channel_id,
                    error = %error,
                    "Failed to expire stale ASC channel request"
                );
            }
        }

        recover_pending_channel_claims(&state).await;
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
        assert_eq!(chunks[0].entries.len(), 3);
        assert_eq!(chunks[1].start_index, 3);
        assert_eq!(chunks[1].entries.len(), 3);
        assert_eq!(chunks[1].entries[0].settlement_id, "set-3");
    }

    #[test]
    fn build_batch_chunks_avoids_tiny_tail_chunk() {
        let entries: Vec<PreparedSettlement> = (0..5).map(sample_entry).collect();
        let chunks = build_batch_chunks(&entries);

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].entries.len(), 3);
        assert_eq!(chunks[1].entries.len(), 2);
        assert_eq!(chunks[1].start_index, 3);
    }

    #[test]
    fn select_batch_settlement_ids_round_robins_oldest_providers() {
        let selected = select_batch_settlement_ids(
            vec![
                ProviderBatchCursor {
                    provider_id: "provider-b".to_string(),
                    oldest_credit_at: 200,
                    settlement_ids: vec!["b-1".to_string(), "b-2".to_string()],
                    next_index: 0,
                },
                ProviderBatchCursor {
                    provider_id: "provider-a".to_string(),
                    oldest_credit_at: 100,
                    settlement_ids: vec!["a-1".to_string(), "a-2".to_string(), "a-3".to_string()],
                    next_index: 0,
                },
                ProviderBatchCursor {
                    provider_id: "provider-c".to_string(),
                    oldest_credit_at: 200,
                    settlement_ids: vec!["c-1".to_string()],
                    next_index: 0,
                },
            ],
            5,
        );

        assert_eq!(
            selected,
            vec![
                ("provider-a".to_string(), "a-1".to_string()),
                ("provider-b".to_string(), "b-1".to_string()),
                ("provider-c".to_string(), "c-1".to_string()),
                ("provider-a".to_string(), "a-2".to_string()),
                ("provider-b".to_string(), "b-2".to_string()),
            ]
        );
    }

    #[test]
    fn aggregate_settlements_merges_same_provider() {
        let provider = Pubkey::new_unique();
        let mut entry_a = sample_entry(1);
        entry_a.provider_id = "provider-merged".to_string();
        entry_a.settlement.provider_token_account = provider;
        entry_a.audit.provider = provider;

        let mut entry_b = sample_entry(2);
        entry_b.provider_id = "provider-merged".to_string();
        entry_b.settlement.provider_token_account = provider;
        entry_b.audit.provider = provider;

        let aggregated = aggregate_settlements(&[entry_a, entry_b]).unwrap();
        assert_eq!(aggregated.len(), 1);
        assert_eq!(aggregated[0].provider_token_account, provider);
        assert_eq!(aggregated[0].amount, 5);
    }

    #[test]
    fn decide_batch_action_waits_for_jitter_until_deadline() {
        let (decision, jitter_deadline) = decide_batch_action(
            1_000,
            BATCH_WINDOW_SEC as i64,
            MIN_BATCH_PROVIDERS,
            10,
            None,
            17,
        );
        assert_eq!(decision, BatchLoopDecision::Wait);
        assert_eq!(jitter_deadline, Some(1_017));

        let (decision, jitter_deadline) = decide_batch_action(
            1_018,
            BATCH_WINDOW_SEC as i64,
            MIN_BATCH_PROVIDERS,
            10,
            Some(1_017),
            3,
        );
        assert_eq!(decision, BatchLoopDecision::Fire);
        assert_eq!(jitter_deadline, None);
    }

    #[test]
    fn decide_batch_action_bypasses_jitter_at_max_delay() {
        let (decision, jitter_deadline) =
            decide_batch_action(2_000, 1, 1, MAX_SETTLEMENT_DELAY_SEC, Some(9_999), 30);
        assert_eq!(decision, BatchLoopDecision::Fire);
        assert_eq!(jitter_deadline, None);
    }

    #[test]
    fn provider_is_auto_batchable_respects_min_payout_floor() {
        let config = BatchPrivacyConfig {
            auto_batch_min_provider_payout_atomic: 1_000_000,
        };

        assert!(!provider_is_auto_batchable(600_000, 30, config));
        assert!(provider_is_auto_batchable(1_000_000, 30, config));
        assert!(provider_is_auto_batchable(
            600_000,
            MAX_SETTLEMENT_DELAY_SEC,
            config
        ));
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
