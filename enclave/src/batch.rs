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
use subly402_vault::accounts::{RecordAudit, SettleVault};
use subly402_vault::asc_claim::hash_identifier;
use subly402_vault::instruction::{RecordAudit as RecordAuditIx, SettleVault as SettleVaultIx};
use subly402_vault::instructions::record_audit::AuditRecordData;
use subly402_vault::instructions::settle_vault::SettlementEntry;
use subly402_vault::state::AscCloseClaim as OnChainAscCloseClaim;
use tokio::{
    task,
    time::{self, Duration},
};
use tracing::{info, warn};

use crate::audit;
use crate::handlers::AppState;
use crate::state::{PendingWithdrawal, ReservationStatus, SettlementRecord};
use crate::wal::WalEntry;

const BATCH_WINDOW_SEC: u64 = 120;
const MAX_SETTLEMENT_DELAY_SEC: i64 = 900;
const MAX_SETTLEMENTS_PER_TX: usize = 20;
/// Max audit records per atomic settle/audit transaction.
///
/// Solana transactions are capped at 1232 raw bytes. The paired
/// settle_vault + record_audit transaction carries encrypted audit payloads,
/// settlement accounts, audit PDAs, and the instructions sysvar, so larger
/// chunks exceed the runtime limit before compute becomes the bottleneck.
const MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT: usize = 2;
const MAX_BATCH_JITTER_SEC: i64 = 30;
/// Max age (seconds) for orphaned settlement_history entries before cleanup
const SETTLEMENT_HISTORY_MAX_AGE_SEC: i64 = 1800;
const DEFAULT_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC: u64 = 1_000_000;
/// Minimum age (seconds) for an individual settlement before it is eligible
/// for an automatic batch. Guarantees every settlement was held in the vault
/// for at least this long, so on-chain observers cannot trivially correlate a
/// fresh deposit/reservation with an immediate payout to a provider.
const DEFAULT_MIN_ANONYMITY_WINDOW_SEC: i64 = 60;
/// Default minimum number of distinct providers in a batch. `1` means the
/// time-based anonymity window is the sole anonymity knob; operators who want
/// to additionally require N-way mixing can raise this via env.
const DEFAULT_MIN_BATCH_PROVIDERS: usize = 1;

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
    /// Minimum age (seconds) for an individual settlement before it is
    /// eligible for an automatic batch. Guarantees a minimum anonymity window
    /// for every settlement, independent of batch cadence. Set to 0 to
    /// disable (not recommended for public deployments).
    pub min_anonymity_window_sec: i64,
    /// Minimum distinct providers required in an automatic batch. `1`
    /// effectively disables the N-way mixing gate and relies solely on the
    /// time-based anonymity window. Raise this when volume supports it to
    /// enforce k-anonymity in addition to the time window.
    pub min_batch_providers: usize,
}

impl Default for BatchPrivacyConfig {
    fn default() -> Self {
        Self {
            auto_batch_min_provider_payout_atomic: DEFAULT_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC,
            min_anonymity_window_sec: DEFAULT_MIN_ANONYMITY_WINDOW_SEC,
            min_batch_providers: DEFAULT_MIN_BATCH_PROVIDERS,
        }
    }
}

impl BatchPrivacyConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(value) = std::env::var("SUBLY402_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC") {
            config.auto_batch_min_provider_payout_atomic = value.parse().unwrap_or_else(|_| {
                panic!("SUBLY402_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC must be a valid u64")
            });
        }
        if let Ok(value) = std::env::var("SUBLY402_MIN_ANONYMITY_WINDOW_SEC") {
            config.min_anonymity_window_sec =
                parse_nonnegative_i64_env("SUBLY402_MIN_ANONYMITY_WINDOW_SEC", &value);
        }
        if let Ok(value) = std::env::var("SUBLY402_MIN_BATCH_PROVIDERS") {
            let parsed: usize = value
                .parse()
                .unwrap_or_else(|_| panic!("SUBLY402_MIN_BATCH_PROVIDERS must be a valid usize"));
            config.min_batch_providers = parsed.max(1);
        }
        config
    }
}

fn parse_nonnegative_i64_env(name: &str, value: &str) -> i64 {
    let parsed = value
        .parse::<i64>()
        .unwrap_or_else(|_| panic!("{name} must be a valid non-negative i64"));
    if parsed < 0 {
        panic!("{name} must be a valid non-negative i64");
    }
    parsed
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
        let cursors =
            build_provider_batch_cursors(&state, now, BatchBuildMode::Auto, batch_privacy);
        let provider_count = cursors.len();
        let oldest_credit_age = cursors
            .iter()
            .map(|cursor| now - cursor.oldest_credit_at)
            .max()
            .unwrap_or(0);

        let sampled_jitter_sec = rand::thread_rng().gen_range(0..=MAX_BATCH_JITTER_SEC);
        let (decision, next_deadline) = decide_batch_action(
            now,
            elapsed,
            provider_count,
            oldest_credit_age,
            jitter_deadline,
            sampled_jitter_sec,
            batch_privacy.min_batch_providers,
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
    let cursors = build_provider_batch_cursors(state, batch_timestamp, mode, batch_privacy);

    let mut prepared: Vec<PreparedSettlement> = Vec::new();
    for (provider_id, sid) in select_batch_settlement_ids(cursors, MAX_SETTLEMENTS_PER_TX) {
        let Some(record) = state
            .vault
            .settlement_history
            .get(&sid)
            .map(|rec| rec.clone())
        else {
            warn!(
                settlement_id = %sid,
                provider_id = %provider_id,
                "Settlement history entry disappeared between filter and selection"
            );
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

/// Build per-provider cursors with the exact set of settlements that are
/// eligible for the current batch. This is shared by the batch loop and the
/// batch builder so the "should we fire?" decision sees the same filtered
/// subset that `prepare_batch()` will actually submit.
fn build_provider_batch_cursors(
    state: &Arc<AppState>,
    batch_timestamp: i64,
    mode: BatchBuildMode,
    batch_privacy: BatchPrivacyConfig,
) -> Vec<ProviderBatchCursor> {
    let provider_snapshots: Vec<(String, Vec<String>)> = state
        .vault
        .provider_credits
        .iter()
        .map(|entry| (entry.provider_id.clone(), entry.settlement_ids.clone()))
        .collect();

    let mut cursors: Vec<ProviderBatchCursor> = Vec::new();
    let mut missing: Vec<(String, String)> = Vec::new();
    for (provider_id, settlement_ids) in provider_snapshots {
        let mut timestamped: Vec<(String, i64, u64)> = Vec::with_capacity(settlement_ids.len());
        for sid in settlement_ids {
            let record_opt = state
                .vault
                .settlement_history
                .get(&sid)
                .map(|rec| rec.clone())
                .or_else(|| {
                    let rec = reconstruct_settlement_record(state, &provider_id, &sid)?;
                    warn!(
                        settlement_id = %sid,
                        provider_id = %provider_id,
                        "Reconstructed missing settlement_history entry from reservation state"
                    );
                    state
                        .vault
                        .settlement_history
                        .insert(sid.clone(), rec.clone());
                    Some(rec)
                });

            match record_opt {
                Some(record) => timestamped.push((sid, record.timestamp, record.amount)),
                None => missing.push((provider_id.clone(), sid)),
            }
        }

        let Some(selection) =
            select_provider_batch_entries(&timestamped, batch_timestamp, mode, batch_privacy)
        else {
            continue;
        };

        cursors.push(ProviderBatchCursor {
            provider_id,
            oldest_credit_at: selection.oldest_timestamp,
            settlement_ids: selection.settlement_ids,
            next_index: 0,
        });
    }

    for (provider_id, sid) in missing {
        warn!(
            settlement_id = %sid,
            provider_id = %provider_id,
            "Pruning provider credit with missing settlement_history and reservation state"
        );
        prune_missing_settlement_reference(state, &provider_id, &sid);
    }

    cursors
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
    min_batch_providers: usize,
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
    if provider_count < min_batch_providers && !deadline_reached {
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

/// Result of filtering a provider's settlement_ids down to the age-eligible
/// subset. `None` means this provider contributes nothing to the current batch.
struct ProviderBatchSelection {
    settlement_ids: Vec<String>,
    oldest_timestamp: i64,
}

/// Per-provider filter. Takes the full list of candidate
/// `(settlement_id, timestamp, amount)` for a provider and returns the subset
/// that satisfies the anonymity window and payout-floor rules. Pure so it can
/// be unit-tested without spinning up AppState.
fn select_provider_batch_entries(
    candidates: &[(String, i64, u64)],
    batch_timestamp: i64,
    mode: BatchBuildMode,
    config: BatchPrivacyConfig,
) -> Option<ProviderBatchSelection> {
    let mut eligible_ids: Vec<String> = Vec::new();
    let mut eligible_amount: u64 = 0;
    let mut eligible_oldest_timestamp: Option<i64> = None;

    for (sid, timestamp, amount) in candidates {
        let age = batch_timestamp - timestamp;
        let is_eligible = match mode {
            BatchBuildMode::Flush => true,
            BatchBuildMode::Auto => settlement_is_age_eligible(age, config),
        };
        if !is_eligible {
            continue;
        }

        eligible_amount = eligible_amount.saturating_add(*amount);
        eligible_oldest_timestamp = Some(
            eligible_oldest_timestamp
                .map(|current: i64| current.min(*timestamp))
                .unwrap_or(*timestamp),
        );
        eligible_ids.push(sid.clone());
    }

    if eligible_ids.is_empty() {
        return None;
    }

    let oldest_timestamp = eligible_oldest_timestamp.unwrap_or(batch_timestamp);
    let eligible_oldest_age = batch_timestamp - oldest_timestamp;

    if matches!(mode, BatchBuildMode::Auto)
        && !provider_payout_floor_satisfied(eligible_amount, eligible_oldest_age, config)
    {
        return None;
    }

    Some(ProviderBatchSelection {
        settlement_ids: eligible_ids,
        oldest_timestamp,
    })
}

/// Per-settlement eligibility. A settlement must have aged at least
/// `min_anonymity_window_sec` before it can be included in an automatic batch,
/// unless `MAX_SETTLEMENT_DELAY_SEC` liveness ceiling has been reached.
fn settlement_is_age_eligible(age: i64, config: BatchPrivacyConfig) -> bool {
    if age >= MAX_SETTLEMENT_DELAY_SEC {
        return true;
    }
    age >= config.min_anonymity_window_sec
}

/// Provider-level payout floor. Applied to the *eligible* subset (settlements
/// that have already cleared the anonymity window), so that a provider whose
/// eligible aggregate is below the configured minimum payout defers the batch.
/// The `MAX_SETTLEMENT_DELAY_SEC` liveness ceiling still forces a fire.
fn provider_payout_floor_satisfied(
    eligible_amount: u64,
    eligible_oldest_age: i64,
    config: BatchPrivacyConfig,
) -> bool {
    if eligible_amount == 0 {
        return false;
    }
    if eligible_oldest_age >= MAX_SETTLEMENT_DELAY_SEC {
        return true;
    }
    config.auto_batch_min_provider_payout_atomic == 0
        || eligible_amount >= config.auto_batch_min_provider_payout_atomic
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

    let program_id = state.vault.solana.program_id;
    let rpc_url = state.vault.solana.rpc_url.clone();
    let ws_url = state.vault.solana.ws_url.clone();
    let vault_signer_pubkey = state.vault.vault_signer_pubkey;
    let vault_config = state.vault.vault_config;
    let vault_token_account = state.vault.solana.vault_token_account;

    let instructions = task::spawn_blocking(move || {
        let program_payer = Rc::new(Keypair::new_from_array(signer_bytes));
        let client = Client::new_with_options(
            Cluster::Custom(rpc_url, ws_url),
            program_payer,
            CommitmentConfig::confirmed(),
        );
        let program = client
            .program(program_id)
            .map_err(|error| format!("failed to create Anchor program client: {error}"))?;

        let settle_ix = program
            .request()
            .accounts(SettleVault {
                vault_signer: vault_signer_pubkey,
                vault_config,
                vault_token_account,
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
                vault_signer: vault_signer_pubkey,
                vault_config,
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
        Ok::<_, String>(instructions)
    })
    .await
    .map_err(|error| format!("failed to join atomic chunk instruction builder: {error}"))??;

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
    hasher.update(b"subly402-batch-chunk-v1");
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
        // These can accumulate when batches don't fire (e.g., credits younger than min_anonymity_window_sec).
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

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].start_index, 0);
        assert_eq!(chunks[0].entries.len(), 2);
        assert_eq!(chunks[1].start_index, 2);
        assert_eq!(chunks[1].entries.len(), 2);
        assert_eq!(chunks[2].start_index, 4);
        assert_eq!(chunks[2].entries.len(), 2);
        assert_eq!(chunks[2].entries[0].settlement_id, "set-4");
    }

    #[test]
    fn build_batch_chunks_caps_atomic_transaction_size() {
        let entries: Vec<PreparedSettlement> = (0..5).map(sample_entry).collect();
        let chunks = build_batch_chunks(&entries);

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].entries.len(), 2);
        assert_eq!(chunks[1].entries.len(), 2);
        assert_eq!(chunks[2].entries.len(), 1);
        assert!(chunks
            .iter()
            .all(|chunk| chunk.entries.len() <= MAX_ATOMIC_SETTLEMENTS_WITH_AUDIT));
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
        let (decision, jitter_deadline) =
            decide_batch_action(1_000, BATCH_WINDOW_SEC as i64, 2, 10, None, 17, 2);
        assert_eq!(decision, BatchLoopDecision::Wait);
        assert_eq!(jitter_deadline, Some(1_017));

        let (decision, jitter_deadline) =
            decide_batch_action(1_018, BATCH_WINDOW_SEC as i64, 2, 10, Some(1_017), 3, 2);
        assert_eq!(decision, BatchLoopDecision::Fire);
        assert_eq!(jitter_deadline, None);
    }

    #[test]
    fn decide_batch_action_bypasses_jitter_at_max_delay() {
        let (decision, jitter_deadline) =
            decide_batch_action(2_000, 1, 1, MAX_SETTLEMENT_DELAY_SEC, Some(9_999), 30, 2);
        assert_eq!(decision, BatchLoopDecision::Fire);
        assert_eq!(jitter_deadline, None);
    }

    #[test]
    fn decide_batch_action_single_provider_fires_when_min_is_one() {
        // With default min_batch_providers = 1, one provider should be enough
        // to fire the batch as long as the time window has elapsed.
        let (decision, _) = decide_batch_action(
            1_000,
            BATCH_WINDOW_SEC as i64,
            1,
            BATCH_WINDOW_SEC as i64,
            None,
            0,
            1,
        );
        assert!(matches!(
            decision,
            BatchLoopDecision::Fire | BatchLoopDecision::Wait
        ));
    }

    #[test]
    fn decide_batch_action_single_provider_skipped_with_n_gate() {
        // With min_batch_providers = 2, a single provider is deferred until
        // MAX_SETTLEMENT_DELAY_SEC regardless of BATCH_WINDOW_SEC elapsing.
        let (decision, _) = decide_batch_action(
            1_000,
            BATCH_WINDOW_SEC as i64,
            1,
            BATCH_WINDOW_SEC as i64,
            None,
            0,
            2,
        );
        assert_eq!(decision, BatchLoopDecision::Skip);
    }

    #[test]
    fn settlement_is_age_eligible_respects_window_and_liveness_ceiling() {
        let config = BatchPrivacyConfig {
            auto_batch_min_provider_payout_atomic: 0,
            min_anonymity_window_sec: 60,
            min_batch_providers: 1,
        };

        // Too fresh — the settlement must keep aging.
        assert!(!settlement_is_age_eligible(0, config));
        assert!(!settlement_is_age_eligible(59, config));
        // Exactly at the window — eligible.
        assert!(settlement_is_age_eligible(60, config));
        // Well past the window.
        assert!(settlement_is_age_eligible(120, config));
        // Liveness ceiling — must fire even if anonymity window requires more.
        let tight = BatchPrivacyConfig {
            min_anonymity_window_sec: 10_000,
            ..config
        };
        assert!(!settlement_is_age_eligible(
            MAX_SETTLEMENT_DELAY_SEC - 1,
            tight
        ));
        assert!(settlement_is_age_eligible(MAX_SETTLEMENT_DELAY_SEC, tight));
    }

    #[test]
    fn provider_payout_floor_respects_eligible_amount_only() {
        let config = BatchPrivacyConfig {
            auto_batch_min_provider_payout_atomic: 1_000_000,
            min_anonymity_window_sec: 60,
            min_batch_providers: 1,
        };

        // Eligible amount below floor and no liveness pressure — wait.
        assert!(!provider_payout_floor_satisfied(600_000, 120, config));
        // Eligible amount at floor — fire.
        assert!(provider_payout_floor_satisfied(1_000_000, 120, config));
        // Below floor but liveness ceiling reached — fire.
        assert!(provider_payout_floor_satisfied(
            600_000,
            MAX_SETTLEMENT_DELAY_SEC,
            config
        ));
        // Zero eligible amount is never batchable (prevents empty cursors).
        assert!(!provider_payout_floor_satisfied(
            0,
            MAX_SETTLEMENT_DELAY_SEC,
            config
        ));
    }

    #[test]
    fn select_provider_batch_entries_filters_fresh_credits() {
        // Provider with one aged credit (t=0, age 120s) and one fresh credit
        // (t=115, age 5s) at batch_timestamp=120. With a 60s anonymity window,
        // only the aged credit should go on-chain; the fresh one keeps aging.
        let config = BatchPrivacyConfig {
            auto_batch_min_provider_payout_atomic: 0,
            min_anonymity_window_sec: 60,
            min_batch_providers: 1,
        };
        let candidates = vec![
            ("old".to_string(), 0i64, 1_000_000u64),
            ("fresh".to_string(), 115i64, 2_000_000u64),
        ];

        let selection =
            select_provider_batch_entries(&candidates, 120, BatchBuildMode::Auto, config)
                .expect("old credit should make the provider eligible");
        assert_eq!(selection.settlement_ids, vec!["old".to_string()]);
        assert_eq!(selection.oldest_timestamp, 0);
    }

    #[test]
    fn select_provider_batch_entries_skips_when_only_fresh() {
        // A provider whose every credit is younger than the anonymity window
        // must defer the whole payout rather than leaking the fresh settlement.
        let config = BatchPrivacyConfig {
            auto_batch_min_provider_payout_atomic: 0,
            min_anonymity_window_sec: 60,
            min_batch_providers: 1,
        };
        let candidates = vec![
            ("fresh-a".to_string(), 115i64, 500_000u64),
            ("fresh-b".to_string(), 118i64, 500_000u64),
        ];

        assert!(
            select_provider_batch_entries(&candidates, 120, BatchBuildMode::Auto, config).is_none()
        );
    }

    #[test]
    fn select_provider_batch_entries_payout_floor_uses_eligible_amount() {
        // Aged credit is only $0.30 — below the $1.00 payout floor. Fresh
        // credit would push the raw total above the floor but must not count.
        let config = BatchPrivacyConfig {
            auto_batch_min_provider_payout_atomic: 1_000_000,
            min_anonymity_window_sec: 60,
            min_batch_providers: 1,
        };
        let candidates = vec![
            ("old".to_string(), 0i64, 300_000u64),
            ("fresh".to_string(), 110i64, 800_000u64),
        ];

        assert!(
            select_provider_batch_entries(&candidates, 120, BatchBuildMode::Auto, config).is_none()
        );
    }

    #[test]
    fn select_provider_batch_entries_liveness_ceiling_includes_fresh_siblings() {
        // Once the oldest eligible credit passes MAX_SETTLEMENT_DELAY_SEC, the
        // payout-floor gate is bypassed so the provider always gets paid.
        // Fresh sibling credits are still excluded by the anonymity window.
        let config = BatchPrivacyConfig {
            auto_batch_min_provider_payout_atomic: 1_000_000,
            min_anonymity_window_sec: 60,
            min_batch_providers: 1,
        };
        let batch_ts = MAX_SETTLEMENT_DELAY_SEC;
        let candidates = vec![
            ("very-old".to_string(), 0i64, 100_000u64),
            ("fresh".to_string(), batch_ts - 10, 900_000u64),
        ];

        let selection =
            select_provider_batch_entries(&candidates, batch_ts, BatchBuildMode::Auto, config)
                .expect("liveness ceiling should force the old credit out");
        assert_eq!(selection.settlement_ids, vec!["very-old".to_string()]);
    }

    #[test]
    fn select_provider_batch_entries_flush_mode_ignores_window() {
        // `BatchBuildMode::Flush` is used by the admin /fire-batch path and
        // must bypass anonymity gating so the operator can force a settlement.
        let config = BatchPrivacyConfig::default();
        let candidates = vec![("fresh".to_string(), 119i64, 500_000u64)];

        let selection =
            select_provider_batch_entries(&candidates, 120, BatchBuildMode::Flush, config)
                .expect("flush mode must pick up fresh credits");
        assert_eq!(selection.settlement_ids, vec!["fresh".to_string()]);
    }

    #[test]
    fn batch_privacy_config_defaults_match_public_launch_posture() {
        let config = BatchPrivacyConfig::default();
        assert_eq!(config.min_anonymity_window_sec, 60);
        assert_eq!(config.min_batch_providers, 1);
        assert_eq!(
            config.auto_batch_min_provider_payout_atomic,
            DEFAULT_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC
        );
    }

    #[test]
    fn parse_nonnegative_i64_env_accepts_zero_and_positive_values() {
        assert_eq!(parse_nonnegative_i64_env("TEST_ENV", "0"), 0);
        assert_eq!(parse_nonnegative_i64_env("TEST_ENV", "60"), 60);
    }

    #[test]
    fn parse_nonnegative_i64_env_rejects_negative_values() {
        let result = std::panic::catch_unwind(|| parse_nonnegative_i64_env("TEST_ENV", "-1"));
        assert!(result.is_err());
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
