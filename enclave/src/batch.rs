use solana_sdk::pubkey::Pubkey;
use std::sync::Arc;
use tokio::time::{self, Duration};
use tracing::{info, warn};

use crate::handlers::AppState;
use crate::state::ReservationStatus;
use crate::wal::WalEntry;

const BATCH_WINDOW_SEC: u64 = 120;
const MAX_SETTLEMENT_DELAY_SEC: i64 = 900;
const MAX_SETTLEMENTS_PER_TX: usize = 20;
const MIN_BATCH_PROVIDERS: usize = 2;
const RESERVATION_TIMEOUT_SEC: i64 = 60;

/// Settlement entry ready for on-chain batch
#[derive(Debug, Clone)]
pub struct BatchSettlementEntry {
    pub provider_token_account: Pubkey,
    pub amount: u64,
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

/// Execute a batch settlement
async fn fire_batch(state: &Arc<AppState>, now: i64) {
    let mut entries: Vec<BatchSettlementEntry> = Vec::new();
    let mut provider_ids: Vec<String> = Vec::new();
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

        // Reset credit
        entry.credited_amount = 0;
        entry.settlement_ids.clear();
        entry.oldest_credit_at = now;
    }

    if entries.is_empty() {
        return;
    }

    // TODO: Phase 1 — Submit on-chain settle_vault transaction
    // For now, log the batch and record in WAL
    let batch_id = now as u64; // Simple batch ID

    info!(
        batch_id,
        provider_count = entries.len(),
        total_amount,
        "Batch settlement ready for on-chain submission"
    );

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
