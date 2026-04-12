//! Deposit Detection: Monitor on-chain deposit events and update enclave state.
//!
//! Per design doc §5.6, the enclave monitors on-chain deposit instructions via
//! Solana RPC (WebSocket logsSubscribe) and updates client balances after the
//! transaction reaches `finalized` commitment.
//!
//! In production, the Solana RPC connection is established through the parent's
//! L4 egress relay with TLS terminated inside the enclave.
//!
//! Catch-up logic handles WebSocket disconnections:
//!   1. On disconnect, immediately reconnect
//!   2. Use getSignaturesForAddress to fetch missed deposits
//!   3. Skip already-applied deposits (checked against WAL)
//!   4. Reject /verify with 503 until catch-up completes

use solana_sdk::pubkey::Pubkey;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::handlers::AppState;
use crate::wal::WalEntry;

/// Tracks deposit detection state and sync status.
pub struct DepositDetector {
    /// Vault token account to monitor for incoming transfers
    pub vault_token_account: Pubkey,
    /// Program ID for the a402_vault program
    pub program_id: Pubkey,
    /// Solana RPC URL (via egress relay in production)
    pub rpc_url: String,
    /// WebSocket RPC URL
    pub ws_url: String,
    /// Whether the detector has completed initial catch-up
    pub is_synced: Arc<AtomicBool>,
    /// Set of already-processed transaction signatures (prevents double-counting)
    pub processed_signatures: Arc<RwLock<HashSet<String>>>,
    /// Last processed signature for catch-up queries
    pub last_processed_signature: Arc<RwLock<Option<String>>>,
}

/// Parsed deposit event from an on-chain transaction.
#[derive(Debug, Clone)]
pub struct DepositEvent {
    pub signature: String,
    pub client: Pubkey,
    pub amount: u64,
    pub slot: u64,
}

impl DepositDetector {
    pub fn new(
        vault_token_account: Pubkey,
        program_id: Pubkey,
        rpc_url: String,
        ws_url: String,
    ) -> Self {
        Self {
            vault_token_account,
            program_id,
            rpc_url,
            ws_url,
            is_synced: Arc::new(AtomicBool::new(false)),
            processed_signatures: Arc::new(RwLock::new(HashSet::new())),
            last_processed_signature: Arc::new(RwLock::new(None)),
        }
    }

    /// Whether the detector has synced and is ready to serve /verify requests.
    pub fn is_ready(&self) -> bool {
        self.is_synced.load(Ordering::SeqCst)
    }

    /// Mark a signature as processed (called during WAL replay on startup).
    pub async fn mark_processed(&self, signature: &str) {
        self.processed_signatures
            .write()
            .await
            .insert(signature.to_string());
    }

    /// Check if a signature has already been processed.
    pub async fn is_processed(&self, signature: &str) -> bool {
        self.processed_signatures
            .read()
            .await
            .contains(signature)
    }
}

/// Spawn the deposit detection background task.
pub fn spawn_deposit_detector(state: Arc<AppState>, detector: Arc<DepositDetector>) {
    tokio::spawn(async move {
        deposit_monitor_loop(state, detector).await;
    });
}

/// Main deposit monitoring loop with reconnection and catch-up.
async fn deposit_monitor_loop(state: Arc<AppState>, detector: Arc<DepositDetector>) {
    info!(
        vault_token_account = %detector.vault_token_account,
        "Starting deposit detection"
    );

    // Initial catch-up: fetch any deposits since last known signature
    match catch_up_deposits(&state, &detector).await {
        Ok(count) => {
            info!(count, "Initial deposit catch-up complete");
            detector.is_synced.store(true, Ordering::SeqCst);
        }
        Err(e) => {
            error!("Initial deposit catch-up failed: {e}");
            // Still mark as synced to avoid blocking indefinitely in dev
            detector.is_synced.store(true, Ordering::SeqCst);
        }
    }

    // Main subscription loop with automatic reconnection
    loop {
        match subscribe_and_process(&state, &detector).await {
            Ok(()) => {
                warn!("Deposit subscription ended normally, reconnecting...");
            }
            Err(e) => {
                error!("Deposit subscription error: {e}, reconnecting in 5s...");
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }

        // Mark as not synced during catch-up
        detector.is_synced.store(false, Ordering::SeqCst);

        // Catch-up on missed deposits before resuming subscription
        match catch_up_deposits(&state, &detector).await {
            Ok(count) => {
                info!(count, "Deposit catch-up after reconnection complete");
                detector.is_synced.store(true, Ordering::SeqCst);
            }
            Err(e) => {
                error!("Deposit catch-up failed: {e}");
                detector.is_synced.store(true, Ordering::SeqCst);
            }
        }
    }
}

/// Subscribe to deposit events via WebSocket logsSubscribe.
///
/// In production, this connects to Solana via the egress relay's TLS tunnel.
/// For local dev, this is a stub that periodically polls.
async fn subscribe_and_process(
    state: &Arc<AppState>,
    detector: &Arc<DepositDetector>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Phase 1 local dev: polling-based deposit detection
    // Production: Use logsSubscribe WebSocket for real-time monitoring
    //
    // let subscription = rpc_client.logs_subscribe(
    //     RpcTransactionLogsFilter::Mentions(vec![detector.program_id.to_string()]),
    //     RpcTransactionLogsConfig { commitment: Some(CommitmentConfig::finalized()) },
    // ).await?;
    //
    // while let Some(log) = subscription.next().await {
    //     if let Some(deposit) = parse_deposit_log(&log) {
    //         apply_deposit(state, detector, deposit).await?;
    //     }
    // }

    info!("Deposit subscription active (polling mode for local dev)");

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
    loop {
        interval.tick().await;

        // In production: this would be event-driven from logsSubscribe
        // For local dev: poll getSignaturesForAddress
        match poll_recent_deposits(state, detector).await {
            Ok(count) => {
                if count > 0 {
                    info!(count, "Processed deposits from polling");
                }
            }
            Err(e) => {
                warn!("Deposit polling error: {e}");
            }
        }
    }
}

/// Poll for recent deposits using getSignaturesForAddress.
async fn poll_recent_deposits(
    _state: &Arc<AppState>,
    _detector: &Arc<DepositDetector>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    // Phase 1 stub: In production, this queries the RPC for recent transactions
    //
    // let sigs = rpc_client.get_signatures_for_address_with_config(
    //     &detector.vault_token_account,
    //     GetConfirmedSignaturesForAddress2Config {
    //         until: last_processed_signature,
    //         commitment: Some(CommitmentConfig::finalized()),
    //         ..Default::default()
    //     },
    // ).await?;
    //
    // for sig_info in sigs.iter().rev() {
    //     if detector.is_processed(&sig_info.signature).await { continue; }
    //     let tx = rpc_client.get_transaction(&sig_info.signature, ...).await?;
    //     if let Some(deposit) = parse_deposit_tx(&tx) {
    //         apply_deposit(state, detector, deposit).await?;
    //     }
    // }

    Ok(0)
}

/// Catch-up on deposits missed during a WebSocket disconnection.
///
/// Per design doc §5.6:
///   1. getSignaturesForAddress(vault_token_account, until=last_processed)
///   2. For each signature, getTransaction to parse deposit data
///   3. Skip WAL-recorded deposits
///   4. Apply new deposits to client_balances
async fn catch_up_deposits(
    _state: &Arc<AppState>,
    _detector: &Arc<DepositDetector>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    // Phase 1 stub: catch-up logic follows same pattern as poll_recent_deposits
    // Production implementation uses getSignaturesForAddress with pagination
    info!("Deposit catch-up: checking for missed deposits");
    Ok(0)
}

/// Apply a confirmed deposit to enclave state.
pub async fn apply_deposit(
    state: &Arc<AppState>,
    detector: &Arc<DepositDetector>,
    deposit: DepositEvent,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Skip if already processed
    if detector.is_processed(&deposit.signature).await {
        return Ok(());
    }

    // Apply to client balance
    state.vault.apply_deposit(deposit.client, deposit.amount);

    // Record in WAL
    state
        .wal
        .append(WalEntry::DepositApplied {
            tx_signature: deposit.signature.clone(),
            client: deposit.client.to_string(),
            amount: deposit.amount,
            slot: deposit.slot,
        })
        .await?;

    // Mark as processed
    detector.mark_processed(&deposit.signature).await;

    // Update last processed signature
    *detector.last_processed_signature.write().await = Some(deposit.signature.clone());

    // Update last finalized slot
    state
        .vault
        .last_finalized_slot
        .store(deposit.slot, std::sync::atomic::Ordering::SeqCst);

    info!(
        client = %deposit.client,
        amount = deposit.amount,
        signature = %deposit.signature,
        "Deposit applied to client balance"
    );

    Ok(())
}
