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

use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_message::{v0::LoadedAddresses, AccountKeys};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

use crate::handlers::AppState;
use crate::outbound::OutboundTransport;
use crate::wal::WalEntry;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    UiTransactionEncoding, UiTransactionStatusMeta,
};

const SIGNATURE_PAGE_LIMIT: usize = 1_000;

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
    /// Outbound transport for Solana RPC calls
    pub outbound: OutboundTransport,
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

#[derive(Debug, Clone)]
pub struct WithdrawEvent {
    pub signature: String,
    pub client: Pubkey,
    pub recipient_ata: Pubkey,
    pub amount: u64,
    pub withdraw_nonce: u64,
    pub expires_at: i64,
    pub slot: u64,
}

#[derive(Debug, Clone)]
pub enum BalanceSyncEvent {
    Deposit(DepositEvent),
    Withdraw(WithdrawEvent),
}

impl DepositDetector {
    pub fn new(
        vault_token_account: Pubkey,
        program_id: Pubkey,
        rpc_url: String,
        ws_url: String,
        outbound: OutboundTransport,
    ) -> Self {
        Self {
            vault_token_account,
            program_id,
            rpc_url,
            ws_url,
            outbound,
            is_synced: Arc::new(AtomicBool::new(false)),
            processed_signatures: Arc::new(RwLock::new(HashSet::new())),
            last_processed_signature: Arc::new(RwLock::new(None)),
        }
    }

    /// Whether the detector has synced and is ready to serve /verify requests.
    pub fn is_ready(&self) -> bool {
        self.is_synced.load(Ordering::SeqCst)
    }

    pub fn is_enabled(&self) -> bool {
        self.vault_token_account != Pubkey::default() && self.program_id != Pubkey::default()
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
        self.processed_signatures.read().await.contains(signature)
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

    if !detector.is_enabled() {
        info!("Deposit detection disabled: vault runtime configuration not provided");
        detector.is_synced.store(true, Ordering::SeqCst);
        return;
    }

    // Initial catch-up: fetch any deposits since last known signature
    match catch_up_deposits(&state, &detector).await {
        Ok(count) => {
            info!(count, "Initial deposit catch-up complete");
            detector.is_synced.store(true, Ordering::SeqCst);
        }
        Err(e) => {
            error!("Initial deposit catch-up failed: {e}");
            detector.is_synced.store(false, Ordering::SeqCst);
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
                detector.is_synced.store(false, Ordering::SeqCst);
            }
        }
    }
}

/// Subscribe to deposit events via WebSocket logsSubscribe.
///
/// In production, this connects to Solana via the egress relay's TLS tunnel.
async fn subscribe_and_process(
    state: &Arc<AppState>,
    detector: &Arc<DepositDetector>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_url = Url::parse(&detector.ws_url)?;
    let request = detector.ws_url.clone().into_client_request()?;
    let stream = detector
        .outbound
        .connect_url(&ws_url)
        .await
        .map_err(std::io::Error::other)?;
    let (mut websocket, _) = client_async(request, stream).await?;
    let subscription_id = subscribe_to_balance_logs(&mut websocket, detector).await?;

    info!(
        ws_url = %detector.ws_url,
        subscription_id,
        "Deposit subscription active"
    );

    while let Some(message) = websocket.next().await {
        match message? {
            Message::Text(text) => {
                if let Some(notification) = parse_logs_notification(&text)? {
                    let applied =
                        process_balance_sync_signature(state, detector, &notification.signature)
                            .await?;
                    if applied {
                        info!(
                            signature = %notification.signature,
                            slot = notification.slot,
                            "Applied balance sync event from WebSocket notification"
                        );
                    }
                }
            }
            Message::Binary(payload) => {
                let text = String::from_utf8(payload)?;
                if let Some(notification) = parse_logs_notification(&text)? {
                    let applied =
                        process_balance_sync_signature(state, detector, &notification.signature)
                            .await?;
                    if applied {
                        info!(
                            signature = %notification.signature,
                            slot = notification.slot,
                            "Applied balance sync event from WebSocket notification"
                        );
                    }
                }
            }
            Message::Ping(payload) => {
                websocket.send(Message::Pong(payload)).await?;
            }
            Message::Close(frame) => {
                warn!(?frame, "Deposit subscription closed by Solana RPC");
                break;
            }
            Message::Pong(_) | Message::Frame(_) => {}
        }
    }

    Ok(())
}

async fn subscribe_to_balance_logs<S>(
    websocket: &mut tokio_tungstenite::WebSocketStream<S>,
    detector: &DepositDetector,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1u64,
        "method": "logsSubscribe",
        "params": [
            {
                "mentions": [detector.vault_token_account.to_string()],
            },
            {
                "commitment": "finalized",
            }
        ],
    });
    websocket.send(Message::text(request.to_string())).await?;

    while let Some(message) = websocket.next().await {
        match message? {
            Message::Text(text) => match parse_logs_subscribe_response(&text)? {
                Some(subscription_id) => return Ok(subscription_id),
                None => continue,
            },
            Message::Binary(payload) => {
                let text = String::from_utf8(payload)?;
                if let Some(subscription_id) = parse_logs_subscribe_response(&text)? {
                    return Ok(subscription_id);
                }
            }
            Message::Ping(payload) => websocket.send(Message::Pong(payload)).await?,
            Message::Close(frame) => {
                return Err(std::io::Error::other(format!(
                    "Solana RPC closed logsSubscribe during handshake: {frame:?}"
                ))
                .into())
            }
            Message::Pong(_) | Message::Frame(_) => {}
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "Solana RPC closed logsSubscribe stream before acknowledging subscription",
    )
    .into())
}

/// Catch-up on deposits missed during a WebSocket disconnection.
///
/// Per design doc §5.6:
///   1. getSignaturesForAddress(vault_token_account, until=last_processed)
///   2. For each signature, getTransaction to parse deposit data
///   3. Skip WAL-recorded deposits
///   4. Apply new deposits to client_balances
async fn catch_up_deposits(
    state: &Arc<AppState>,
    detector: &Arc<DepositDetector>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    info!("Deposit catch-up: checking for missed deposits");
    process_new_deposits(state, detector).await
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

    {
        let _persist_guard = state.persistence_lock.lock().await;

        // Apply to client balance
        state.vault.apply_deposit(deposit.client, deposit.amount);

        // Record in WAL
        if let Err(error) = state
            .wal
            .append(WalEntry::DepositApplied {
                tx_signature: deposit.signature.clone(),
                client: deposit.client.to_string(),
                amount: deposit.amount,
                slot: deposit.slot,
            })
            .await
        {
            let _ = state
                .vault
                .rollback_deposit(&deposit.client, deposit.amount);
            return Err(error.into());
        }

        // Mark as processed
        detector.mark_processed(&deposit.signature).await;

        // Update last processed signature
        *detector.last_processed_signature.write().await = Some(deposit.signature.clone());

        // Update last finalized slot
        state
            .vault
            .last_finalized_slot
            .store(deposit.slot, std::sync::atomic::Ordering::SeqCst);
        crate::handlers::issue_client_receipt_locked(state, deposit.client)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    }

    info!(
        client = %deposit.client,
        amount = deposit.amount,
        signature = %deposit.signature,
        "Deposit applied to client balance"
    );

    Ok(())
}

async fn process_new_deposits(
    state: &Arc<AppState>,
    detector: &Arc<DepositDetector>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let events = fetch_balance_sync_events(detector).await?;
    let mut applied = 0usize;
    for event in events {
        apply_balance_sync_event(state, detector, event).await?;
        applied += 1;
    }
    Ok(applied)
}

async fn process_balance_sync_signature(
    state: &Arc<AppState>,
    detector: &Arc<DepositDetector>,
    signature: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if detector.is_processed(signature).await {
        return Ok(false);
    }

    let Some(event) = fetch_balance_sync_event(detector, signature).await? else {
        return Ok(false);
    };
    apply_balance_sync_event(state, detector, event).await?;
    Ok(true)
}

async fn fetch_balance_sync_events(
    detector: &Arc<DepositDetector>,
) -> Result<Vec<BalanceSyncEvent>, Box<dyn std::error::Error + Send + Sync>> {
    let rpc = balance_sync_rpc_client(detector);
    let until_signature = detector
        .last_processed_signature
        .read()
        .await
        .as_ref()
        .and_then(|signature| Signature::from_str(signature).ok());

    let mut before: Option<Signature> = None;
    let mut signature_infos = Vec::new();

    loop {
        let config = GetConfirmedSignaturesForAddress2Config {
            before,
            until: until_signature,
            limit: Some(SIGNATURE_PAGE_LIMIT),
            commitment: Some(CommitmentConfig::finalized()),
        };
        let page = rpc
            .get_signatures_for_address_with_config(&detector.vault_token_account, config)
            .await?;
        if page.is_empty() {
            break;
        }

        before = page
            .last()
            .and_then(|item| Signature::from_str(&item.signature).ok());
        let page_len = page.len();
        signature_infos.extend(page);

        if page_len < SIGNATURE_PAGE_LIMIT {
            break;
        }
    }

    let mut events = Vec::new();
    for signature_info in signature_infos.into_iter().rev() {
        if let Some(event) =
            fetch_balance_sync_event_with_rpc(&rpc, detector, &signature_info.signature).await?
        {
            events.push(event);
        }
    }

    Ok(events)
}

fn balance_sync_rpc_client(detector: &DepositDetector) -> RpcClient {
    detector
        .outbound
        .solana_rpc_client(detector.rpc_url.clone(), CommitmentConfig::finalized())
}

async fn fetch_balance_sync_event(
    detector: &Arc<DepositDetector>,
    signature: &str,
) -> Result<Option<BalanceSyncEvent>, Box<dyn std::error::Error + Send + Sync>> {
    let rpc = balance_sync_rpc_client(detector);
    fetch_balance_sync_event_with_rpc(&rpc, detector, signature).await
}

async fn fetch_balance_sync_event_with_rpc(
    rpc: &RpcClient,
    detector: &DepositDetector,
    signature: &str,
) -> Result<Option<BalanceSyncEvent>, Box<dyn std::error::Error + Send + Sync>> {
    if detector.is_processed(signature).await {
        return Ok(None);
    }

    let signature = Signature::from_str(signature)?;
    let tx = rpc
        .get_transaction_with_config(
            &signature,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::Base64),
                commitment: Some(CommitmentConfig::finalized()),
                max_supported_transaction_version: Some(0),
            },
        )
        .await?;

    parse_balance_sync_transaction(detector, &tx, &signature.to_string())
}

async fn apply_balance_sync_event(
    state: &Arc<AppState>,
    detector: &Arc<DepositDetector>,
    event: BalanceSyncEvent,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match event {
        BalanceSyncEvent::Deposit(deposit) => apply_deposit(state, detector, deposit).await,
        BalanceSyncEvent::Withdraw(withdrawal) => {
            apply_withdrawal(state, detector, withdrawal).await
        }
    }
}

fn parse_logs_subscribe_response(
    payload: &str,
) -> Result<Option<u64>, Box<dyn std::error::Error + Send + Sync>> {
    let json: serde_json::Value = serde_json::from_str(payload)?;
    if let Some(error) = json.get("error") {
        let code = error
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or_default();
        let message = error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown JSON-RPC error");
        return Err(std::io::Error::other(format!(
            "logsSubscribe failed with RPC error {code}: {message}"
        ))
        .into());
    }

    Ok(json.get("result").and_then(serde_json::Value::as_u64))
}

#[derive(Debug, PartialEq, Eq)]
struct LogsNotification {
    signature: String,
    slot: u64,
}

fn parse_logs_notification(
    payload: &str,
) -> Result<Option<LogsNotification>, Box<dyn std::error::Error + Send + Sync>> {
    let json: serde_json::Value = serde_json::from_str(payload)?;
    if json.get("method").and_then(serde_json::Value::as_str) != Some("logsNotification") {
        return Ok(None);
    }

    let Some(signature) = json
        .pointer("/params/result/value/signature")
        .and_then(serde_json::Value::as_str)
    else {
        return Err(std::io::Error::other("logsNotification missing signature").into());
    };
    let slot = json
        .pointer("/params/result/context/slot")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();

    if json
        .pointer("/params/result/value/err")
        .map(|err| !err.is_null())
        .unwrap_or(false)
    {
        warn!(
            signature,
            slot, "Skipping failed Solana balance sync notification"
        );
        return Ok(None);
    }

    Ok(Some(LogsNotification {
        signature: signature.to_string(),
        slot,
    }))
}

fn parse_balance_sync_transaction(
    detector: &DepositDetector,
    tx: &EncodedConfirmedTransactionWithStatusMeta,
    signature: &str,
) -> Result<Option<BalanceSyncEvent>, Box<dyn std::error::Error + Send + Sync>> {
    if tx
        .transaction
        .meta
        .as_ref()
        .and_then(|meta| meta.err.as_ref())
        .is_some()
    {
        return Ok(None);
    }

    let transaction =
        tx.transaction.transaction.decode().ok_or_else(|| {
            format!("failed to decode transaction for deposit signature {signature}")
        })?;

    let loaded_addresses = tx
        .transaction
        .meta
        .as_ref()
        .and_then(parse_loaded_addresses);
    let account_keys = AccountKeys::new(
        transaction.message.static_account_keys(),
        loaded_addresses.as_ref(),
    );
    let deposit_discriminator = instruction_discriminator("deposit");
    let withdraw_discriminator = instruction_discriminator("withdraw");

    for instruction in transaction.message.instructions() {
        let Some(program_id) = account_keys.get(instruction.program_id_index as usize) else {
            continue;
        };
        if *program_id != detector.program_id {
            continue;
        }

        if instruction.data.len() >= 16
            && instruction.data[..8] == deposit_discriminator
            && instruction.accounts.len() >= 4
        {
            let Some(client) = account_keys.get(instruction.accounts[0] as usize) else {
                continue;
            };
            let Some(vault_token_account) = account_keys.get(instruction.accounts[3] as usize)
            else {
                continue;
            };
            if *vault_token_account != detector.vault_token_account {
                continue;
            }

            let amount = u64::from_le_bytes(instruction.data[8..16].try_into()?);
            return Ok(Some(BalanceSyncEvent::Deposit(DepositEvent {
                signature: signature.to_string(),
                client: *client,
                amount,
                slot: tx.slot,
            })));
        }

        if instruction.data.len() >= 32
            && instruction.data[..8] == withdraw_discriminator
            && instruction.accounts.len() >= 4
        {
            let Some(client) = account_keys.get(instruction.accounts[0] as usize) else {
                continue;
            };
            let Some(vault_token_account) = account_keys.get(instruction.accounts[2] as usize)
            else {
                continue;
            };
            let Some(recipient_ata) = account_keys.get(instruction.accounts[3] as usize) else {
                continue;
            };
            if *vault_token_account != detector.vault_token_account {
                continue;
            }

            let amount = u64::from_le_bytes(instruction.data[8..16].try_into()?);
            let withdraw_nonce = u64::from_le_bytes(instruction.data[16..24].try_into()?);
            let expires_at = i64::from_le_bytes(instruction.data[24..32].try_into()?);
            return Ok(Some(BalanceSyncEvent::Withdraw(WithdrawEvent {
                signature: signature.to_string(),
                client: *client,
                recipient_ata: *recipient_ata,
                amount,
                withdraw_nonce,
                expires_at,
                slot: tx.slot,
            })));
        }
    }

    Ok(None)
}

pub async fn apply_withdrawal(
    state: &Arc<AppState>,
    detector: &Arc<DepositDetector>,
    withdrawal: WithdrawEvent,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if detector.is_processed(&withdrawal.signature).await {
        return Ok(());
    }

    {
        let _persist_guard = state.persistence_lock.lock().await;

        let applied = state
            .vault
            .apply_withdrawal(withdrawal.withdraw_nonce)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if applied.client != withdrawal.client
            || applied.recipient_ata != withdrawal.recipient_ata
            || applied.amount != withdrawal.amount
            || applied.expires_at != withdrawal.expires_at
        {
            return Err(std::io::Error::other(format!(
                "withdraw event mismatch for nonce {}",
                withdrawal.withdraw_nonce
            ))
            .into());
        }

        if let Err(error) = state
            .wal
            .append(WalEntry::WithdrawApplied {
                client: withdrawal.client.to_string(),
                recipient_ata: withdrawal.recipient_ata.to_string(),
                amount: withdrawal.amount,
                withdraw_nonce: withdrawal.withdraw_nonce,
                expires_at: withdrawal.expires_at,
                slot: withdrawal.slot,
                tx_signature: withdrawal.signature.clone(),
            })
            .await
        {
            let _ = state.vault.rollback_applied_withdrawal(applied);
            return Err(error.into());
        }

        detector.mark_processed(&withdrawal.signature).await;
        *detector.last_processed_signature.write().await = Some(withdrawal.signature.clone());
        state
            .vault
            .last_finalized_slot
            .store(withdrawal.slot, std::sync::atomic::Ordering::SeqCst);
        state
            .vault
            .refresh_client_max_lock_expires_at(&withdrawal.client)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        crate::handlers::issue_client_receipt_locked(state, withdrawal.client)
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    }

    info!(
        client = %withdrawal.client,
        amount = withdrawal.amount,
        withdraw_nonce = withdrawal.withdraw_nonce,
        signature = %withdrawal.signature,
        "Withdraw applied to client balance"
    );

    Ok(())
}

fn parse_loaded_addresses(meta: &UiTransactionStatusMeta) -> Option<LoadedAddresses> {
    let loaded = match meta.loaded_addresses.as_ref() {
        OptionSerializer::Some(loaded) => loaded,
        OptionSerializer::None | OptionSerializer::Skip => return None,
    };

    let writable = loaded
        .writable
        .iter()
        .map(|key| Pubkey::from_str(key))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let readonly = loaded
        .readonly
        .iter()
        .map(|key| Pubkey::from_str(key))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;

    Some(LoadedAddresses { writable, readonly })
}

fn instruction_discriminator(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(format!("global:{name}").as_bytes());
    let hash = hasher.finalize();
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
}

#[cfg(test)]
mod tests {
    use super::{parse_logs_notification, parse_logs_subscribe_response, LogsNotification};

    #[test]
    fn parse_logs_subscribe_response_reads_subscription_id() {
        let payload = r#"{"jsonrpc":"2.0","result":42,"id":1}"#;
        let subscription_id = parse_logs_subscribe_response(payload).unwrap();
        assert_eq!(subscription_id, Some(42));
    }

    #[test]
    fn parse_logs_notification_reads_signature_and_slot() {
        let payload = r#"{
            "jsonrpc":"2.0",
            "method":"logsNotification",
            "params":{
                "result":{
                    "context":{"slot":123},
                    "value":{
                        "signature":"5Yd6abc",
                        "err":null,
                        "logs":["Program log: deposit"]
                    }
                },
                "subscription":7
            }
        }"#;
        let notification = parse_logs_notification(payload).unwrap();
        assert_eq!(
            notification,
            Some(LogsNotification {
                signature: "5Yd6abc".to_string(),
                slot: 123,
            })
        );
    }

    #[test]
    fn parse_logs_notification_skips_failed_transactions() {
        let payload = r#"{
            "jsonrpc":"2.0",
            "method":"logsNotification",
            "params":{
                "result":{
                    "context":{"slot":123},
                    "value":{
                        "signature":"5Yd6abc",
                        "err":{"InstructionError":[0,"Custom"]},
                        "logs":["Program log: failed"]
                    }
                },
                "subscription":7
            }
        }"#;
        let notification = parse_logs_notification(payload).unwrap();
        assert_eq!(notification, None);
    }
}
