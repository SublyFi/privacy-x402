//! A402 Receipt Watchtower
//!
//! Per design doc §4.5: Stores latest ParticipantReceipts per participant and
//! automatically challenges stale receipts during force_settle disputes.
//!
//! Components:
//!   - receipt_store: In-memory + file-backed latest receipt store
//!   - challenger: Monitors on-chain ForceSettleRequest PDAs, submits challenges
//!   - HTTP API: Receives receipt updates from enclave, provides status

mod challenger;
mod receipt_store;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Keypair;
use std::env;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tracing::info;

use challenger::ChallengerConfig;
use receipt_store::{ReceiptKey, ReceiptStore, StoredReceipt};

struct AppState {
    receipt_store: Arc<ReceiptStore>,
    vault_config: Pubkey,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let vault_config = env::var("A402_VAULT_CONFIG")
        .ok()
        .and_then(|v| Pubkey::from_str(&v).ok())
        .unwrap_or_default();

    let program_id = env::var("A402_PROGRAM_ID")
        .ok()
        .and_then(|v| Pubkey::from_str(&v).ok())
        .unwrap_or_else(|| a402_vault::ID);

    let rpc_url =
        env::var("A402_SOLANA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());

    let listen_addr =
        env::var("A402_WATCHTOWER_LISTEN").unwrap_or_else(|_| "0.0.0.0:3200".to_string());

    let store_path = env::var("A402_WATCHTOWER_STORE_PATH")
        .unwrap_or_else(|_| "data/watchtower_receipts.json".to_string());

    let poll_interval: u64 = env::var("A402_WATCHTOWER_POLL_SEC")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    let receipt_store = Arc::new(ReceiptStore::new(PathBuf::from(store_path)).await);

    // Load challenger keypair (the watchtower needs a funded keypair to submit txs)
    let challenger_keypair = load_challenger_keypair();

    // Spawn challenger monitoring loop
    let challenger_config = ChallengerConfig {
        program_id,
        rpc_url: rpc_url.clone(),
        poll_interval_sec: poll_interval,
    };
    challenger::spawn_challenger(
        challenger_config,
        receipt_store.clone(),
        Arc::new(challenger_keypair),
    );

    let app_state = Arc::new(AppState {
        receipt_store: receipt_store.clone(),
        vault_config,
    });

    let app = Router::new()
        .route("/v1/receipt/store", post(post_store_receipt))
        .route("/v1/status", get(get_status))
        .with_state(app_state);

    info!(
        addr = %listen_addr,
        vault_config = %vault_config,
        program_id = %program_id,
        "Watchtower starting"
    );

    let listener = tokio::net::TcpListener::bind(&listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ── API Handlers ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoreReceiptRequest {
    pub participant: String,
    pub participant_kind: u8,
    pub recipient_ata: String,
    pub free_balance: u64,
    pub locked_balance: u64,
    pub max_lock_expires_at: i64,
    pub nonce: u64,
    pub timestamp: i64,
    pub snapshot_seqno: u64,
    pub vault_config: String,
    pub signature: String,
    pub message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StoreReceiptResponse {
    pub ok: bool,
    pub stored: bool,
    pub current_nonce: u64,
}

async fn post_store_receipt(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StoreReceiptRequest>,
) -> Json<StoreReceiptResponse> {
    let participant = Pubkey::from_str(&req.participant).unwrap_or_default();
    let vault = Pubkey::from_str(&req.vault_config).unwrap_or(state.vault_config);

    let key = ReceiptKey {
        vault,
        participant,
        participant_kind: req.participant_kind,
    };

    let receipt = StoredReceipt {
        participant: req.participant,
        participant_kind: req.participant_kind,
        recipient_ata: req.recipient_ata,
        free_balance: req.free_balance,
        locked_balance: req.locked_balance,
        max_lock_expires_at: req.max_lock_expires_at,
        nonce: req.nonce,
        timestamp: req.timestamp,
        snapshot_seqno: req.snapshot_seqno,
        vault_config: req.vault_config,
        signature: req.signature,
        message: req.message,
    };

    let stored = state.receipt_store.store_receipt(&key, receipt);
    let current_nonce = state.receipt_store.get_nonce(&key);

    // Persist to disk after each store
    if stored {
        state.receipt_store.persist().await;
    }

    Json(StoreReceiptResponse {
        ok: true,
        stored,
        current_nonce,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    pub ok: bool,
    pub receipt_count: usize,
    pub vault_config: String,
}

async fn get_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        ok: true,
        receipt_count: state.receipt_store.all_receipts().len(),
        vault_config: state.vault_config.to_string(),
    })
}

fn load_challenger_keypair() -> Keypair {
    if let Ok(encoded) = env::var("A402_WATCHTOWER_KEYPAIR_B64") {
        let bytes = BASE64
            .decode(encoded)
            .expect("A402_WATCHTOWER_KEYPAIR_B64 must be valid base64");
        return Keypair::from_bytes(&bytes).expect("Invalid keypair bytes");
    }

    // For local dev, generate a random keypair (needs to be funded)
    info!("No keypair configured, generating ephemeral keypair for local dev");
    Keypair::new()
}
