//! Subly402 Receipt Watchtower
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
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
    rpc_url: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let vault_config = env::var("SUBLY402_VAULT_CONFIG")
        .ok()
        .and_then(|v| Pubkey::from_str(&v).ok())
        .unwrap_or_default();

    let program_id = env::var("SUBLY402_PROGRAM_ID")
        .ok()
        .and_then(|v| Pubkey::from_str(&v).ok())
        .unwrap_or_else(|| subly402_vault::ID);

    let rpc_url =
        env::var("SUBLY402_SOLANA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());

    let listen_addr =
        env::var("SUBLY402_WATCHTOWER_LISTEN").unwrap_or_else(|_| "0.0.0.0:3200".to_string());

    let store_path = env::var("SUBLY402_WATCHTOWER_STORE_PATH")
        .unwrap_or_else(|_| "data/watchtower_receipts.json".to_string());

    let poll_interval: u64 = env::var("SUBLY402_WATCHTOWER_POLL_SEC")
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
        rpc_url,
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
) -> Response {
    let (key, receipt) = match validate_store_receipt_request(&state, &req).await {
        Ok(validated) => validated,
        Err((status, message)) => {
            return (
                status,
                Json(json!({
                    "ok": false,
                    "error": "invalid_receipt",
                    "message": message,
                })),
            )
                .into_response();
        }
    };

    let stored = state.receipt_store.store_receipt(&key, receipt);
    let current_nonce = state.receipt_store.get_nonce(&key);

    // Persist to disk after each store
    if stored {
        state.receipt_store.persist().await;
    }

    (
        StatusCode::OK,
        Json(StoreReceiptResponse {
            ok: true,
            stored,
            current_nonce,
        }),
    )
        .into_response()
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
    if let Ok(encoded) = env::var("SUBLY402_WATCHTOWER_KEYPAIR_B64") {
        let bytes = BASE64
            .decode(encoded)
            .expect("SUBLY402_WATCHTOWER_KEYPAIR_B64 must be valid base64");
        return Keypair::try_from(bytes.as_slice()).expect("Invalid keypair bytes");
    }

    // For local dev, generate a random keypair (needs to be funded)
    info!("No keypair configured, generating ephemeral keypair for local dev");
    Keypair::new()
}

async fn validate_store_receipt_request(
    state: &AppState,
    req: &StoreReceiptRequest,
) -> Result<(ReceiptKey, StoredReceipt), (StatusCode, String)> {
    let vault = Pubkey::from_str(&req.vault_config)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid vaultConfig: {e}")))?;
    let vault_signer = fetch_vault_signer_pubkey(&state.rpc_url, &vault)
        .map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e))?;
    validate_store_receipt_request_inner(
        req,
        (state.vault_config != Pubkey::default()).then_some(state.vault_config),
        &vault_signer,
    )
}

fn fetch_vault_signer_pubkey(rpc_url: &str, vault: &Pubkey) -> Result<[u8; 32], String> {
    let rpc = solana_rpc_client::rpc_client::RpcClient::new(rpc_url.to_string());
    let vault_config_data = rpc
        .get_account_data(vault)
        .map_err(|e| format!("failed to fetch vault config: {e}"))?;

    let signer_offset = 8 + 1 + 8 + 32 + 1;
    if vault_config_data.len() < signer_offset + 32 {
        return Err("vault config account data too short".into());
    }

    vault_config_data[signer_offset..signer_offset + 32]
        .try_into()
        .map_err(|_| "failed to decode vault signer pubkey".into())
}

fn validate_store_receipt_request_inner(
    req: &StoreReceiptRequest,
    expected_vault: Option<Pubkey>,
    vault_signer: &[u8; 32],
) -> Result<(ReceiptKey, StoredReceipt), (StatusCode, String)> {
    if req.participant_kind > 1 {
        return Err((
            StatusCode::BAD_REQUEST,
            "participantKind must be 0 or 1".into(),
        ));
    }

    let participant = Pubkey::from_str(&req.participant)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid participant: {e}")))?;
    let recipient_ata = Pubkey::from_str(&req.recipient_ata).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid recipientAta: {e}"),
        )
    })?;
    let vault = Pubkey::from_str(&req.vault_config)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid vaultConfig: {e}")))?;

    if let Some(expected_vault) = expected_vault {
        if vault != expected_vault {
            return Err((
                StatusCode::BAD_REQUEST,
                "receipt vaultConfig does not match this watchtower".into(),
            ));
        }
    }

    let signature_bytes = BASE64.decode(&req.signature).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid signature base64: {e}"),
        )
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid signature bytes: {e}"),
        )
    })?;
    let message = BASE64.decode(&req.message).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid message base64: {e}"),
        )
    })?;

    let decoded = subly402_vault::ed25519_utils::decode_participant_receipt_message(&message)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid receipt message: {e}"),
            )
        })?;

    require_match(
        decoded.participant.as_ref(),
        participant.as_ref(),
        "participant mismatch in receipt message",
    )?;
    require_match(
        &[decoded.participant_kind],
        &[req.participant_kind],
        "participantKind mismatch in receipt message",
    )?;
    require_match(
        decoded.recipient_ata.as_ref(),
        recipient_ata.as_ref(),
        "recipientAta mismatch in receipt message",
    )?;
    require_match_u64(
        decoded.free_balance,
        req.free_balance,
        "freeBalance mismatch in receipt message",
    )?;
    require_match_u64(
        decoded.locked_balance,
        req.locked_balance,
        "lockedBalance mismatch in receipt message",
    )?;
    require_match_i64(
        decoded.max_lock_expires_at,
        req.max_lock_expires_at,
        "maxLockExpiresAt mismatch in receipt message",
    )?;
    require_match_u64(
        decoded.nonce,
        req.nonce,
        "nonce mismatch in receipt message",
    )?;
    require_match_i64(
        decoded.timestamp,
        req.timestamp,
        "timestamp mismatch in receipt message",
    )?;
    require_match_u64(
        decoded.snapshot_seqno,
        req.snapshot_seqno,
        "snapshotSeqno mismatch in receipt message",
    )?;
    require_match(
        decoded.vault_config.as_ref(),
        vault.as_ref(),
        "vaultConfig mismatch in receipt message",
    )?;

    let verifying_key = VerifyingKey::from_bytes(vault_signer).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid vault signer: {e}"),
        )
    })?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("receipt signature verification failed: {e}"),
            )
        })?;

    let key = ReceiptKey {
        vault,
        participant,
        participant_kind: req.participant_kind,
    };
    let receipt = StoredReceipt {
        participant: req.participant.clone(),
        participant_kind: req.participant_kind,
        recipient_ata: req.recipient_ata.clone(),
        free_balance: req.free_balance,
        locked_balance: req.locked_balance,
        max_lock_expires_at: req.max_lock_expires_at,
        nonce: req.nonce,
        timestamp: req.timestamp,
        snapshot_seqno: req.snapshot_seqno,
        vault_config: req.vault_config.clone(),
        signature: req.signature.clone(),
        message: req.message.clone(),
    };

    Ok((key, receipt))
}

fn require_match(
    actual: &[u8],
    expected: &[u8],
    message: &'static str,
) -> Result<(), (StatusCode, String)> {
    if actual == expected {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, message.into()))
    }
}

fn require_match_u64(
    actual: u64,
    expected: u64,
    message: &'static str,
) -> Result<(), (StatusCode, String)> {
    if actual == expected {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, message.into()))
    }
}

fn require_match_i64(
    actual: i64,
    expected: i64,
    message: &'static str,
) -> Result<(), (StatusCode, String)> {
    if actual == expected {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, message.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64_STD;
    use ed25519_dalek::{Signer, SigningKey};

    fn build_request(signing_key: &SigningKey, vault: Pubkey) -> StoreReceiptRequest {
        let participant = Pubkey::new_unique();
        let recipient_ata = Pubkey::new_unique();
        let participant_kind = 0u8;
        let free_balance = 1_000_000u64;
        let locked_balance = 250_000u64;
        let max_lock_expires_at = 1_700_000_000i64;
        let nonce = 42u64;
        let timestamp = 1_700_000_100i64;
        let snapshot_seqno = 7u64;

        let mut message = Vec::with_capacity(145);
        message.extend_from_slice(participant.as_ref());
        message.push(participant_kind);
        message.extend_from_slice(recipient_ata.as_ref());
        message.extend_from_slice(&free_balance.to_le_bytes());
        message.extend_from_slice(&locked_balance.to_le_bytes());
        message.extend_from_slice(&max_lock_expires_at.to_le_bytes());
        message.extend_from_slice(&nonce.to_le_bytes());
        message.extend_from_slice(&timestamp.to_le_bytes());
        message.extend_from_slice(&snapshot_seqno.to_le_bytes());
        message.extend_from_slice(vault.as_ref());

        let signature = signing_key.sign(&message).to_bytes();

        StoreReceiptRequest {
            participant: participant.to_string(),
            participant_kind,
            recipient_ata: recipient_ata.to_string(),
            free_balance,
            locked_balance,
            max_lock_expires_at,
            nonce,
            timestamp,
            snapshot_seqno,
            vault_config: vault.to_string(),
            signature: BASE64_STD.encode(signature),
            message: BASE64_STD.encode(message),
        }
    }

    #[test]
    fn validate_receipt_rejects_mismatched_message_fields() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let vault = Pubkey::new_unique();
        let mut req = build_request(&signing_key, vault);
        req.free_balance += 1;

        let err = validate_store_receipt_request_inner(
            &req,
            Some(vault),
            &signing_key.verifying_key().to_bytes(),
        )
        .expect_err("validation should fail");
        assert!(err.1.contains("freeBalance mismatch"));
    }

    #[test]
    fn validate_receipt_accepts_signed_message() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let vault = Pubkey::new_unique();
        let req = build_request(&signing_key, vault);

        let (key, receipt) = validate_store_receipt_request_inner(
            &req,
            Some(vault),
            &signing_key.verifying_key().to_bytes(),
        )
        .expect("validation should succeed");
        assert_eq!(key.vault, vault);
        assert_eq!(receipt.vault_config, vault.to_string());
    }
}
