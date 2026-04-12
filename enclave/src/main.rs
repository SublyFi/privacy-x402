#![allow(dead_code)]

mod batch;
mod error;
mod handlers;
mod state;
mod wal;

use axum::routing::{get, post};
use axum::Router;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use solana_sdk::pubkey::Pubkey;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use handlers::AppState;
use state::VaultState;
use wal::Wal;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Phase 1: Generate ephemeral vault signer key (production: loaded via KMS)
    let signing_key = SigningKey::generate(&mut OsRng);
    let vault_signer_pubkey = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
    info!(vault_signer = %vault_signer_pubkey, "Generated vault signer keypair");

    // Phase 1: Use placeholder vault config address (production: read from on-chain)
    let vault_config = Pubkey::default();
    let usdc_mint = Pubkey::default();
    let attestation_policy_hash = [0u8; 32];

    let vault_state = Arc::new(VaultState::new(
        vault_config,
        signing_key,
        usdc_mint,
        attestation_policy_hash,
    ));

    let wal = Arc::new(Wal::new(PathBuf::from("data/wal.jsonl")).await);

    let app_state = Arc::new(AppState {
        vault: vault_state,
        wal,
    });

    // Spawn background tasks (batch settlement, reservation expiry)
    batch::spawn_background_tasks(app_state.clone());

    let app = Router::new()
        .route("/v1/attestation", get(handlers::get_attestation))
        .route("/v1/verify", post(handlers::post_verify))
        .route("/v1/settle", post(handlers::post_settle))
        .route("/v1/cancel", post(handlers::post_cancel))
        .route("/v1/withdraw-auth", post(handlers::post_withdraw_auth))
        .with_state(app_state);

    let addr = "0.0.0.0:3100";
    info!(addr, "Enclave facilitator starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
