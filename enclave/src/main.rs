#![allow(dead_code)]

mod adaptor_sig;
mod asc_manager;
mod audit;
mod batch;
mod deposit_detector;
mod error;
mod handlers;
mod state;
mod wal;

use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use solana_sdk::pubkey::Pubkey;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use deposit_detector::DepositDetector;
use handlers::AppState;
use state::{SolanaRuntimeConfig, VaultState};
use wal::Wal;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let signing_key = load_signing_key();
    let vault_signer_pubkey = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
    info!(vault_signer = %vault_signer_pubkey, "Loaded vault signer keypair");

    let vault_config = read_pubkey_env("A402_VAULT_CONFIG", Pubkey::default());
    let usdc_mint = read_pubkey_env("A402_USDC_MINT", Pubkey::default());
    let attestation_policy_hash =
        read_fixed_bytes_env("A402_ATTESTATION_POLICY_HASH_HEX", [0u8; 32]);
    let solana = SolanaRuntimeConfig {
        program_id: read_pubkey_env("A402_PROGRAM_ID", a402_vault::ID),
        vault_token_account: read_pubkey_env("A402_VAULT_TOKEN_ACCOUNT", Pubkey::default()),
        rpc_url: env::var("A402_SOLANA_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string()),
        ws_url: env::var("A402_SOLANA_WS_URL")
            .unwrap_or_else(|_| "ws://127.0.0.1:8900".to_string()),
    };
    let wal_path = env::var("A402_WAL_PATH").unwrap_or_else(|_| "data/wal.jsonl".to_string());
    let listen_addr =
        env::var("A402_ENCLAVE_LISTEN").unwrap_or_else(|_| "0.0.0.0:3100".to_string());

    let vault_state = Arc::new(VaultState::new(
        vault_config,
        signing_key,
        usdc_mint,
        attestation_policy_hash,
        solana.clone(),
    ));

    let wal = Arc::new(Wal::new(PathBuf::from(wal_path)).await);
    let deposit_detector = Arc::new(DepositDetector::new(
        solana.vault_token_account,
        solana.program_id,
        solana.rpc_url.clone(),
        solana.ws_url.clone(),
    ));

    let watchtower_url = env::var("A402_WATCHTOWER_URL").ok();

    let app_state = Arc::new(AppState {
        vault: vault_state,
        wal,
        deposit_detector: deposit_detector.clone(),
        asc_ops_lock: tokio::sync::Mutex::new(()),
        watchtower_url,
    });

    wal::replay_app_state(&app_state)
        .await
        .expect("WAL replay must succeed on startup");

    // Spawn background tasks (batch settlement, reservation expiry)
    batch::spawn_background_tasks(app_state.clone());

    // Spawn deposit detection (monitors on-chain deposits to update client balances)
    deposit_detector::spawn_deposit_detector(app_state.clone(), deposit_detector);

    let app = Router::new()
        .route("/v1/attestation", get(handlers::get_attestation))
        .route("/v1/verify", post(handlers::post_verify))
        .route("/v1/settle", post(handlers::post_settle))
        .route("/v1/cancel", post(handlers::post_cancel))
        .route("/v1/withdraw-auth", post(handlers::post_withdraw_auth))
        .route("/v1/balance", post(handlers::post_balance))
        .route("/v1/receipt", post(handlers::post_receipt))
        .route(
            "/v1/provider/register",
            post(handlers::post_register_provider),
        )
        // Phase 3: ASC channel endpoints
        .route("/v1/channel/open", post(handlers::post_channel_open))
        .route("/v1/channel/request", post(handlers::post_channel_request))
        .route("/v1/channel/deliver", post(handlers::post_channel_deliver))
        .route(
            "/v1/channel/finalize",
            post(handlers::post_channel_finalize),
        )
        .route("/v1/channel/close", post(handlers::post_channel_close))
        .route("/v1/admin/seed-balance", post(handlers::post_seed_balance))
        .route("/v1/admin/fire-batch", post(handlers::post_fire_batch))
        .with_state(app_state);

    info!(addr = %listen_addr, vault_config = %vault_config, program_id = %solana.program_id, "Enclave facilitator starting");

    let listener = tokio::net::TcpListener::bind(&listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn load_signing_key() -> SigningKey {
    if let Ok(encoded) = env::var("A402_VAULT_SIGNER_SECRET_KEY_B64") {
        let secret = BASE64
            .decode(encoded)
            .expect("A402_VAULT_SIGNER_SECRET_KEY_B64 must be valid base64");
        let secret: [u8; 32] = secret
            .try_into()
            .expect("A402_VAULT_SIGNER_SECRET_KEY_B64 must decode to exactly 32 bytes");
        return SigningKey::from_bytes(&secret);
    }

    SigningKey::generate(&mut OsRng)
}

fn read_pubkey_env(name: &str, default: Pubkey) -> Pubkey {
    env::var(name)
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("{name} must be a valid Pubkey"))
        })
        .unwrap_or(default)
}

fn read_fixed_bytes_env<const N: usize>(name: &str, default: [u8; N]) -> [u8; N] {
    env::var(name)
        .ok()
        .map(|value| {
            let bytes = hex::decode(value).unwrap_or_else(|_| panic!("{name} must be valid hex"));
            bytes
                .try_into()
                .unwrap_or_else(|_| panic!("{name} must decode to exactly {N} bytes"))
        })
        .unwrap_or(default)
}
