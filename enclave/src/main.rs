#![allow(dead_code)]

mod adaptor_sig;
mod attestation;
mod asc_manager;
mod audit;
mod batch;
mod deposit_detector;
mod error;
mod handlers;
mod kms_bootstrap;
mod snapshot;
mod snapshot_store;
mod state;
mod tls;
mod wal;

use axum::routing::{get, post};
use axum::Router;
use solana_sdk::pubkey::Pubkey;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

use deposit_detector::DepositDetector;
use handlers::AppState;
use kms_bootstrap::bootstrap_materials;
use snapshot::SnapshotManager;
use snapshot_store::SnapshotStoreClient;
use state::{SolanaRuntimeConfig, VaultState};
use wal::Wal;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

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
    let snapshot_store = SnapshotStoreClient::from_env();
    let bootstrap = bootstrap_materials(vault_config, attestation_policy_hash, snapshot_store.clone())
        .await
        .expect("runtime bootstrap must succeed");
    let vault_signer_pubkey =
        Pubkey::new_from_array(bootstrap.signing_key.verifying_key().to_bytes());
    info!(vault_signer = %vault_signer_pubkey, "Loaded vault signer keypair");

    let vault_state = Arc::new(VaultState::new(
        vault_config,
        bootstrap.signing_key,
        usdc_mint,
        attestation_policy_hash,
        solana.clone(),
    ));

    let wal = if let Some(snapshot_store) = snapshot_store.clone() {
        let wal_prefix =
            env::var("A402_WAL_PREFIX").unwrap_or_else(|_| format!("wal/{vault_config}"));
        Arc::new(
            Wal::new_with_snapshot_store(
                PathBuf::from(&wal_path),
                bootstrap.storage_key,
                snapshot_store,
                wal_prefix,
            )
            .await,
        )
    } else {
        Arc::new(Wal::new_with_key(PathBuf::from(&wal_path), bootstrap.storage_key).await)
    };
    let deposit_detector = Arc::new(DepositDetector::new(
        solana.vault_token_account,
        solana.program_id,
        solana.rpc_url.clone(),
        solana.ws_url.clone(),
    ));

    let watchtower_url = env::var("A402_WATCHTOWER_URL")
        .expect("A402_WATCHTOWER_URL must be set for Phase 4 receipt mirroring");
    ensure_watchtower_ready(&watchtower_url)
        .await
        .expect("watchtower health check must succeed before enclave starts serving");

    let tls_runtime = tls::TlsRuntime::from_env().expect("TLS configuration must be valid");
    let provider_mtls_enabled = tls_runtime
        .as_ref()
        .map(|runtime| runtime.mtls_enabled())
        .unwrap_or(false);

    let app_state = Arc::new(AppState {
        vault: vault_state,
        wal,
        deposit_detector: deposit_detector.clone(),
        asc_ops_lock: tokio::sync::Mutex::new(()),
        persistence_lock: tokio::sync::Mutex::new(()),
        watchtower_url: Some(watchtower_url),
        attestation_document: bootstrap.attestation.document_b64,
        attestation_is_local_dev: bootstrap.attestation.is_local_dev,
        provider_mtls_enabled,
    });

    let snapshot_manager = snapshot_store
        .clone()
        .and_then(|client| SnapshotManager::from_env(client, bootstrap.storage_key, vault_config))
        .map(Arc::new);

    let replay_from = if let Some(manager) = snapshot_manager.as_ref() {
        manager
            .recover_latest(&app_state)
            .await
            .expect("snapshot recovery must succeed")
    } else {
        None
    };

    wal::replay_app_state_from(&app_state, replay_from)
        .await
        .expect("WAL replay must succeed on startup");

    // Spawn background tasks (batch settlement, reservation expiry)
    batch::spawn_background_tasks(app_state.clone());

    // Spawn deposit detection (monitors on-chain deposits to update client balances)
    deposit_detector::spawn_deposit_detector(app_state.clone(), deposit_detector);

    if let Some(manager) = snapshot_manager {
        manager.spawn_background_task(app_state.clone());
    }

    let app = Router::new()
        .route("/v1/attestation", get(handlers::get_attestation))
        .route("/v1/verify", post(handlers::post_verify))
        .route("/v1/settle", post(handlers::post_settle))
        .route(
            "/v1/settlement/status",
            post(handlers::post_settlement_status),
        )
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
    if let Some(tls_runtime) = tls_runtime {
        tls::serve(listener, app, tls_runtime).await.unwrap();
    } else {
        axum::serve(listener, app).await.unwrap();
    }
}

async fn ensure_watchtower_ready(url: &str) -> Result<(), String> {
    let status_url = format!("{url}/v1/status");
    let response = reqwest::Client::new()
        .get(&status_url)
        .send()
        .await
        .map_err(|error| format!("failed to reach watchtower at {status_url}: {error}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "watchtower health check returned status {}",
            response.status()
        ));
    }
    Ok(())
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
