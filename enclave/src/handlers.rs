use axum::extract::State;
use axum::http::{header::AUTHORIZATION, HeaderMap};
use axum::Json;
use a402_vault::constants::{
    VAULT_STATUS_ACTIVE, VAULT_STATUS_MIGRATING, VAULT_STATUS_PAUSED, VAULT_STATUS_RETIRED,
};
use a402_vault::state::VaultConfig as OnChainVaultConfig;
use anchor_client::anchor_lang::AccountDeserialize;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::adaptor_sig::AdaptorPreSignature;
use crate::asc_manager;
use crate::attestation::response_window;
use crate::batch;
use crate::deposit_detector::DepositDetector;
use crate::error::EnclaveError;
use crate::state::{Reservation, ReservationStatus, VaultLifecycle, VaultState};
use crate::tls::INTERNAL_MTLS_FINGERPRINT_HEADER;
use crate::wal::{Wal, WalEntry};

const PROVIDER_ID_HEADER: &str = "x-a402-provider-id";
const PROVIDER_AUTH_HEADER: &str = "x-a402-provider-auth";

pub struct AppState {
    pub vault: Arc<VaultState>,
    pub wal: Arc<Wal>,
    pub deposit_detector: Arc<DepositDetector>,
    pub asc_ops_lock: Mutex<()>,
    pub persistence_lock: Mutex<()>,
    /// Watchtower URL for receipt replication (Phase 4).
    pub watchtower_url: Option<String>,
    pub attestation_document: String,
    pub attestation_is_local_dev: bool,
    pub provider_mtls_enabled: bool,
}

// ── Attestation ──

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResponse {
    pub vault_config: String,
    pub vault_signer: String,
    pub attestation_policy_hash: String,
    pub attestation_document: String,
    pub issued_at: String,
    pub expires_at: String,
}

pub async fn get_attestation(State(state): State<Arc<AppState>>) -> Json<AttestationResponse> {
    let (issued_at, expires_at) = response_window();

    Json(AttestationResponse {
        vault_config: state.vault.vault_config.to_string(),
        vault_signer: state.vault.vault_signer_pubkey.to_string(),
        attestation_policy_hash: hex::encode(state.vault.attestation_policy_hash),
        attestation_document: state.attestation_document.clone(),
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    })
}

// ── Verify ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestContext {
    pub method: String,
    pub origin: String,
    pub path_and_query: String,
    pub body_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub version: u32,
    pub scheme: String,
    pub payment_id: String,
    pub client: String,
    pub vault: String,
    pub provider_id: String,
    pub pay_to: String,
    pub network: String,
    pub asset_mint: String,
    pub amount: String,
    pub request_hash: String,
    pub payment_details_hash: String,
    pub expires_at: String,
    pub nonce: String,
    pub client_sig: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyRequest {
    pub payment_payload: PaymentPayload,
    #[serde(default)]
    pub payment_details: Option<serde_json::Value>,
    pub request_context: RequestContext,
}

// ── Provider Authentication Helper (§8.2 requirement 1) ──

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

async fn load_vault_lifecycle(state: &Arc<AppState>) -> Result<VaultLifecycle, EnclaveError> {
    if cfg!(test) {
        return Ok(state.vault.lifecycle.read().await.clone());
    }

    let now_ms = Utc::now().timestamp_millis();
    let rpc = RpcClient::new(state.vault.solana.rpc_url.clone());
    let account_data = rpc
        .get_account_data(&state.vault.vault_config)
        .await
        .map_err(|_| EnclaveError::VaultStatusUnavailable)?;
    let mut slice: &[u8] = account_data.as_slice();
    let vault_config = OnChainVaultConfig::try_deserialize(&mut slice)
        .map_err(|_| EnclaveError::VaultStatusUnavailable)?;

    let lifecycle = VaultLifecycle {
        status: vault_config.status,
        successor_vault: vault_config.successor_vault,
        exit_deadline: vault_config.exit_deadline,
        synced_at_ms: now_ms,
    };
    *state.vault.lifecycle.write().await = lifecycle.clone();
    Ok(lifecycle)
}

async fn ensure_vault_allows_new_verification(state: &Arc<AppState>) -> Result<(), EnclaveError> {
    let lifecycle = load_vault_lifecycle(state).await?;
    match lifecycle.status {
        VAULT_STATUS_ACTIVE => Ok(()),
        VAULT_STATUS_PAUSED => Err(EnclaveError::VaultPaused),
        VAULT_STATUS_MIGRATING => Err(EnclaveError::VaultMigrating),
        VAULT_STATUS_RETIRED => Err(EnclaveError::VaultRetired),
        _ => Err(EnclaveError::VaultStatusUnavailable),
    }
}

async fn ensure_vault_allows_existing_reservation_ops(
    state: &Arc<AppState>,
) -> Result<(), EnclaveError> {
    let lifecycle = load_vault_lifecycle(state).await?;
    match lifecycle.status {
        VAULT_STATUS_ACTIVE => Ok(()),
        VAULT_STATUS_PAUSED => Err(EnclaveError::VaultPaused),
        VAULT_STATUS_MIGRATING => {
            if Utc::now().timestamp() <= lifecycle.exit_deadline {
                Ok(())
            } else {
                Err(EnclaveError::VaultRetired)
            }
        }
        VAULT_STATUS_RETIRED => Err(EnclaveError::VaultRetired),
        _ => Err(EnclaveError::VaultStatusUnavailable),
    }
}

async fn ensure_vault_allows_withdraw(state: &Arc<AppState>) -> Result<(), EnclaveError> {
    let lifecycle = load_vault_lifecycle(state).await?;
    match lifecycle.status {
        VAULT_STATUS_ACTIVE => Ok(()),
        VAULT_STATUS_MIGRATING => {
            if Utc::now().timestamp() <= lifecycle.exit_deadline {
                Ok(())
            } else {
                Err(EnclaveError::VaultRetired)
            }
        }
        VAULT_STATUS_PAUSED => Err(EnclaveError::VaultPaused),
        VAULT_STATUS_RETIRED => Err(EnclaveError::VaultRetired),
        _ => Err(EnclaveError::VaultStatusUnavailable),
    }
}

fn authenticate_registered_provider(
    provider: &crate::state::ProviderRegistration,
    headers: &HeaderMap,
) -> Result<(), EnclaveError> {
    match provider.auth_mode.as_str() {
        "bearer" => {
            let api_key_hash = provider
                .api_key_hash
                .as_deref()
                .ok_or(EnclaveError::InvalidProviderAuthConfig)?;
            if api_key_hash.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }

            let provider_id = header_value(headers, PROVIDER_ID_HEADER)
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            if provider_id != provider.provider_id {
                return Err(EnclaveError::ProviderIdMismatch);
            }

            let auth_header = headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            let token = auth_header
                .strip_prefix("Bearer ")
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            if Sha256::digest(token.as_bytes()).as_slice() != api_key_hash {
                return Err(EnclaveError::ProviderAuthFailed);
            }
            Ok(())
        }
        "api-key" => {
            let api_key_hash = provider
                .api_key_hash
                .as_deref()
                .ok_or(EnclaveError::InvalidProviderAuthConfig)?;
            if api_key_hash.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }

            if let Some(provider_id) = header_value(headers, PROVIDER_ID_HEADER) {
                if provider_id != provider.provider_id {
                    return Err(EnclaveError::ProviderIdMismatch);
                }
            }

            let token = header_value(headers, PROVIDER_AUTH_HEADER)
                .or_else(|| {
                    headers
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.strip_prefix("Bearer "))
                })
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            if Sha256::digest(token.as_bytes()).as_slice() != api_key_hash {
                return Err(EnclaveError::ProviderAuthFailed);
            }
            Ok(())
        }
        "mtls" => {
            let expected_fingerprint = provider
                .mtls_cert_fingerprint
                .as_deref()
                .ok_or(EnclaveError::InvalidProviderAuthConfig)?;
            if expected_fingerprint.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }

            if let Some(provider_id) = header_value(headers, PROVIDER_ID_HEADER) {
                if provider_id != provider.provider_id {
                    return Err(EnclaveError::ProviderIdMismatch);
                }
            }

            let presented_fingerprint = header_value(headers, INTERNAL_MTLS_FINGERPRINT_HEADER)
                .ok_or(EnclaveError::ProviderAuthFailed)?;
            let presented_fingerprint = hex::decode(presented_fingerprint)
                .map_err(|_| EnclaveError::ProviderAuthFailed)?;
            if presented_fingerprint.as_slice() != expected_fingerprint {
                return Err(EnclaveError::ProviderAuthFailed);
            }
            Ok(())
        }
        _ => Err(EnclaveError::UnsupportedProviderAuthMode),
    }
}

fn authenticate_provider(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    expected_provider_id: &str,
) -> Result<String, EnclaveError> {
    let provider = state
        .vault
        .providers
        .get(expected_provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;
    authenticate_registered_provider(provider.value(), headers)?;
    Ok(expected_provider_id.to_string())
}

/// Compute canonical JSON hash of payment details (§6, paymentDetailsHash).
fn compute_payment_details_hash(details: &serde_json::Value) -> Vec<u8> {
    // canonical_json: UTF-8, keys in lexicographic order, no extra whitespace
    let canonical = canonical_json(details);
    Sha256::digest(canonical.as_bytes()).to_vec()
}

/// Produce canonical JSON: sorted keys, no extra whitespace.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonical_json(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let entries: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", entries.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub ok: bool,
    pub verification_id: String,
    pub reservation_id: String,
    pub reservation_expires_at: String,
    pub provider_id: String,
    pub amount: String,
    pub verification_receipt: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReceiptEnvelope {
    pub verification_id: String,
    pub reservation_id: String,
    pub payment_id: String,
    pub client: String,
    pub provider_id: String,
    pub amount: String,
    pub request_hash: String,
    pub payment_details_hash: String,
    pub reservation_expires_at: String,
    pub vault_config: String,
    pub signature: String,
    pub message: String,
}

fn encode_verification_receipt_envelope(
    receipt: &VerificationReceiptEnvelope,
) -> Result<String, EnclaveError> {
    serde_json::to_vec(receipt)
        .map(|json| BASE64.encode(json))
        .map_err(|e| EnclaveError::Internal(format!("VerificationReceipt serialization failed: {e}")))
}

fn issue_verification_receipt(
    state: &Arc<AppState>,
    reservation: &Reservation,
) -> Result<String, EnclaveError> {
    let reservation_expires_at =
        chrono::DateTime::from_timestamp(reservation.expires_at, 0).unwrap_or_default();
    let request_hash = hex::encode(reservation.request_hash);
    let payment_details_hash = hex::encode(reservation.payment_details_hash);
    let message = state.vault.build_verification_receipt_message(
        &reservation.verification_id,
        &reservation.reservation_id,
        &reservation.payment_id,
        &reservation.client,
        &reservation.provider_id,
        reservation.amount,
        &request_hash,
        &payment_details_hash,
        reservation.expires_at,
    );
    let signature = state.vault.sign_message(&message);

    encode_verification_receipt_envelope(&VerificationReceiptEnvelope {
        verification_id: reservation.verification_id.clone(),
        reservation_id: reservation.reservation_id.clone(),
        payment_id: reservation.payment_id.clone(),
        client: reservation.client.to_string(),
        provider_id: reservation.provider_id.clone(),
        amount: reservation.amount.to_string(),
        request_hash,
        payment_details_hash,
        reservation_expires_at: reservation_expires_at.to_rfc3339(),
        vault_config: state.vault.vault_config.to_string(),
        signature: BASE64.encode(signature),
        message: BASE64.encode(message),
    })
}

pub async fn post_verify(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, EnclaveError> {
    let payload = &req.payment_payload;
    let payment_details = req
        .payment_details
        .as_ref()
        .ok_or(EnclaveError::PaymentDetailsRequired)?;

    if state.deposit_detector.is_enabled() && !state.deposit_detector.is_ready() {
        return Err(EnclaveError::DepositSyncInProgress);
    }

    ensure_vault_allows_new_verification(&state).await?;

    // 1. Validate scheme
    if payload.scheme != "a402-svm-v1" {
        return Err(EnclaveError::InvalidScheme);
    }
    if payment_details
        .get("scheme")
        .and_then(|value| value.as_str())
        != Some("a402-svm-v1")
    {
        return Err(EnclaveError::InvalidScheme);
    }

    // C5: Authenticate provider from provider registration + headers (§8.2 requirement 1)
    let authenticated_provider_id =
        authenticate_provider(&state, &headers, &payload.provider_id)?;

    // 2. Validate provider exists and matches authenticated identity
    let provider = state
        .vault
        .providers
        .get(&payload.provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;

    if authenticated_provider_id != payload.provider_id {
        return Err(EnclaveError::ProviderIdMismatch);
    }

    // C6: Validate registration fields match payload (§8.2 requirement 7)
    if payload.pay_to != provider.settlement_token_account.to_string() {
        return Err(EnclaveError::PayToMismatch);
    }
    if payload.asset_mint != provider.asset_mint.to_string() {
        return Err(EnclaveError::AssetMintMismatch);
    }
    if payload.network != provider.network {
        return Err(EnclaveError::NetworkMismatch);
    }

    // C9: Validate request origin against provider allowedOrigins (§4)
    if !provider.allowed_origins.is_empty()
        && !provider
            .allowed_origins
            .contains(&req.request_context.origin)
    {
        return Err(EnclaveError::OriginNotAllowed);
    }

    // C7: Validate paymentDetailsHash via canonical JSON (§8.2 requirement 3)
    let computed_hash = compute_payment_details_hash(payment_details);
    let provided_hash = hex::decode(&payload.payment_details_hash)
        .map_err(|_| EnclaveError::PaymentDetailsHashMismatch)?;
    if computed_hash != provided_hash {
        return Err(EnclaveError::PaymentDetailsHashMismatch);
    }

    // Drop the provider reference before further borrows
    drop(provider);

    // 3. Validate vault address
    if payload.vault != state.vault.vault_config.to_string() {
        return Err(EnclaveError::VaultNotActive);
    }

    // 4. Validate expiration
    let expires_at = chrono::DateTime::parse_from_rfc3339(&payload.expires_at)
        .map_err(|_| EnclaveError::PaymentExpired)?;
    if expires_at < Utc::now() {
        return Err(EnclaveError::PaymentExpired);
    }

    // 5. Verify client signature
    let client_pubkey =
        Pubkey::from_str(&payload.client).map_err(|_| EnclaveError::InvalidClientSignature)?;

    verify_client_signature(payload)?;

    // 6. Verify request hash
    let computed_request_hash =
        compute_request_hash(&req.request_context, &payload.payment_details_hash);
    let provided_request_hash =
        hex::decode(&payload.request_hash).map_err(|_| EnclaveError::RequestHashMismatch)?;
    if computed_request_hash != provided_request_hash.as_slice() {
        return Err(EnclaveError::RequestHashMismatch);
    }

    let amount: u64 = payload
        .amount
        .parse()
        .map_err(|_| EnclaveError::Internal("Invalid amount".into()))?;

    // 7. Idempotency: check if payment_id already used
    if let Some(existing_ver_id) = state.vault.payment_id_index.get(&payload.payment_id) {
        if let Some(existing) = state.vault.reservations.get(existing_ver_id.value()) {
            // Same payment_id + same request_hash → idempotent retry
            let req_hash: [u8; 32] = computed_request_hash.try_into().unwrap();
            if existing.request_hash == req_hash {
                let res_expires =
                    chrono::DateTime::from_timestamp(existing.expires_at, 0).unwrap_or_default();
                let verification_receipt = issue_verification_receipt(&state, &existing)?;
                return Ok(Json(VerifyResponse {
                    ok: true,
                    verification_id: existing.verification_id.clone(),
                    reservation_id: existing.reservation_id.clone(),
                    reservation_expires_at: res_expires.to_rfc3339(),
                    provider_id: existing.provider_id.clone(),
                    amount: existing.amount.to_string(),
                    verification_receipt,
                }));
            } else {
                return Err(EnclaveError::PaymentIdReused);
            }
        }
    }

    let now = Utc::now().timestamp();
    let verification_id = format!("ver_{}", uuid::Uuid::now_v7());
    let reservation_id = format!("res_{}", uuid::Uuid::now_v7());
    let reservation_expires_at = now + 60; // 60 second window

    let request_hash: [u8; 32] = computed_request_hash.try_into().unwrap();
    let payment_details_hash: [u8; 32] = hex::decode(&payload.payment_details_hash)
        .map_err(|_| EnclaveError::PaymentDetailsHashMismatch)?
        .try_into()
        .map_err(|_| EnclaveError::PaymentDetailsHashMismatch)?;

    let reservation = Reservation {
        verification_id: verification_id.clone(),
        reservation_id: reservation_id.clone(),
        payment_id: payload.payment_id.clone(),
        client: client_pubkey,
        provider_id: payload.provider_id.clone(),
        amount,
        request_hash,
        payment_details_hash,
        status: ReservationStatus::Reserved,
        created_at: now,
        expires_at: reservation_expires_at,
        settlement_id: None,
        settled_at: None,
    };

    {
        let _persist_guard = state.persistence_lock.lock().await;

        // 8. Reserve balance
        state.vault.reserve_balance(&client_pubkey, amount)?;

        // 10. WAL append (durable before response)
        state
            .wal
            .append(WalEntry::ReservationCreated {
                verification_id: verification_id.clone(),
                reservation_id: Some(reservation_id.clone()),
                payment_id: payload.payment_id.clone(),
                client: payload.client.clone(),
                provider_id: payload.provider_id.clone(),
                amount,
                request_hash: Some(hex::encode(request_hash)),
                payment_details_hash: Some(hex::encode(payment_details_hash)),
                created_at: Some(now),
                expires_at: Some(reservation_expires_at),
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

        state
            .vault
            .reservations
            .insert(verification_id.clone(), reservation);
        state
            .vault
            .payment_id_index
            .insert(payload.payment_id.clone(), verification_id.clone());
    }

    let res_expires =
        chrono::DateTime::from_timestamp(reservation_expires_at, 0).unwrap_or_default();

    info!(verification_id = %verification_id, amount, "Payment verified and reserved");

    let verification_receipt = issue_verification_receipt(
        &state,
        state
            .vault
            .reservations
            .get(&verification_id)
            .ok_or(EnclaveError::ReservationNotFound)?
            .value(),
    )?;

    Ok(Json(VerifyResponse {
        ok: true,
        verification_id,
        reservation_id,
        reservation_expires_at: res_expires.to_rfc3339(),
        provider_id: payload.provider_id.clone(),
        amount: amount.to_string(),
        verification_receipt,
    }))
}

// ── Settle ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleRequest {
    pub verification_id: String,
    pub result_hash: String,
    pub status_code: u16,
}

const PARTICIPANT_KIND_CLIENT: u8 = 0;
const PARTICIPANT_KIND_PROVIDER: u8 = 1;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponse {
    pub ok: bool,
    pub settlement_id: String,
    pub offchain_settled_at: String,
    pub provider_credit_amount: String,
    pub batch_id: Option<u64>,
    pub participant_receipt: String,
}

pub async fn post_settle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SettleRequest>,
) -> Result<Json<SettleResponse>, EnclaveError> {
    let (status, client, provider_id, amount, existing_settlement_id, settled_at) = {
        let reservation = state
            .vault
            .reservations
            .get(&req.verification_id)
            .ok_or(EnclaveError::ReservationNotFound)?;
        (
            reservation.status.clone(),
            reservation.client,
            reservation.provider_id.clone(),
            reservation.amount,
            reservation.settlement_id.clone(),
            reservation.settled_at,
        )
    };

    ensure_vault_allows_existing_reservation_ops(&state).await?;

    // C5: Authenticate provider (§8.3 — same auth as /verify)
    let authenticated_provider_id =
        authenticate_provider(&state, &headers, &provider_id)?;

    // Verify authenticated provider owns this reservation
    if authenticated_provider_id != provider_id {
        return Err(EnclaveError::ProviderIdMismatch);
    }

    if status == ReservationStatus::SettledOffchain {
        let settled_at = settled_at.unwrap_or(0);
        let settled_time = chrono::DateTime::from_timestamp(settled_at, 0).unwrap_or_default();
        return Ok(Json(SettleResponse {
            ok: true,
            settlement_id: existing_settlement_id.unwrap_or_default(),
            offchain_settled_at: settled_time.to_rfc3339(),
            provider_credit_amount: amount.to_string(),
            batch_id: None,
            participant_receipt: encode_receipt_envelope(
                &issue_provider_receipt(&state, &provider_id).await?,
            )?,
        }));
    }

    // Must be Reserved
    if status != ReservationStatus::Reserved {
        return Err(EnclaveError::InvalidReservationStatus(format!(
            "{:?}",
            status
        )));
    }

    let now = Utc::now().timestamp();
    let settlement_id = format!("set_{}", uuid::Uuid::now_v7());

    {
        let _persist_guard = state.persistence_lock.lock().await;

        // Settle payment
        state
            .vault
            .settle_payment(&client, amount, &provider_id, &settlement_id, now)?;

        // Record settlement for audit record generation (Phase 2)
        let provider_reg = state.vault.providers.get(&provider_id);
        let provider_pubkey = provider_reg
            .as_ref()
            .map(|p| p.settlement_token_account)
            .unwrap_or_default();
        state.vault.settlement_history.insert(
            settlement_id.clone(),
            crate::state::SettlementRecord {
                settlement_id: settlement_id.clone(),
                client,
                provider: provider_pubkey,
                amount,
                timestamp: now,
            },
        );

        // WAL append (durable before response)
        state
            .wal
            .append(WalEntry::SettlementCommitted {
                settlement_id: settlement_id.clone(),
                verification_id: req.verification_id.clone(),
                provider_id: provider_id.clone(),
                amount,
                settled_at: Some(now),
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

        {
            let mut reservation = state
                .vault
                .reservations
                .get_mut(&req.verification_id)
                .ok_or(EnclaveError::ReservationNotFound)?;
            reservation.status = ReservationStatus::SettledOffchain;
            reservation.settlement_id = Some(settlement_id.clone());
            reservation.settled_at = Some(now);
        }
    }

    let participant_receipt =
        encode_receipt_envelope(&issue_provider_receipt(&state, &provider_id).await?)?;

    let settled_time = chrono::DateTime::from_timestamp(now, 0).unwrap_or_default();

    info!(settlement_id = %settlement_id, "Payment settled off-chain");

    Ok(Json(SettleResponse {
        ok: true,
        settlement_id,
        offchain_settled_at: settled_time.to_rfc3339(),
        provider_credit_amount: amount.to_string(),
        batch_id: None,
        participant_receipt,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementStatusRequest {
    pub settlement_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementStatusResponse {
    pub ok: bool,
    pub settlement_id: String,
    pub verification_id: String,
    pub provider_id: String,
    pub status: String,
    pub batch_id: Option<u64>,
    pub tx_signature: Option<String>,
}

pub async fn post_settlement_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SettlementStatusRequest>,
) -> Result<Json<SettlementStatusResponse>, EnclaveError> {
    let reservation = state
        .vault
        .reservations
        .iter()
        .find(|entry| {
            entry
                .settlement_id
                .as_ref()
                .map(|settlement_id| settlement_id == &req.settlement_id)
                .unwrap_or(false)
        })
        .map(|entry| entry.clone())
        .ok_or(EnclaveError::SettlementNotFound)?;

    authenticate_provider(&state, &headers, &reservation.provider_id)?;

    let batch_info = state
        .vault
        .settlement_batches
        .get(&req.settlement_id)
        .map(|entry| entry.clone());

    Ok(Json(SettlementStatusResponse {
        ok: true,
        settlement_id: req.settlement_id,
        verification_id: reservation.verification_id,
        provider_id: reservation.provider_id,
        status: format!("{:?}", reservation.status),
        batch_id: batch_info.as_ref().map(|entry| entry.batch_id),
        tx_signature: batch_info.map(|entry| entry.tx_signature),
    }))
}

// ── Cancel ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelRequest {
    pub verification_id: String,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelResponse {
    pub ok: bool,
    pub cancelled_at: String,
}

pub async fn post_cancel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CancelRequest>,
) -> Result<Json<CancelResponse>, EnclaveError> {
    let provider_id = state
        .vault
        .reservations
        .get(&req.verification_id)
        .ok_or(EnclaveError::ReservationNotFound)?
        .provider_id
        .clone();

    ensure_vault_allows_existing_reservation_ops(&state).await?;

    // C8: Authenticate provider (§8.5)
    let authenticated_provider_id =
        authenticate_provider(&state, &headers, &provider_id)?;

    let mut reservation = state
        .vault
        .reservations
        .get_mut(&req.verification_id)
        .ok_or(EnclaveError::ReservationNotFound)?;

    // C8: Check provider_mismatch — only the provider that owns the reservation can cancel (§8.5)
    if authenticated_provider_id != reservation.provider_id {
        return Err(EnclaveError::ProviderIdMismatch);
    }

    if reservation.status == ReservationStatus::Cancelled {
        let now_str = Utc::now().to_rfc3339();
        return Ok(Json(CancelResponse {
            ok: true,
            cancelled_at: now_str,
        }));
    }

    if reservation.status != ReservationStatus::Reserved {
        return Err(EnclaveError::InvalidReservationStatus(format!(
            "{:?}",
            reservation.status
        )));
    }

    {
        let _persist_guard = state.persistence_lock.lock().await;

        // Release balance
        state
            .vault
            .release_balance(&reservation.client, reservation.amount)?;

        // WAL
        state
            .wal
            .append(WalEntry::ReservationCancelled {
                verification_id: req.verification_id.clone(),
                reason: req.reason.clone(),
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

        reservation.status = ReservationStatus::Cancelled;
    }

    let now_str = Utc::now().to_rfc3339();

    info!(verification_id = %req.verification_id, reason = %req.reason, "Reservation cancelled");

    Ok(Json(CancelResponse {
        ok: true,
        cancelled_at: now_str,
    }))
}

// ── Withdraw Authorization ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawAuthRequest {
    pub client: String,
    pub recipient_ata: String,
    pub amount: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawAuthResponse {
    pub ok: bool,
    pub withdraw_nonce: u64,
    pub expires_at: i64,
    pub signature: String,
    pub message: String,
}

pub async fn post_withdraw_auth(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WithdrawAuthRequest>,
) -> Result<Json<WithdrawAuthResponse>, EnclaveError> {
    ensure_vault_allows_withdraw(&state).await?;

    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;
    let recipient_ata = Pubkey::from_str(&req.recipient_ata)
        .map_err(|_| EnclaveError::Internal("Invalid recipient ATA".into()))?;

    // Check client has sufficient free balance
    let balance = state
        .vault
        .client_balances
        .get(&client)
        .ok_or(EnclaveError::ClientNotFound)?;
    if balance.free < req.amount {
        return Err(EnclaveError::InsufficientBalance);
    }

    let withdraw_nonce = state.vault.next_withdraw_nonce();
    let now = Utc::now().timestamp();
    let expires_at = now + 300; // 5 minutes

    let message = state.vault.build_withdraw_authorization_message(
        &client,
        &recipient_ata,
        req.amount,
        withdraw_nonce,
        expires_at,
    );

    let signature = state.vault.sign_message(&message);

    Ok(Json(WithdrawAuthResponse {
        ok: true,
        withdraw_nonce,
        expires_at,
        signature: BASE64.encode(&signature),
        message: BASE64.encode(&message),
    }))
}

// ── Client Balance ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceRequest {
    pub client: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    pub ok: bool,
    pub client: String,
    pub free: u64,
    pub locked: u64,
    pub total_deposited: u64,
    pub total_withdrawn: u64,
}

pub async fn post_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BalanceRequest>,
) -> Result<Json<BalanceResponse>, EnclaveError> {
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;

    let balance = state
        .vault
        .client_balances
        .get(&client)
        .ok_or(EnclaveError::ClientNotFound)?;

    Ok(Json(BalanceResponse {
        ok: true,
        client: req.client,
        free: balance.free,
        locked: balance.locked,
        total_deposited: balance.total_deposited,
        total_withdrawn: balance.total_withdrawn,
    }))
}

// ── Client Receipt ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptRequest {
    pub client: String,
    pub recipient_ata: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptResponse {
    pub ok: bool,
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WatchtowerStoreReceiptResponse {
    pub ok: bool,
    pub stored: bool,
    pub current_nonce: u64,
}

pub async fn post_receipt(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReceiptRequest>,
) -> Result<Json<ReceiptResponse>, EnclaveError> {
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;
    let recipient_ata = Pubkey::from_str(&req.recipient_ata)
        .map_err(|_| EnclaveError::Internal("Invalid recipient ATA".into()))?;

    let balance = state
        .vault
        .client_balances
        .get(&client)
        .ok_or(EnclaveError::ClientNotFound)?;
    let free_balance = balance.free;
    let locked_balance = balance.locked;
    let max_lock_expires_at = balance.max_lock_expires_at;
    drop(balance);

    Ok(Json(
        issue_participant_receipt(
            &state,
            client,
            PARTICIPANT_KIND_CLIENT,
            recipient_ata,
            free_balance,
            locked_balance,
            max_lock_expires_at,
        )
        .await?,
    ))
}

fn encode_receipt_envelope(receipt: &ReceiptResponse) -> Result<String, EnclaveError> {
    serde_json::to_vec(receipt)
        .map(|json| BASE64.encode(json))
        .map_err(|e| EnclaveError::Internal(format!("Receipt serialization failed: {e}")))
}

async fn issue_provider_receipt(
    state: &Arc<AppState>,
    provider_id: &str,
) -> Result<ReceiptResponse, EnclaveError> {
    let provider = state
        .vault
        .providers
        .get(provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;
    let participant = provider
        .participant_pubkey
        .unwrap_or(provider.settlement_token_account);
    let recipient_ata = provider.settlement_token_account;
    drop(provider);

    let free_balance = state
        .vault
        .provider_credits
        .get(provider_id)
        .map(|credit| credit.credited_amount)
        .unwrap_or(0);

    issue_participant_receipt(
        state,
        participant,
        PARTICIPANT_KIND_PROVIDER,
        recipient_ata,
        free_balance,
        0,
        0,
    )
    .await
}

async fn issue_participant_receipt(
    state: &Arc<AppState>,
    participant: Pubkey,
    participant_kind: u8,
    recipient_ata: Pubkey,
    free_balance: u64,
    locked_balance: u64,
    max_lock_expires_at: i64,
) -> Result<ReceiptResponse, EnclaveError> {
    let receipt = {
        let _persist_guard = state.persistence_lock.lock().await;
        let nonce = state.vault.next_receipt_nonce();
        let timestamp = Utc::now().timestamp();
        let snapshot_seqno = state
            .vault
            .snapshot_seqno
            .load(std::sync::atomic::Ordering::SeqCst);
        let receipt_message = state.vault.build_participant_receipt_message(
            &participant,
            participant_kind,
            &recipient_ata,
            free_balance,
            locked_balance,
            max_lock_expires_at,
            nonce,
            timestamp,
            snapshot_seqno,
        );
        let signature = state.vault.sign_message(&receipt_message);

        let receipt = ReceiptResponse {
            ok: true,
            participant: participant.to_string(),
            participant_kind,
            recipient_ata: recipient_ata.to_string(),
            free_balance,
            locked_balance,
            max_lock_expires_at,
            nonce,
            timestamp,
            snapshot_seqno,
            vault_config: state.vault.vault_config.to_string(),
            signature: BASE64.encode(signature),
            message: BASE64.encode(receipt_message),
        };

        state
            .wal
            .append(WalEntry::ParticipantReceiptIssued {
                participant: receipt.participant.clone(),
                participant_kind,
                nonce,
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

        replicate_receipt_to_watchtower(state, &receipt).await?;

        state
            .wal
            .append(WalEntry::ParticipantReceiptMirrored {
                participant: receipt.participant.clone(),
                participant_kind,
                nonce,
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;
        receipt
    };

    info!(
        participant = %receipt.participant,
        participant_kind,
        nonce = receipt.nonce,
        "ParticipantReceipt issued"
    );

    Ok(receipt)
}

async fn replicate_receipt_to_watchtower(
    state: &Arc<AppState>,
    receipt: &ReceiptResponse,
) -> Result<(), EnclaveError> {
    let watchtower_url = state
        .watchtower_url
        .as_ref()
        .ok_or(EnclaveError::ReceiptWatchtowerUnavailable)?;
    let url = format!("{watchtower_url}/v1/receipt/store");
    let response = reqwest::Client::new()
        .post(url)
        .json(receipt)
        .send()
        .await
        .map_err(|e| EnclaveError::Internal(format!("Watchtower replication failed: {e}")))?;

    if !response.status().is_success() {
        return Err(EnclaveError::Internal(format!(
            "Watchtower replication failed with status {}",
            response.status()
        )));
    }

    let body = response
        .json::<WatchtowerStoreReceiptResponse>()
        .await
        .map_err(|e| EnclaveError::Internal(format!("Watchtower response decode failed: {e}")))?;

    if !body.ok || body.current_nonce != receipt.nonce {
        return Err(EnclaveError::Internal(format!(
            "Watchtower rejected receipt nonce {} (stored={}, current_nonce={})",
            receipt.nonce, body.stored, body.current_nonce
        )));
    }

    Ok(())
}

// ── Provider Registration ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterProviderRequest {
    pub provider_id: String,
    pub display_name: String,
    pub participant_pubkey: Option<String>,
    pub settlement_token_account: String,
    pub network: String,
    pub asset_mint: String,
    pub allowed_origins: Vec<String>,
    pub auth_mode: String,
    #[serde(default)]
    pub api_key_hash: String,
    #[serde(default)]
    pub mtls_cert_fingerprint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterProviderResponse {
    pub ok: bool,
    pub provider_id: String,
    pub registered_at: String,
}

pub async fn post_register_provider(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterProviderRequest>,
) -> Result<Json<RegisterProviderResponse>, EnclaveError> {
    let settlement_token_account = Pubkey::from_str(&req.settlement_token_account)
        .map_err(|_| EnclaveError::Internal("Invalid settlement token account".into()))?;
    let participant_pubkey = req
        .participant_pubkey
        .as_deref()
        .map(|value| Pubkey::from_str(value).map_err(|_| EnclaveError::InvalidProviderParticipant))
        .transpose()?;
    let asset_mint = Pubkey::from_str(&req.asset_mint)
        .map_err(|_| EnclaveError::Internal("Invalid asset mint".into()))?;

    let (api_key_hash, mtls_cert_fingerprint) = match req.auth_mode.as_str() {
        "bearer" | "api-key" => {
            let api_key_hash = hex::decode(&req.api_key_hash)
                .map_err(|_| EnclaveError::InvalidProviderAuthConfig)?;
            if api_key_hash.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }
            (Some(api_key_hash), None)
        }
        "mtls" => {
            if !state.provider_mtls_enabled {
                return Err(EnclaveError::MtlsNotEnabled);
            }
            let fingerprint_hex = req
                .mtls_cert_fingerprint
                .as_deref()
                .ok_or(EnclaveError::InvalidProviderAuthConfig)?;
            let fingerprint = hex::decode(fingerprint_hex)
                .map_err(|_| EnclaveError::InvalidProviderAuthConfig)?;
            if fingerprint.len() != 32 {
                return Err(EnclaveError::InvalidProviderAuthConfig);
            }
            (None, Some(fingerprint))
        }
        _ => return Err(EnclaveError::UnsupportedProviderAuthMode),
    };

    let registration = crate::state::ProviderRegistration {
        provider_id: req.provider_id.clone(),
        display_name: req.display_name.clone(),
        participant_pubkey,
        settlement_token_account,
        network: req.network.clone(),
        asset_mint,
        allowed_origins: req.allowed_origins.clone(),
        auth_mode: req.auth_mode.clone(),
        api_key_hash,
        mtls_cert_fingerprint,
    };

    {
        let _persist_guard = state.persistence_lock.lock().await;
        state
            .wal
            .append(WalEntry::ProviderRegistered {
                provider_id: req.provider_id.clone(),
                display_name: req.display_name.clone(),
                participant_pubkey: req.participant_pubkey.clone(),
                settlement_token_account: req.settlement_token_account.clone(),
                network: req.network.clone(),
                asset_mint: req.asset_mint.clone(),
                allowed_origins: req.allowed_origins.clone(),
                auth_mode: req.auth_mode.clone(),
                api_key_hash: if req.api_key_hash.is_empty() {
                    None
                } else {
                    Some(req.api_key_hash.clone())
                },
                mtls_cert_fingerprint: req.mtls_cert_fingerprint.clone(),
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

        state
            .vault
            .providers
            .insert(req.provider_id.clone(), registration);
    }

    let now = Utc::now().to_rfc3339();
    info!(provider_id = %req.provider_id, "Provider registered");

    Ok(Json(RegisterProviderResponse {
        ok: true,
        provider_id: req.provider_id,
        registered_at: now,
    }))
}

// ── Admin (local dev / tests) ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedBalanceRequest {
    pub client: String,
    pub free: u64,
    pub locked: Option<u64>,
    pub max_lock_expires_at: Option<i64>,
    pub total_deposited: Option<u64>,
    pub total_withdrawn: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedBalanceResponse {
    pub ok: bool,
    pub client: String,
    pub free: u64,
    pub locked: u64,
}

pub async fn post_seed_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SeedBalanceRequest>,
) -> Result<Json<SeedBalanceResponse>, EnclaveError> {
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;
    let locked = req.locked.unwrap_or(0);
    let max_lock_expires_at = req.max_lock_expires_at.unwrap_or(0);
    let total_deposited = req
        .total_deposited
        .unwrap_or(req.free.saturating_add(locked));
    let total_withdrawn = req.total_withdrawn.unwrap_or(0);

    {
        let _persist_guard = state.persistence_lock.lock().await;
        state
            .wal
            .append(WalEntry::ClientBalanceSeeded {
                client: req.client.clone(),
                free: req.free,
                locked,
                max_lock_expires_at,
                total_deposited,
                total_withdrawn,
            })
            .await
            .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

        state.vault.client_balances.insert(
            client,
            crate::state::ClientBalance {
                free: req.free,
                locked,
                max_lock_expires_at,
                total_deposited,
                total_withdrawn,
            },
        );
    }

    info!(client = %req.client, free = req.free, locked, "Seeded client balance for local dev");

    Ok(Json(SeedBalanceResponse {
        ok: true,
        client: req.client,
        free: req.free,
        locked,
    }))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FireBatchRequest {}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FireBatchResponse {
    pub ok: bool,
    pub submitted: bool,
    pub batch_id: Option<u64>,
    pub provider_count: usize,
    pub settlement_count: usize,
    pub total_amount: u64,
    pub tx_signatures: Vec<String>,
}

pub async fn post_fire_batch(
    State(state): State<Arc<AppState>>,
    Json(_req): Json<FireBatchRequest>,
) -> Result<Json<FireBatchResponse>, EnclaveError> {
    let result = batch::fire_batch_now(&state)
        .await
        .map_err(|error| EnclaveError::Internal(format!("fire_batch failed: {error}")))?;

    Ok(Json(FireBatchResponse {
        ok: true,
        submitted: result.submitted,
        batch_id: result.batch_id,
        provider_count: result.provider_count,
        settlement_count: result.settlement_count,
        total_amount: result.total_amount,
        tx_signatures: result.tx_signatures,
    }))
}

// ── Helper functions ──

fn compute_request_hash(ctx: &RequestContext, payment_details_hash: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"A402-SVM-V1-REQ\n");
    hasher.update(ctx.method.as_bytes());
    hasher.update(b"\n");
    hasher.update(ctx.origin.as_bytes());
    hasher.update(b"\n");
    hasher.update(ctx.path_and_query.as_bytes());
    hasher.update(b"\n");
    hasher.update(ctx.body_sha256.as_bytes());
    hasher.update(b"\n");
    hasher.update(payment_details_hash.as_bytes());
    hasher.update(b"\n");
    hasher.finalize().to_vec()
}

fn verify_client_signature(payload: &PaymentPayload) -> Result<(), EnclaveError> {
    // Build signature message per spec
    let mut message = String::new();
    message.push_str("A402-SVM-V1-AUTH\n");
    message.push_str(&format!("{}\n", payload.version));
    message.push_str(&format!("{}\n", payload.scheme));
    message.push_str(&format!("{}\n", payload.payment_id));
    message.push_str(&format!("{}\n", payload.client));
    message.push_str(&format!("{}\n", payload.vault));
    message.push_str(&format!("{}\n", payload.provider_id));
    message.push_str(&format!("{}\n", payload.pay_to));
    message.push_str(&format!("{}\n", payload.network));
    message.push_str(&format!("{}\n", payload.asset_mint));
    message.push_str(&format!("{}\n", payload.amount));
    message.push_str(&format!("{}\n", payload.request_hash));
    message.push_str(&format!("{}\n", payload.payment_details_hash));
    message.push_str(&format!("{}\n", payload.expires_at));
    message.push_str(&format!("{}\n", payload.nonce));

    let client_pubkey =
        Pubkey::from_str(&payload.client).map_err(|_| EnclaveError::InvalidClientSignature)?;
    verify_ed25519_signature(&client_pubkey, message.as_bytes(), &payload.client_sig)
}

fn verify_channel_open_signature(req: &OpenChannelRequest) -> Result<(), EnclaveError> {
    let client_pubkey =
        Pubkey::from_str(&req.client).map_err(|_| EnclaveError::InvalidClientSignature)?;
    let message = build_channel_open_message(&req.client, &req.provider_id, req.initial_deposit);
    verify_ed25519_signature(&client_pubkey, message.as_bytes(), &req.client_sig)
}

fn verify_ed25519_signature(
    signer: &Pubkey,
    message: &[u8],
    signature_b64: &str,
) -> Result<(), EnclaveError> {
    let verifying_key = VerifyingKey::from_bytes(&signer.to_bytes())
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    let sig_bytes = BASE64
        .decode(signature_b64)
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EnclaveError::InvalidClientSignature)?,
    );

    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    Ok(())
}

fn verify_channel_client_signature(
    state: &AppState,
    channel_id: &str,
    message: &str,
    client_sig: &str,
) -> Result<(), EnclaveError> {
    let client = state
        .vault
        .active_channels
        .get(channel_id)
        .map(|channel| channel.client)
        .ok_or(EnclaveError::ChannelNotFound)?;

    verify_ed25519_signature(&client, message.as_bytes(), client_sig)
}

fn verify_channel_provider_auth(
    state: &AppState,
    channel_id: &str,
    headers: &HeaderMap,
) -> Result<(), EnclaveError> {
    let provider_id = state
        .vault
        .active_channels
        .get(channel_id)
        .map(|channel| channel.provider_id.clone())
        .ok_or(EnclaveError::ChannelNotFound)?;

    let provider = state
        .vault
        .providers
        .get(&provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;
    authenticate_registered_provider(provider.value(), headers)
}

fn build_channel_open_message(client: &str, provider_id: &str, initial_deposit: u64) -> String {
    format!(
        "A402-CHANNEL-OPEN\n{}\n{}\n{}\n",
        client, provider_id, initial_deposit
    )
}

fn build_channel_request_message(
    channel_id: &str,
    request_id: &str,
    amount: u64,
    request_hash: &str,
) -> String {
    format!(
        "A402-CHANNEL-REQUEST\n{}\n{}\n{}\n{}\n",
        channel_id, request_id, amount, request_hash
    )
}

fn build_channel_finalize_message(channel_id: &str, adaptor_secret: &str) -> String {
    format!(
        "A402-CHANNEL-FINALIZE\n{}\n{}\n",
        channel_id, adaptor_secret
    )
}

fn build_channel_close_message(channel_id: &str) -> String {
    format!("A402-CHANNEL-CLOSE\n{}\n", channel_id)
}

// ── Phase 3: Atomic Service Channel Endpoints ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenChannelRequest {
    pub client: String,
    pub provider_id: String,
    pub initial_deposit: u64,
    /// Ed25519 signature over "A402-CHANNEL-OPEN\n{client}\n{provider_id}\n{initial_deposit}\n"
    pub client_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenChannelResponse {
    pub ok: bool,
    pub channel_id: String,
    pub client_free: u64,
    pub client_locked: u64,
}

pub async fn post_channel_open(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenChannelRequest>,
) -> Result<Json<OpenChannelResponse>, EnclaveError> {
    ensure_vault_allows_new_verification(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    let client = Pubkey::from_str(&req.client).map_err(|_| EnclaveError::ClientNotFound)?;

    // Verify client signature
    verify_channel_open_signature(&req)?;

    let channel_id =
        asc_manager::open_channel(&state.vault, &client, &req.provider_id, req.initial_deposit)?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelOpened {
            channel_id: channel_id.clone(),
            client: req.client.clone(),
            provider_id: req.provider_id.clone(),
            initial_deposit: req.initial_deposit,
        })
        .await
    {
        let _ = asc_manager::rollback_open_channel(&state.vault, &channel_id);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }

    Ok(Json(OpenChannelResponse {
        ok: true,
        channel_id,
        client_free: req.initial_deposit,
        client_locked: 0,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRequestReq {
    pub channel_id: String,
    pub request_id: String,
    pub amount: u64,
    pub request_hash: String,
    pub client_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelRequestResponse {
    pub ok: bool,
    pub channel_id: String,
    pub request_id: String,
    pub status: String,
}

pub async fn post_channel_request(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChannelRequestReq>,
) -> Result<Json<ChannelRequestResponse>, EnclaveError> {
    ensure_vault_allows_new_verification(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    let message = build_channel_request_message(
        &req.channel_id,
        &req.request_id,
        req.amount,
        &req.request_hash,
    );
    verify_channel_client_signature(&state, &req.channel_id, &message, &req.client_sig)?;

    let request_hash: [u8; 32] = hex::decode(&req.request_hash)
        .map_err(|_| EnclaveError::RequestHashMismatch)?
        .try_into()
        .map_err(|_| EnclaveError::RequestHashMismatch)?;

    asc_manager::submit_request(
        &state.vault,
        &req.channel_id,
        &req.request_id,
        req.amount,
        request_hash,
    )?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelRequestSubmitted {
            channel_id: req.channel_id.clone(),
            request_id: req.request_id.clone(),
            amount: req.amount,
            request_hash: Some(req.request_hash.clone()),
        })
        .await
    {
        let _ =
            asc_manager::rollback_submit_request(&state.vault, &req.channel_id, &req.request_id);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }

    Ok(Json(ChannelRequestResponse {
        ok: true,
        channel_id: req.channel_id,
        request_id: req.request_id,
        status: "locked".to_string(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDeliverRequest {
    pub channel_id: String,
    pub adaptor_point: String,
    pub pre_sig_r_prime: String,
    pub pre_sig_s_prime: String,
    pub encrypted_result: String,
    pub result_hash: String,
    pub provider_pubkey: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDeliverResponse {
    pub ok: bool,
    pub channel_id: String,
    pub status: String,
}

pub async fn post_channel_deliver(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ChannelDeliverRequest>,
) -> Result<Json<ChannelDeliverResponse>, EnclaveError> {
    ensure_vault_allows_existing_reservation_ops(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    verify_channel_provider_auth(&state, &req.channel_id, &headers)?;

    let adaptor_point: [u8; 32] = hex::decode(&req.adaptor_point)
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?
        .try_into()
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?;

    let r_prime: [u8; 32] = hex::decode(&req.pre_sig_r_prime)
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?
        .try_into()
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?;

    let s_prime: [u8; 32] = hex::decode(&req.pre_sig_s_prime)
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?
        .try_into()
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?;

    let pre_sig = AdaptorPreSignature { r_prime, s_prime };

    let encrypted_result = BASE64
        .decode(&req.encrypted_result)
        .map_err(|_| EnclaveError::Internal("Invalid encrypted_result base64".into()))?;

    let result_hash: [u8; 32] = hex::decode(&req.result_hash)
        .map_err(|_| EnclaveError::Internal("Invalid result_hash hex".into()))?
        .try_into()
        .map_err(|_| EnclaveError::Internal("result_hash must be 32 bytes".into()))?;

    let provider_pubkey: [u8; 32] = hex::decode(&req.provider_pubkey)
        .map_err(|_| EnclaveError::Internal("Invalid provider_pubkey hex".into()))?
        .try_into()
        .map_err(|_| EnclaveError::Internal("provider_pubkey must be 32 bytes".into()))?;

    let request_id = state
        .vault
        .active_channels
        .get(&req.channel_id)
        .and_then(|channel| {
            channel
                .active_request
                .as_ref()
                .map(|request| request.request_id.clone())
        })
        .ok_or(EnclaveError::ChannelNotFound)?;

    asc_manager::deliver_adaptor(
        &state.vault,
        &req.channel_id,
        adaptor_point,
        pre_sig,
        encrypted_result,
        result_hash,
        &provider_pubkey,
    )?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelAdaptorDelivered {
            channel_id: req.channel_id.clone(),
            request_id: request_id.clone(),
            adaptor_point: Some(req.adaptor_point.clone()),
            pre_sig_r_prime: Some(req.pre_sig_r_prime.clone()),
            pre_sig_s_prime: Some(req.pre_sig_s_prime.clone()),
            encrypted_result: Some(req.encrypted_result.clone()),
            result_hash: Some(req.result_hash.clone()),
            provider_pubkey: Some(req.provider_pubkey.clone()),
        })
        .await
    {
        let _ = asc_manager::rollback_deliver_adaptor(&state.vault, &req.channel_id, &request_id);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }

    Ok(Json(ChannelDeliverResponse {
        ok: true,
        channel_id: req.channel_id,
        status: "pending".to_string(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelFinalizeRequest {
    pub channel_id: String,
    pub adaptor_secret: String,
    pub client_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelFinalizeResponse {
    pub ok: bool,
    pub channel_id: String,
    pub result: String,
    pub amount_paid: u64,
    pub status: String,
}

pub async fn post_channel_finalize(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ChannelFinalizeRequest>,
) -> Result<Json<ChannelFinalizeResponse>, EnclaveError> {
    ensure_vault_allows_existing_reservation_ops(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    let message = build_channel_finalize_message(&req.channel_id, &req.adaptor_secret);
    verify_channel_client_signature(&state, &req.channel_id, &message, &req.client_sig)?;

    let adaptor_secret: [u8; 32] = hex::decode(&req.adaptor_secret)
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?
        .try_into()
        .map_err(|_| EnclaveError::InvalidAdaptorSignature)?;

    let outcome = asc_manager::finalize_offchain(&state.vault, &req.channel_id, adaptor_secret)?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelFinalized {
            channel_id: req.channel_id.clone(),
            request_id: outcome.request_id.clone(),
            amount_paid: outcome.amount,
        })
        .await
    {
        let _ = asc_manager::rollback_finalize_offchain(
            &state.vault,
            &req.channel_id,
            outcome.request.clone(),
        );
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }

    Ok(Json(ChannelFinalizeResponse {
        ok: true,
        channel_id: req.channel_id,
        result: BASE64.encode(&outcome.result_bytes),
        amount_paid: outcome.amount,
        status: "open".to_string(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseChannelRequest {
    pub channel_id: String,
    pub client_sig: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseChannelResponse {
    pub ok: bool,
    pub channel_id: String,
    pub provider_id: String,
    pub returned_to_client: u64,
    pub provider_earned: u64,
}

pub async fn post_channel_close(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CloseChannelRequest>,
) -> Result<Json<CloseChannelResponse>, EnclaveError> {
    ensure_vault_allows_existing_reservation_ops(&state).await?;

    let _guard = state.asc_ops_lock.lock().await;
    let _persist_guard = state.persistence_lock.lock().await;
    let message = build_channel_close_message(&req.channel_id);
    verify_channel_client_signature(&state, &req.channel_id, &message, &req.client_sig)?;

    let outcome = asc_manager::close_channel(&state.vault, &req.channel_id)?;

    if let Err(error) = state
        .wal
        .append(WalEntry::ChannelClosed {
            channel_id: req.channel_id.clone(),
            returned_to_client: outcome.returned_to_client,
            provider_earned: outcome.provider_earned,
            settlement_id: outcome.settlement_id.clone(),
        })
        .await
    {
        let _ = asc_manager::rollback_close_channel(&state.vault, outcome);
        return Err(EnclaveError::Internal(format!(
            "WAL append failed: {error}"
        )));
    }

    Ok(Json(CloseChannelResponse {
        ok: true,
        channel_id: req.channel_id,
        provider_id: outcome.provider_id,
        returned_to_client: outcome.returned_to_client,
        provider_earned: outcome.provider_earned,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptor_sig::{self, AdaptorKeyPair};
    use crate::state::{SolanaRuntimeConfig, VaultState};
    use crate::wal::{self, Wal};
    use axum::http::{header::AUTHORIZATION, HeaderName, HeaderValue};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use solana_sdk::pubkey::Pubkey;
    use std::path::PathBuf;

    fn sign_text_message(signing_key: &SigningKey, message: &str) -> String {
        use ed25519_dalek::Signer;
        BASE64.encode(signing_key.sign(message.as_bytes()).to_bytes())
    }

    fn sign_payment_payload(signing_key: &SigningKey, payload: &PaymentPayload) -> String {
        use ed25519_dalek::Signer;

        let mut message = String::new();
        message.push_str("A402-SVM-V1-AUTH\n");
        message.push_str(&format!("{}\n", payload.version));
        message.push_str(&format!("{}\n", payload.scheme));
        message.push_str(&format!("{}\n", payload.payment_id));
        message.push_str(&format!("{}\n", payload.client));
        message.push_str(&format!("{}\n", payload.vault));
        message.push_str(&format!("{}\n", payload.provider_id));
        message.push_str(&format!("{}\n", payload.pay_to));
        message.push_str(&format!("{}\n", payload.network));
        message.push_str(&format!("{}\n", payload.asset_mint));
        message.push_str(&format!("{}\n", payload.amount));
        message.push_str(&format!("{}\n", payload.request_hash));
        message.push_str(&format!("{}\n", payload.payment_details_hash));
        message.push_str(&format!("{}\n", payload.expires_at));
        message.push_str(&format!("{}\n", payload.nonce));

        BASE64.encode(signing_key.sign(message.as_bytes()).to_bytes())
    }

    async fn make_app_state_with_mtls(provider_mtls_enabled: bool) -> (Arc<AppState>, PathBuf) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let usdc_mint = Pubkey::new_unique();
        let solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let vault = Arc::new(VaultState::new(
            Pubkey::new_unique(),
            signing_key,
            usdc_mint,
            [0u8; 32],
            solana.clone(),
        ));
        let wal_path =
            std::env::temp_dir().join(format!("a402-phase3-{}.jsonl", uuid::Uuid::now_v7()));
        let wal = Arc::new(Wal::new(wal_path.clone()).await);
        let detector = Arc::new(DepositDetector::new(
            solana.vault_token_account,
            solana.program_id,
            solana.rpc_url,
            solana.ws_url,
        ));

        (
            Arc::new(AppState {
                vault,
                wal,
                deposit_detector: detector,
                asc_ops_lock: Mutex::new(()),
                persistence_lock: Mutex::new(()),
                watchtower_url: None,
                attestation_document: String::new(),
                attestation_is_local_dev: true,
                provider_mtls_enabled,
            }),
            wal_path,
        )
    }

    async fn make_app_state() -> (Arc<AppState>, PathBuf) {
        make_app_state_with_mtls(false).await
    }

    #[tokio::test]
    async fn register_provider_rejects_mtls_when_listener_disabled() {
        let (state, wal_path) = make_app_state().await;

        let error = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: "provider-mtls-disabled".to_string(),
                display_name: "mTLS Provider".to_string(),
                participant_pubkey: None,
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "mtls".to_string(),
                api_key_hash: String::new(),
                mtls_cert_fingerprint: Some("ab".repeat(32)),
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(error, EnclaveError::MtlsNotEnabled));
        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn verify_accepts_mtls_provider_with_matching_client_certificate_fingerprint() {
        let (state, wal_path) = make_app_state_with_mtls(true).await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-mtls".to_string();
        let settlement_token_account = Pubkey::new_unique();
        let asset_mint = Pubkey::new_unique();
        let fingerprint_hex = "cd".repeat(32);

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "mTLS Provider".to_string(),
                participant_pubkey: None,
                settlement_token_account: settlement_token_account.to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: asset_mint.to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "mtls".to_string(),
                api_key_hash: String::new(),
                mtls_cert_fingerprint: Some(fingerprint_hex.clone()),
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 2_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(2_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        state
            .deposit_detector
            .is_synced
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let request_context = RequestContext {
            method: "POST".to_string(),
            origin: "http://localhost".to_string(),
            path_and_query: "/demo".to_string(),
            body_sha256: "11".repeat(32),
        };
        let payment_details = serde_json::json!({
            "scheme": "a402-svm-v1",
            "network": "solana:localnet",
            "amount": "600000",
            "asset": {
                "kind": "spl-token",
                "mint": asset_mint.to_string(),
                "decimals": 6,
                "symbol": "USDC",
            },
            "payTo": settlement_token_account.to_string(),
            "providerId": provider_id,
            "facilitatorUrl": "https://localhost:3100/v1",
            "vault": {
                "config": state.vault.vault_config.to_string(),
                "signer": state.vault.vault_signer_pubkey.to_string(),
                "attestationPolicyHash": hex::encode(state.vault.attestation_policy_hash),
            },
            "paymentDetailsId": "paydet_test_mtls",
            "verifyWindowSec": 60,
            "maxSettlementDelaySec": 900,
            "privacyMode": "vault-batched-v1",
        });
        let payment_details_hash = hex::encode(compute_payment_details_hash(&payment_details));
        let request_hash = hex::encode(compute_request_hash(&request_context, &payment_details_hash));

        let mut payment_payload = PaymentPayload {
            version: 1,
            scheme: "a402-svm-v1".to_string(),
            payment_id: "pay_mtls_test".to_string(),
            client: client.to_string(),
            vault: state.vault.vault_config.to_string(),
            provider_id: "provider-mtls".to_string(),
            pay_to: settlement_token_account.to_string(),
            network: "solana:localnet".to_string(),
            asset_mint: asset_mint.to_string(),
            amount: "600000".to_string(),
            request_hash,
            payment_details_hash,
            expires_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            nonce: "1".to_string(),
            client_sig: String::new(),
        };
        payment_payload.client_sig = sign_payment_payload(&client_signing_key, &payment_payload);

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_static("provider-mtls"),
        );
        headers.insert(
            HeaderName::from_static(INTERNAL_MTLS_FINGERPRINT_HEADER),
            HeaderValue::from_str(&fingerprint_hex).unwrap(),
        );

        let response = post_verify(
            State(state.clone()),
            headers,
            Json(VerifyRequest {
                payment_payload,
                payment_details: Some(payment_details),
                request_context,
            }),
        )
        .await
        .unwrap();

        assert!(response.0.ok);
        assert_eq!(response.0.provider_id, "provider-mtls");
        assert!(!response.0.verification_receipt.is_empty());

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_api_flow_requires_auth_and_records_request_id() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: None,
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let open_res = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: provider_id.clone(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .unwrap();
        let channel_id = open_res.0.channel_id.clone();

        let request_hash_hex = "ab".repeat(32);
        let request_message =
            build_channel_request_message(&channel_id, "req-123", 1_250_000, &request_hash_hex);
        let _ = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-123".to_string(),
                amount: 1_250_000,
                request_hash: request_hash_hex.clone(),
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .unwrap();

        let provider_signing_key = SigningKey::generate(&mut OsRng);
        let provider_pubkey = provider_signing_key.verifying_key().to_bytes();
        let adaptor = AdaptorKeyPair::generate();
        let payment_message = format!(
            "{}:{}:{}:{}",
            channel_id, "req-123", 1_250_000, request_hash_hex
        );
        let pre_sig = adaptor_sig::pre_sign(
            &provider_signing_key.to_bytes(),
            payment_message.as_bytes(),
            &adaptor.public,
        );
        let plaintext = br#"{"ok":true,"payload":"phase3"}"#.to_vec();
        let encrypted_result =
            crate::asc_manager::encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());
        let result_hash = hex::encode(Sha256::digest(&plaintext));

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let _ = post_channel_deliver(
            State(state.clone()),
            headers,
            Json(ChannelDeliverRequest {
                channel_id: channel_id.clone(),
                adaptor_point: hex::encode(adaptor.public_compressed),
                pre_sig_r_prime: hex::encode(pre_sig.r_prime),
                pre_sig_s_prime: hex::encode(pre_sig.s_prime),
                encrypted_result: BASE64.encode(&encrypted_result),
                result_hash,
                provider_pubkey: hex::encode(provider_pubkey),
            }),
        )
        .await
        .unwrap();

        let finalize_secret = hex::encode(adaptor.secret.to_bytes());
        let finalize_message = build_channel_finalize_message(&channel_id, &finalize_secret);
        let finalize_res = post_channel_finalize(
            State(state.clone()),
            Json(ChannelFinalizeRequest {
                channel_id: channel_id.clone(),
                adaptor_secret: finalize_secret,
                client_sig: sign_text_message(&client_signing_key, &finalize_message),
            }),
        )
        .await
        .unwrap();
        assert_eq!(BASE64.decode(finalize_res.0.result).unwrap(), plaintext);
        assert_eq!(finalize_res.0.amount_paid, 1_250_000);

        let close_message = build_channel_close_message(&channel_id);
        let close_res = post_channel_close(
            State(state.clone()),
            Json(CloseChannelRequest {
                channel_id: channel_id.clone(),
                client_sig: sign_text_message(&client_signing_key, &close_message),
            }),
        )
        .await
        .unwrap();
        assert_eq!(close_res.0.returned_to_client, 1_750_000);
        assert_eq!(close_res.0.provider_earned, 1_250_000);

        let wal_records = state.wal.read_records().await.unwrap();
        assert!(wal_records.iter().any(|record| {
            matches!(
                &record.entry,
                WalEntry::ChannelFinalized {
                    request_id,
                    amount_paid,
                    ..
                } if request_id == "req-123" && *amount_paid == 1_250_000
            )
        }));

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_request_id_cannot_be_reused_after_finalize() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3-reuse".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: None,
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "api-key".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let open_res = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: provider_id.clone(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .unwrap();
        let channel_id = open_res.0.channel_id;

        let request_hash_hex = "cd".repeat(32);
        let request_message =
            build_channel_request_message(&channel_id, "req-reuse", 1_000_000, &request_hash_hex);
        let _ = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-reuse".to_string(),
                amount: 1_000_000,
                request_hash: request_hash_hex.clone(),
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .unwrap();

        let provider_signing_key = SigningKey::generate(&mut OsRng);
        let adaptor = AdaptorKeyPair::generate();
        let pre_sig = adaptor_sig::pre_sign(
            &provider_signing_key.to_bytes(),
            format!(
                "{channel_id}:{}:{}:{request_hash_hex}",
                "req-reuse", 1_000_000
            )
            .as_bytes(),
            &adaptor.public,
        );
        let plaintext = br#"{"ok":true,"payload":"phase3"}"#.to_vec();
        let encrypted_result =
            crate::asc_manager::encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());

        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-a402-provider-auth"),
            HeaderValue::from_str(provider_api_key).unwrap(),
        );

        let _ = post_channel_deliver(
            State(state.clone()),
            headers,
            Json(ChannelDeliverRequest {
                channel_id: channel_id.clone(),
                adaptor_point: hex::encode(adaptor.public_compressed),
                pre_sig_r_prime: hex::encode(pre_sig.r_prime),
                pre_sig_s_prime: hex::encode(pre_sig.s_prime),
                encrypted_result: BASE64.encode(&encrypted_result),
                result_hash: hex::encode(Sha256::digest(&plaintext)),
                provider_pubkey: hex::encode(provider_signing_key.verifying_key().to_bytes()),
            }),
        )
        .await
        .unwrap();

        let finalize_secret = hex::encode(adaptor.secret.to_bytes());
        let finalize_message = build_channel_finalize_message(&channel_id, &finalize_secret);
        let _ = post_channel_finalize(
            State(state.clone()),
            Json(ChannelFinalizeRequest {
                channel_id: channel_id.clone(),
                adaptor_secret: finalize_secret,
                client_sig: sign_text_message(&client_signing_key, &finalize_message),
            }),
        )
        .await
        .unwrap();

        let reuse_err = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-reuse".to_string(),
                amount: 1_000_000,
                request_hash: request_hash_hex,
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .err()
        .unwrap();
        assert!(matches!(reuse_err, EnclaveError::ChannelRequestIdReused));

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn wal_replay_restores_pending_channel_and_allows_finalize() {
        let (state, wal_path) = make_app_state().await;
        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        let provider_id = "provider-phase3-replay".to_string();
        let provider_api_key = "phase3-provider-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));

        let _ = post_register_provider(
            State(state.clone()),
            Json(RegisterProviderRequest {
                provider_id: provider_id.clone(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: None,
                settlement_token_account: Pubkey::new_unique().to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique().to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: provider_api_key_hash,
                mtls_cert_fingerprint: None,
            }),
        )
        .await
        .unwrap();

        let _ = post_seed_balance(
            State(state.clone()),
            Json(SeedBalanceRequest {
                client: client.to_string(),
                free: 5_000_000,
                locked: Some(0),
                max_lock_expires_at: Some(0),
                total_deposited: Some(5_000_000),
                total_withdrawn: Some(0),
            }),
        )
        .await
        .unwrap();

        let open_message = build_channel_open_message(&client.to_string(), &provider_id, 3_000_000);
        let open_res = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: provider_id.clone(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .unwrap();
        let channel_id = open_res.0.channel_id;

        let request_hash_hex = "ef".repeat(32);
        let request_message =
            build_channel_request_message(&channel_id, "req-replay", 1_250_000, &request_hash_hex);
        let _ = post_channel_request(
            State(state.clone()),
            Json(ChannelRequestReq {
                channel_id: channel_id.clone(),
                request_id: "req-replay".to_string(),
                amount: 1_250_000,
                request_hash: request_hash_hex.clone(),
                client_sig: sign_text_message(&client_signing_key, &request_message),
            }),
        )
        .await
        .unwrap();

        let provider_signing_key = SigningKey::generate(&mut OsRng);
        let adaptor = AdaptorKeyPair::generate();
        let pre_sig = adaptor_sig::pre_sign(
            &provider_signing_key.to_bytes(),
            format!(
                "{channel_id}:{}:{}:{request_hash_hex}",
                "req-replay", 1_250_000
            )
            .as_bytes(),
            &adaptor.public,
        );
        let plaintext = br#"{"ok":true,"payload":"phase3-replay"}"#.to_vec();
        let encrypted_result =
            crate::asc_manager::encrypt_with_scalar(&plaintext, &adaptor.secret.to_bytes());

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let _ = post_channel_deliver(
            State(state.clone()),
            headers,
            Json(ChannelDeliverRequest {
                channel_id: channel_id.clone(),
                adaptor_point: hex::encode(adaptor.public_compressed),
                pre_sig_r_prime: hex::encode(pre_sig.r_prime),
                pre_sig_s_prime: hex::encode(pre_sig.s_prime),
                encrypted_result: BASE64.encode(&encrypted_result),
                result_hash: hex::encode(Sha256::digest(&plaintext)),
                provider_pubkey: hex::encode(provider_signing_key.verifying_key().to_bytes()),
            }),
        )
        .await
        .unwrap();

        let replay_signing_key = SigningKey::generate(&mut OsRng);
        let replay_solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let replay_state = Arc::new(AppState {
            vault: Arc::new(VaultState::new(
                Pubkey::new_unique(),
                replay_signing_key,
                Pubkey::new_unique(),
                [0u8; 32],
                replay_solana.clone(),
            )),
            wal: Arc::new(Wal::new(wal_path.clone()).await),
            deposit_detector: Arc::new(DepositDetector::new(
                replay_solana.vault_token_account,
                replay_solana.program_id,
                replay_solana.rpc_url,
                replay_solana.ws_url,
            )),
            asc_ops_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
        });

        wal::replay_app_state(&replay_state).await.unwrap();

        let replay_channel = replay_state.vault.active_channels.get(&channel_id).unwrap();
        assert_eq!(replay_channel.status, crate::state::ChannelStatus::Pending);
        assert_eq!(
            replay_channel
                .active_request
                .as_ref()
                .map(|request| request.request_id.as_str()),
            Some("req-replay")
        );
        drop(replay_channel);

        let finalize_secret = hex::encode(adaptor.secret.to_bytes());
        let finalize_message = build_channel_finalize_message(&channel_id, &finalize_secret);
        let finalize_res = post_channel_finalize(
            State(replay_state.clone()),
            Json(ChannelFinalizeRequest {
                channel_id: channel_id.clone(),
                adaptor_secret: finalize_secret,
                client_sig: sign_text_message(&client_signing_key, &finalize_message),
            }),
        )
        .await
        .unwrap();
        assert_eq!(BASE64.decode(finalize_res.0.result).unwrap(), plaintext);

        let close_message = build_channel_close_message(&channel_id);
        let close_res = post_channel_close(
            State(replay_state.clone()),
            Json(CloseChannelRequest {
                channel_id: channel_id.clone(),
                client_sig: sign_text_message(&client_signing_key, &close_message),
            }),
        )
        .await
        .unwrap();
        assert_eq!(close_res.0.returned_to_client, 1_750_000);
        assert_eq!(close_res.0.provider_earned, 1_250_000);

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn channel_open_rolls_back_when_wal_append_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let usdc_mint = Pubkey::new_unique();
        let solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let vault = Arc::new(VaultState::new(
            Pubkey::new_unique(),
            signing_key,
            usdc_mint,
            [0u8; 32],
            solana.clone(),
        ));
        let wal_path =
            std::env::temp_dir().join(format!("a402-phase3-dir-{}", uuid::Uuid::now_v7()));
        tokio::fs::create_dir_all(&wal_path).await.unwrap();
        let state = Arc::new(AppState {
            vault: vault.clone(),
            wal: Arc::new(Wal::new(wal_path.clone()).await),
            deposit_detector: Arc::new(DepositDetector::new(
                solana.vault_token_account,
                solana.program_id,
                solana.rpc_url,
                solana.ws_url,
            )),
            asc_ops_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
        });

        let client_signing_key = SigningKey::generate(&mut OsRng);
        let client = Pubkey::new_from_array(client_signing_key.verifying_key().to_bytes());
        state.vault.providers.insert(
            "provider-phase3".to_string(),
            crate::state::ProviderRegistration {
                provider_id: "provider-phase3".to_string(),
                display_name: "Phase3 Provider".to_string(),
                participant_pubkey: None,
                settlement_token_account: Pubkey::new_unique(),
                network: "solana:localnet".to_string(),
                asset_mint: Pubkey::new_unique(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "api-key".to_string(),
                api_key_hash: Some(Sha256::digest(b"secret").to_vec()),
                mtls_cert_fingerprint: None,
            },
        );
        state.vault.client_balances.insert(
            client,
            crate::state::ClientBalance {
                free: 5_000_000,
                locked: 0,
                max_lock_expires_at: 0,
                total_deposited: 5_000_000,
                total_withdrawn: 0,
            },
        );

        let open_message =
            build_channel_open_message(&client.to_string(), "provider-phase3", 3_000_000);
        let error = post_channel_open(
            State(state.clone()),
            Json(OpenChannelRequest {
                client: client.to_string(),
                provider_id: "provider-phase3".to_string(),
                initial_deposit: 3_000_000,
                client_sig: sign_text_message(&client_signing_key, &open_message),
            }),
        )
        .await
        .err()
        .unwrap();

        assert!(matches!(error, EnclaveError::Internal(_)));
        assert!(state.vault.active_channels.is_empty());
        let balance = state.vault.client_balances.get(&client).unwrap();
        assert_eq!(balance.free, 5_000_000);
        assert_eq!(balance.locked, 0);

        let _ = tokio::fs::remove_dir_all(wal_path).await;
    }

    #[tokio::test]
    async fn wal_replay_restores_receipt_nonce() {
        let (state, wal_path) = make_app_state().await;
        state
            .wal
            .append(WalEntry::ParticipantReceiptIssued {
                participant: Pubkey::new_unique().to_string(),
                participant_kind: PARTICIPANT_KIND_CLIENT,
                nonce: 7,
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::ParticipantReceiptMirrored {
                participant: Pubkey::new_unique().to_string(),
                participant_kind: PARTICIPANT_KIND_PROVIDER,
                nonce: 7,
            })
            .await
            .unwrap();

        let replay_signing_key = SigningKey::generate(&mut OsRng);
        let replay_solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let replay_state = Arc::new(AppState {
            vault: Arc::new(VaultState::new(
                Pubkey::new_unique(),
                replay_signing_key,
                Pubkey::new_unique(),
                [0u8; 32],
                replay_solana.clone(),
            )),
            wal: Arc::new(Wal::new(wal_path.clone()).await),
            deposit_detector: Arc::new(DepositDetector::new(
                replay_solana.vault_token_account,
                replay_solana.program_id,
                replay_solana.rpc_url,
                replay_solana.ws_url,
            )),
            asc_ops_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
        });

        wal::replay_app_state(&replay_state).await.unwrap();
        assert_eq!(replay_state.vault.next_receipt_nonce(), 8);

        let _ = tokio::fs::remove_file(wal_path).await;
    }

    #[tokio::test]
    async fn wal_replay_restores_batched_settlement_lookup_state() {
        let (state, wal_path) = make_app_state().await;
        let client = Pubkey::new_unique();
        let provider_id = "provider-replay-batch".to_string();
        let provider_api_key = "provider-replay-batch-secret";
        let provider_api_key_hash = hex::encode(Sha256::digest(provider_api_key.as_bytes()));
        let provider_settlement_account = Pubkey::new_unique();
        let asset_mint = Pubkey::new_unique();

        state
            .wal
            .append(WalEntry::ProviderRegistered {
                provider_id: provider_id.clone(),
                display_name: "Replay Batch Provider".to_string(),
                participant_pubkey: None,
                settlement_token_account: provider_settlement_account.to_string(),
                network: "solana:localnet".to_string(),
                asset_mint: asset_mint.to_string(),
                allowed_origins: vec!["http://localhost".to_string()],
                auth_mode: "bearer".to_string(),
                api_key_hash: Some(provider_api_key_hash.clone()),
                mtls_cert_fingerprint: None,
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::ClientBalanceSeeded {
                client: client.to_string(),
                free: 2_000_000,
                locked: 0,
                max_lock_expires_at: 0,
                total_deposited: 2_000_000,
                total_withdrawn: 0,
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::ReservationCreated {
                verification_id: "ver_replay_batch".to_string(),
                reservation_id: Some("res_replay_batch".to_string()),
                payment_id: "pay_replay_batch".to_string(),
                client: client.to_string(),
                provider_id: provider_id.clone(),
                amount: 600_000,
                request_hash: Some("11".repeat(32)),
                payment_details_hash: Some("22".repeat(32)),
                created_at: Some(1_700_000_000),
                expires_at: Some(1_700_000_060),
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::SettlementCommitted {
                settlement_id: "set_replay_batch".to_string(),
                verification_id: "ver_replay_batch".to_string(),
                provider_id: provider_id.clone(),
                amount: 600_000,
                settled_at: Some(1_700_000_010),
            })
            .await
            .unwrap();
        state
            .wal
            .append(WalEntry::BatchConfirmed {
                batch_id: 7,
                tx_signature: "txsig_replay_batch".to_string(),
                settlement_ids: vec!["set_replay_batch".to_string()],
            })
            .await
            .unwrap();

        let replay_signing_key = SigningKey::generate(&mut OsRng);
        let replay_solana = SolanaRuntimeConfig {
            program_id: Pubkey::new_unique(),
            vault_token_account: Pubkey::new_unique(),
            rpc_url: "http://localhost:8899".to_string(),
            ws_url: "ws://localhost:8900".to_string(),
        };
        let replay_state = Arc::new(AppState {
            vault: Arc::new(VaultState::new(
                Pubkey::new_unique(),
                replay_signing_key,
                Pubkey::new_unique(),
                [0u8; 32],
                replay_solana.clone(),
            )),
            wal: Arc::new(Wal::new(wal_path.clone()).await),
            deposit_detector: Arc::new(DepositDetector::new(
                replay_solana.vault_token_account,
                replay_solana.program_id,
                replay_solana.rpc_url,
                replay_solana.ws_url,
            )),
            asc_ops_lock: Mutex::new(()),
            persistence_lock: Mutex::new(()),
            watchtower_url: None,
            attestation_document: String::new(),
            attestation_is_local_dev: true,
            provider_mtls_enabled: false,
        });

        wal::replay_app_state(&replay_state).await.unwrap();

        let reservation = replay_state
            .vault
            .reservations
            .get("ver_replay_batch")
            .unwrap();
        assert_eq!(reservation.status, ReservationStatus::BatchedOnchain);
        assert_eq!(reservation.settlement_id.as_deref(), Some("set_replay_batch"));
        drop(reservation);

        assert!(replay_state
            .vault
            .provider_credits
            .get(&provider_id)
            .is_none());
        assert!(replay_state
            .vault
            .settlement_history
            .get("set_replay_batch")
            .is_none());

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {provider_api_key}")).unwrap(),
        );
        headers.insert(
            HeaderName::from_static(PROVIDER_ID_HEADER),
            HeaderValue::from_str(&provider_id).unwrap(),
        );

        let response = post_settlement_status(
            State(replay_state.clone()),
            headers,
            Json(SettlementStatusRequest {
                settlement_id: "set_replay_batch".to_string(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(response.0.batch_id, Some(7));
        assert_eq!(response.0.tx_signature.as_deref(), Some("txsig_replay_batch"));
        assert_eq!(response.0.status, "BatchedOnchain");

        let _ = tokio::fs::remove_file(wal_path).await;
    }
}
