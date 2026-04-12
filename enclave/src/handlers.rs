use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::sync::Arc;
use tracing::info;

use crate::error::EnclaveError;
use crate::state::{Reservation, ReservationStatus, VaultState};
use crate::wal::{Wal, WalEntry};

pub struct AppState {
    pub vault: Arc<VaultState>,
    pub wal: Arc<Wal>,
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

pub async fn get_attestation(
    State(state): State<Arc<AppState>>,
) -> Json<AttestationResponse> {
    let now = Utc::now();
    let expires = now + chrono::Duration::minutes(10);

    Json(AttestationResponse {
        vault_config: state.vault.vault_config.to_string(),
        vault_signer: state.vault.vault_signer_pubkey.to_string(),
        attestation_policy_hash: hex::encode(state.vault.attestation_policy_hash),
        // Phase 1 local dev: stub attestation document
        attestation_document: BASE64.encode(b"local-dev-attestation-stub"),
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
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
    pub request_context: RequestContext,
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

pub async fn post_verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, EnclaveError> {
    let payload = &req.payment_payload;

    // 1. Validate scheme
    if payload.scheme != "a402-svm-v1" {
        return Err(EnclaveError::InvalidScheme);
    }

    // 2. Validate provider
    let _provider = state
        .vault
        .providers
        .get(&payload.provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;

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
    let client_pubkey = Pubkey::from_str(&payload.client)
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    verify_client_signature(payload)?;

    // 6. Verify request hash
    let computed_request_hash = compute_request_hash(&req.request_context, &payload.payment_details_hash);
    let provided_request_hash = hex::decode(&payload.request_hash)
        .map_err(|_| EnclaveError::RequestHashMismatch)?;
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
                let res_expires = chrono::DateTime::from_timestamp(existing.expires_at, 0)
                    .unwrap_or_default();
                return Ok(Json(VerifyResponse {
                    ok: true,
                    verification_id: existing.verification_id.clone(),
                    reservation_id: existing.reservation_id.clone(),
                    reservation_expires_at: res_expires.to_rfc3339(),
                    provider_id: existing.provider_id.clone(),
                    amount: existing.amount.to_string(),
                    verification_receipt: String::new(),
                }));
            } else {
                return Err(EnclaveError::PaymentIdReused);
            }
        }
    }

    // 8. Reserve balance
    state.vault.reserve_balance(&client_pubkey, amount)?;

    // 9. Create reservation
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

    // 10. WAL append (durable before response)
    state
        .wal
        .append(WalEntry::ReservationCreated {
            verification_id: verification_id.clone(),
            payment_id: payload.payment_id.clone(),
            client: payload.client.clone(),
            provider_id: payload.provider_id.clone(),
            amount,
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

    let res_expires = chrono::DateTime::from_timestamp(reservation_expires_at, 0).unwrap_or_default();

    info!(verification_id = %verification_id, amount, "Payment verified and reserved");

    Ok(Json(VerifyResponse {
        ok: true,
        verification_id,
        reservation_id,
        reservation_expires_at: res_expires.to_rfc3339(),
        provider_id: payload.provider_id.clone(),
        amount: amount.to_string(),
        verification_receipt: String::new(),
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
    Json(req): Json<SettleRequest>,
) -> Result<Json<SettleResponse>, EnclaveError> {
    // Look up reservation
    let mut reservation = state
        .vault
        .reservations
        .get_mut(&req.verification_id)
        .ok_or(EnclaveError::ReservationNotFound)?;

    // Idempotency
    if reservation.status == ReservationStatus::SettledOffchain {
        let settled_at = reservation.settled_at.unwrap_or(0);
        let settled_time = chrono::DateTime::from_timestamp(settled_at, 0).unwrap_or_default();
        return Ok(Json(SettleResponse {
            ok: true,
            settlement_id: reservation.settlement_id.clone().unwrap_or_default(),
            offchain_settled_at: settled_time.to_rfc3339(),
            provider_credit_amount: reservation.amount.to_string(),
            batch_id: None,
            participant_receipt: String::new(),
        }));
    }

    // Must be Reserved
    if reservation.status != ReservationStatus::Reserved {
        return Err(EnclaveError::InvalidReservationStatus(
            format!("{:?}", reservation.status),
        ));
    }

    let now = Utc::now().timestamp();
    let settlement_id = format!("set_{}", uuid::Uuid::now_v7());

    // Settle payment
    state.vault.settle_payment(
        &reservation.client,
        reservation.amount,
        &reservation.provider_id,
        &settlement_id,
        now,
    )?;

    // WAL append (durable before response)
    state
        .wal
        .append(WalEntry::SettlementCommitted {
            settlement_id: settlement_id.clone(),
            verification_id: req.verification_id.clone(),
            provider_id: reservation.provider_id.clone(),
            amount: reservation.amount,
        })
        .await
        .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

    // Issue ParticipantReceipt to provider
    let provider = state
        .vault
        .providers
        .get(&reservation.provider_id)
        .ok_or(EnclaveError::ProviderNotFound)?;

    let nonce = state.vault.next_receipt_nonce();
    let snapshot_seqno = state
        .vault
        .snapshot_seqno
        .load(std::sync::atomic::Ordering::SeqCst);

    let receipt_message = state.vault.build_participant_receipt_message(
        &Pubkey::from_str(&reservation.provider_id).unwrap_or(provider.settlement_token_account),
        1, // Provider kind
        &provider.settlement_token_account,
        reservation.amount,
        0, // Provider locked is always 0
        0,
        nonce,
        now,
        snapshot_seqno,
    );

    let receipt_signature = state.vault.sign_message(&receipt_message);
    let receipt_b64 = BASE64.encode(&receipt_signature);

    // Update reservation
    reservation.status = ReservationStatus::SettledOffchain;
    reservation.settlement_id = Some(settlement_id.clone());
    reservation.settled_at = Some(now);

    let settled_time = chrono::DateTime::from_timestamp(now, 0).unwrap_or_default();

    info!(settlement_id = %settlement_id, "Payment settled off-chain");

    Ok(Json(SettleResponse {
        ok: true,
        settlement_id,
        offchain_settled_at: settled_time.to_rfc3339(),
        provider_credit_amount: reservation.amount.to_string(),
        batch_id: None,
        participant_receipt: receipt_b64,
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
    Json(req): Json<CancelRequest>,
) -> Result<Json<CancelResponse>, EnclaveError> {
    let mut reservation = state
        .vault
        .reservations
        .get_mut(&req.verification_id)
        .ok_or(EnclaveError::ReservationNotFound)?;

    if reservation.status == ReservationStatus::Cancelled {
        let now_str = Utc::now().to_rfc3339();
        return Ok(Json(CancelResponse {
            ok: true,
            cancelled_at: now_str,
        }));
    }

    if reservation.status != ReservationStatus::Reserved {
        return Err(EnclaveError::InvalidReservationStatus(
            format!("{:?}", reservation.status),
        ));
    }

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
    let client = Pubkey::from_str(&req.client)
        .map_err(|_| EnclaveError::ClientNotFound)?;
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
    let client = Pubkey::from_str(&req.client)
        .map_err(|_| EnclaveError::ClientNotFound)?;

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

#[derive(Serialize)]
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

pub async fn post_receipt(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReceiptRequest>,
) -> Result<Json<ReceiptResponse>, EnclaveError> {
    let client = Pubkey::from_str(&req.client)
        .map_err(|_| EnclaveError::ClientNotFound)?;
    let recipient_ata = Pubkey::from_str(&req.recipient_ata)
        .map_err(|_| EnclaveError::Internal("Invalid recipient ATA".into()))?;

    let balance = state
        .vault
        .client_balances
        .get(&client)
        .ok_or(EnclaveError::ClientNotFound)?;

    let nonce = state.vault.next_receipt_nonce();
    let now = Utc::now().timestamp();
    let snapshot_seqno = state
        .vault
        .snapshot_seqno
        .load(std::sync::atomic::Ordering::SeqCst);

    let receipt_message = state.vault.build_participant_receipt_message(
        &client,
        0, // Client kind
        &recipient_ata,
        balance.free,
        balance.locked,
        balance.max_lock_expires_at,
        nonce,
        now,
        snapshot_seqno,
    );

    let signature = state.vault.sign_message(&receipt_message);

    // Record in WAL
    state
        .wal
        .append(WalEntry::ParticipantReceiptIssued {
            participant: req.client.clone(),
            participant_kind: 0,
            nonce,
        })
        .await
        .map_err(|e| EnclaveError::Internal(format!("WAL append failed: {e}")))?;

    info!(client = %req.client, nonce, "ParticipantReceipt issued");

    Ok(Json(ReceiptResponse {
        ok: true,
        participant: req.client,
        participant_kind: 0,
        recipient_ata: req.recipient_ata,
        free_balance: balance.free,
        locked_balance: balance.locked,
        max_lock_expires_at: balance.max_lock_expires_at,
        nonce,
        timestamp: now,
        snapshot_seqno,
        vault_config: state.vault.vault_config.to_string(),
        signature: BASE64.encode(&signature),
        message: BASE64.encode(&receipt_message),
    }))
}

// ── Provider Registration ──

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterProviderRequest {
    pub provider_id: String,
    pub display_name: String,
    pub settlement_token_account: String,
    pub network: String,
    pub asset_mint: String,
    pub allowed_origins: Vec<String>,
    pub auth_mode: String,
    pub api_key_hash: String,
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
    let asset_mint = Pubkey::from_str(&req.asset_mint)
        .map_err(|_| EnclaveError::Internal("Invalid asset mint".into()))?;

    let api_key_hash = hex::decode(&req.api_key_hash)
        .unwrap_or_default();

    let registration = crate::state::ProviderRegistration {
        provider_id: req.provider_id.clone(),
        display_name: req.display_name.clone(),
        settlement_token_account,
        network: req.network.clone(),
        asset_mint,
        allowed_origins: req.allowed_origins.clone(),
        auth_mode: req.auth_mode.clone(),
        api_key_hash,
    };

    state
        .vault
        .providers
        .insert(req.provider_id.clone(), registration);

    let now = Utc::now().to_rfc3339();
    info!(provider_id = %req.provider_id, "Provider registered");

    Ok(Json(RegisterProviderResponse {
        ok: true,
        provider_id: req.provider_id,
        registered_at: now,
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

    let client_pubkey_bytes: [u8; 32] = Pubkey::from_str(&payload.client)
        .map_err(|_| EnclaveError::InvalidClientSignature)?
        .to_bytes();

    let verifying_key = VerifyingKey::from_bytes(&client_pubkey_bytes)
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    let sig_bytes = BASE64.decode(&payload.client_sig)
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| EnclaveError::InvalidClientSignature)?,
    );

    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .map_err(|_| EnclaveError::InvalidClientSignature)?;

    Ok(())
}
