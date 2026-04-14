use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum EnclaveError {
    #[error("Insufficient client balance")]
    InsufficientBalance,

    #[error("Client not found")]
    ClientNotFound,

    #[error("Provider not found")]
    ProviderNotFound,

    #[error("Provider authentication failed")]
    ProviderAuthFailed,

    #[error("Provider registration has an unsupported auth mode")]
    UnsupportedProviderAuthMode,

    #[error("Provider registration auth material is invalid")]
    InvalidProviderAuthConfig,

    #[error("mTLS listener is not enabled on this facilitator")]
    MtlsNotEnabled,

    #[error("Invalid payment scheme")]
    InvalidScheme,

    #[error("paymentDetails is required")]
    PaymentDetailsRequired,

    #[error("Invalid client signature")]
    InvalidClientSignature,

    #[error("Payment expired")]
    PaymentExpired,

    #[error("Payment ID already used with different request")]
    PaymentIdReused,

    #[error("Reservation not found")]
    ReservationNotFound,

    #[error("Settlement not found")]
    SettlementNotFound,

    #[error("Invalid reservation status: {0}")]
    InvalidReservationStatus(String),

    #[error("Vault not active")]
    VaultNotActive,

    #[error("Vault is paused")]
    VaultPaused,

    #[error("Vault is migrating")]
    VaultMigrating,

    #[error("Vault is retired")]
    VaultRetired,

    #[error("Vault status is unavailable")]
    VaultStatusUnavailable,

    #[error("Deposit synchronization in progress")]
    DepositSyncInProgress,

    #[error("Request hash mismatch")]
    RequestHashMismatch,

    #[error("Payment details hash mismatch")]
    PaymentDetailsHashMismatch,

    #[error("Provider ID mismatch")]
    ProviderIdMismatch,

    #[error("Channel not found")]
    ChannelNotFound,

    #[error("Invalid channel status: {0}")]
    InvalidChannelStatus(String),

    #[error("Channel request expired")]
    ChannelRequestExpired,

    #[error("Channel request ID already used")]
    ChannelRequestIdReused,

    #[error("Invalid adaptor pre-signature")]
    InvalidAdaptorSignature,

    #[error("Receipt watchtower is unavailable")]
    ReceiptWatchtowerUnavailable,

    #[error("Provider participant pubkey is invalid")]
    InvalidProviderParticipant,

    #[error("payTo does not match provider registration")]
    PayToMismatch,

    #[error("assetMint does not match provider registration")]
    AssetMintMismatch,

    #[error("network does not match provider registration")]
    NetworkMismatch,

    #[error("Request origin not in provider allowed origins")]
    OriginNotAllowed,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        let (status, error_code) = match &self {
            EnclaveError::InsufficientBalance => {
                (StatusCode::PAYMENT_REQUIRED, "insufficient_balance")
            }
            EnclaveError::ClientNotFound => (StatusCode::BAD_REQUEST, "client_not_found"),
            EnclaveError::ProviderNotFound => (StatusCode::BAD_REQUEST, "provider_not_found"),
            EnclaveError::ProviderAuthFailed => (StatusCode::UNAUTHORIZED, "provider_auth_failed"),
            EnclaveError::UnsupportedProviderAuthMode => {
                (StatusCode::BAD_REQUEST, "unsupported_provider_auth_mode")
            }
            EnclaveError::InvalidProviderAuthConfig => {
                (StatusCode::BAD_REQUEST, "invalid_provider_auth_config")
            }
            EnclaveError::MtlsNotEnabled => (StatusCode::SERVICE_UNAVAILABLE, "mtls_not_enabled"),
            EnclaveError::InvalidScheme => (StatusCode::BAD_REQUEST, "invalid_scheme"),
            EnclaveError::PaymentDetailsRequired => {
                (StatusCode::BAD_REQUEST, "payment_details_required")
            }
            EnclaveError::InvalidClientSignature => {
                (StatusCode::BAD_REQUEST, "invalid_client_signature")
            }
            EnclaveError::PaymentExpired => (StatusCode::BAD_REQUEST, "payment_expired"),
            EnclaveError::PaymentIdReused => (StatusCode::CONFLICT, "payment_id_reused"),
            EnclaveError::ReservationNotFound => (StatusCode::NOT_FOUND, "reservation_not_found"),
            EnclaveError::SettlementNotFound => (StatusCode::NOT_FOUND, "settlement_not_found"),
            EnclaveError::InvalidReservationStatus(ref _s) => {
                (StatusCode::CONFLICT, "invalid_reservation_status")
            }
            EnclaveError::VaultNotActive => (StatusCode::SERVICE_UNAVAILABLE, "vault_not_active"),
            EnclaveError::VaultPaused => (StatusCode::SERVICE_UNAVAILABLE, "vault_paused"),
            EnclaveError::VaultMigrating => {
                (StatusCode::SERVICE_UNAVAILABLE, "vault_migrating")
            }
            EnclaveError::VaultRetired => (StatusCode::SERVICE_UNAVAILABLE, "vault_retired"),
            EnclaveError::VaultStatusUnavailable => {
                (StatusCode::SERVICE_UNAVAILABLE, "vault_status_unavailable")
            }
            EnclaveError::DepositSyncInProgress => {
                (StatusCode::SERVICE_UNAVAILABLE, "deposit_sync_in_progress")
            }
            EnclaveError::RequestHashMismatch => (StatusCode::BAD_REQUEST, "request_hash_mismatch"),
            EnclaveError::PaymentDetailsHashMismatch => {
                (StatusCode::BAD_REQUEST, "payment_details_hash_mismatch")
            }
            EnclaveError::ProviderIdMismatch => (StatusCode::FORBIDDEN, "provider_id_mismatch"),
            EnclaveError::ChannelNotFound => (StatusCode::NOT_FOUND, "channel_not_found"),
            EnclaveError::InvalidChannelStatus(ref _s) => {
                (StatusCode::CONFLICT, "invalid_channel_status")
            }
            EnclaveError::ChannelRequestExpired => {
                (StatusCode::BAD_REQUEST, "channel_request_expired")
            }
            EnclaveError::ChannelRequestIdReused => {
                (StatusCode::CONFLICT, "channel_request_id_reused")
            }
            EnclaveError::InvalidAdaptorSignature => {
                (StatusCode::BAD_REQUEST, "invalid_adaptor_signature")
            }
            EnclaveError::ReceiptWatchtowerUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "receipt_watchtower_unavailable",
            ),
            EnclaveError::InvalidProviderParticipant => {
                (StatusCode::BAD_REQUEST, "invalid_provider_participant")
            }
            EnclaveError::PayToMismatch => (StatusCode::BAD_REQUEST, "pay_to_mismatch"),
            EnclaveError::AssetMintMismatch => (StatusCode::BAD_REQUEST, "asset_mint_mismatch"),
            EnclaveError::NetworkMismatch => (StatusCode::BAD_REQUEST, "network_mismatch"),
            EnclaveError::OriginNotAllowed => (StatusCode::FORBIDDEN, "origin_not_allowed"),
            EnclaveError::Internal(ref _s) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        let body = json!({
            "ok": false,
            "error": error_code,
            "message": self.to_string(),
        });

        (status, axum::Json(body)).into_response()
    }
}
