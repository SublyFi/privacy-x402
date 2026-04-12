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

    #[error("Invalid payment scheme")]
    InvalidScheme,

    #[error("Invalid client signature")]
    InvalidClientSignature,

    #[error("Payment expired")]
    PaymentExpired,

    #[error("Payment ID already used with different request")]
    PaymentIdReused,

    #[error("Reservation not found")]
    ReservationNotFound,

    #[error("Invalid reservation status: {0}")]
    InvalidReservationStatus(String),

    #[error("Vault not active")]
    VaultNotActive,

    #[error("Request hash mismatch")]
    RequestHashMismatch,

    #[error("Payment details hash mismatch")]
    PaymentDetailsHashMismatch,

    #[error("Provider ID mismatch")]
    ProviderIdMismatch,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        let (status, error_code) = match &self {
            EnclaveError::InsufficientBalance => (StatusCode::PAYMENT_REQUIRED, "insufficient_balance"),
            EnclaveError::ClientNotFound => (StatusCode::BAD_REQUEST, "client_not_found"),
            EnclaveError::ProviderNotFound => (StatusCode::BAD_REQUEST, "provider_not_found"),
            EnclaveError::ProviderAuthFailed => (StatusCode::UNAUTHORIZED, "provider_auth_failed"),
            EnclaveError::InvalidScheme => (StatusCode::BAD_REQUEST, "invalid_scheme"),
            EnclaveError::InvalidClientSignature => (StatusCode::BAD_REQUEST, "invalid_client_signature"),
            EnclaveError::PaymentExpired => (StatusCode::BAD_REQUEST, "payment_expired"),
            EnclaveError::PaymentIdReused => (StatusCode::CONFLICT, "payment_id_reused"),
            EnclaveError::ReservationNotFound => (StatusCode::NOT_FOUND, "reservation_not_found"),
            EnclaveError::InvalidReservationStatus(ref _s) => (StatusCode::CONFLICT, "invalid_reservation_status"),
            EnclaveError::VaultNotActive => (StatusCode::SERVICE_UNAVAILABLE, "vault_not_active"),
            EnclaveError::RequestHashMismatch => (StatusCode::BAD_REQUEST, "request_hash_mismatch"),
            EnclaveError::PaymentDetailsHashMismatch => (StatusCode::BAD_REQUEST, "payment_details_hash_mismatch"),
            EnclaveError::ProviderIdMismatch => (StatusCode::FORBIDDEN, "provider_id_mismatch"),
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
