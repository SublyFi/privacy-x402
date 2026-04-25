use axum::body::Body;
use axum::http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;

const ADMIN_TOKEN_HASH_ENV: &str = "SUBLY402_ADMIN_AUTH_TOKEN_SHA256";
const ADMIN_TOKEN_ENV: &str = "SUBLY402_ADMIN_AUTH_TOKEN";

pub async fn require_admin_auth(req: Request<Body>, next: Next) -> Response {
    match verify_admin_auth(req.headers()) {
        Ok(()) => next.run(req).await,
        Err(response) => response,
    }
}

fn verify_admin_auth(headers: &HeaderMap) -> Result<(), Response> {
    let Some(token) = bearer_token(headers) else {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "admin_auth_failed",
            "Control-plane authorization is required",
        ));
    };

    if let Some(expected_hash) = env_value(ADMIN_TOKEN_HASH_ENV) {
        let expected_hash = normalize_hash_hex(&expected_hash);
        let Ok(expected_hash_bytes) = hex::decode(expected_hash) else {
            return Err(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "admin_auth_misconfigured",
                "SUBLY402_ADMIN_AUTH_TOKEN_SHA256 must be 64 hex characters",
            ));
        };
        if expected_hash_bytes.len() != 32 {
            return Err(json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "admin_auth_misconfigured",
                "SUBLY402_ADMIN_AUTH_TOKEN_SHA256 must be 64 hex characters",
            ));
        }

        let actual_hash = Sha256::digest(token.as_bytes());
        if constant_time_eq(actual_hash.as_ref(), &expected_hash_bytes) {
            return Ok(());
        }

        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "admin_auth_failed",
            "Control-plane authorization failed",
        ));
    }

    if let Some(expected_token) = env_value(ADMIN_TOKEN_ENV) {
        if constant_time_eq(token.as_bytes(), expected_token.as_bytes()) {
            return Ok(());
        }

        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "admin_auth_failed",
            "Control-plane authorization failed",
        ));
    }

    Err(json_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "admin_auth_not_configured",
        "Control-plane API is enabled but admin authorization is not configured",
    ))
}

fn normalize_hash_hex(value: &str) -> &str {
    let trimmed = value.trim();
    trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed)
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

fn json_error(status: StatusCode, error: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "ok": false,
            "error": error,
            "message": message,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_admin_env(hash: Option<&str>, token: Option<&str>, test: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous_hash = env::var(ADMIN_TOKEN_HASH_ENV).ok();
        let previous_token = env::var(ADMIN_TOKEN_ENV).ok();

        set_or_remove_env(ADMIN_TOKEN_HASH_ENV, hash);
        set_or_remove_env(ADMIN_TOKEN_ENV, token);
        test();
        set_or_remove_env(ADMIN_TOKEN_HASH_ENV, previous_hash.as_deref());
        set_or_remove_env(ADMIN_TOKEN_ENV, previous_token.as_deref());
    }

    fn set_or_remove_env(name: &str, value: Option<&str>) {
        match value {
            Some(value) => env::set_var(name, value),
            None => env::remove_var(name),
        }
    }

    fn headers(auth: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(auth) = auth {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(auth).unwrap());
        }
        headers
    }

    #[test]
    fn rejects_when_admin_auth_is_not_configured() {
        with_admin_env(None, None, || {
            let response = verify_admin_auth(&headers(Some("Bearer secret"))).unwrap_err();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        });
    }

    #[test]
    fn accepts_plaintext_admin_token_for_local_dev() {
        with_admin_env(None, Some("secret"), || {
            assert!(verify_admin_auth(&headers(Some("Bearer secret"))).is_ok());
            let response = verify_admin_auth(&headers(Some("Bearer wrong"))).unwrap_err();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        });
    }

    #[test]
    fn accepts_sha256_admin_token_hash() {
        let hash = hex::encode(Sha256::digest(b"secret"));
        with_admin_env(Some(&hash), None, || {
            assert!(verify_admin_auth(&headers(Some("Bearer secret"))).is_ok());
            let response = verify_admin_auth(&headers(Some("Bearer wrong"))).unwrap_err();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        });
    }
}
