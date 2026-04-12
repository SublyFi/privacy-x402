use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use solana_sdk::pubkey::Pubkey;

#[derive(Debug, Clone)]
pub struct AttestationBundle {
    pub document_b64: String,
    pub is_local_dev: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalDevAttestationDocument {
    pub version: u32,
    pub mode: String,
    pub vault_config: String,
    pub vault_signer: String,
    pub attestation_policy_hash: String,
    pub recipient_public_key_pem: String,
    pub recipient_public_key_sha256: String,
    pub issued_at: String,
    pub expires_at: String,
}

pub fn build_local_dev_attestation(
    vault_config: Pubkey,
    vault_signer: Pubkey,
    attestation_policy_hash: [u8; 32],
    recipient_public_key_pem: &str,
) -> AttestationBundle {
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::hours(24);
    let public_key_sha256 = sha2::Sha256::digest(recipient_public_key_pem.as_bytes());
    let document = LocalDevAttestationDocument {
        version: 1,
        mode: "local-dev".to_string(),
        vault_config: vault_config.to_string(),
        vault_signer: vault_signer.to_string(),
        attestation_policy_hash: hex::encode(attestation_policy_hash),
        recipient_public_key_pem: recipient_public_key_pem.to_string(),
        recipient_public_key_sha256: hex::encode(public_key_sha256),
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };

    AttestationBundle {
        document_b64: BASE64.encode(
            serde_json::to_vec(&document).expect("local attestation document must serialize"),
        ),
        is_local_dev: true,
    }
}

pub fn build_static_nitro_attestation(document_b64: String) -> AttestationBundle {
    AttestationBundle {
        document_b64,
        is_local_dev: false,
    }
}

pub fn response_window() -> (DateTime<Utc>, DateTime<Utc>) {
    let issued_at = Utc::now();
    (issued_at, issued_at + Duration::minutes(10))
}
