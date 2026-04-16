use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use solana_sdk::pubkey::Pubkey;

use crate::tls::TlsBindingInfo;

#[derive(Debug, Clone)]
pub struct AttestationBundle {
    pub document_b64: String,
    pub is_local_dev: bool,
    pub recipient_public_key_pem: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_public_key_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_public_key_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    pub snapshot_seqno: u64,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct A402NitroUserDataEnvelope<'a> {
    version: u32,
    vault_config: String,
    vault_signer: String,
    attestation_policy_hash: String,
    snapshot_seqno: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_public_key_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_hash: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct RuntimeAttestation {
    pub document_b64: String,
    pub is_local_dev: bool,
    pub snapshot_seqno: u64,
    pub tls_public_key_sha256: Option<String>,
    pub manifest_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttestationProvider {
    mode: AttestationMode,
    tls_binding: Option<TlsBindingInfo>,
    manifest_hash: Option<String>,
}

#[derive(Debug, Clone)]
enum AttestationMode {
    LocalDev { recipient_public_key_pem: String },
    NitroDynamic,
    NitroStatic { document_b64: String },
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
        tls_public_key_pem: None,
        tls_public_key_sha256: None,
        manifest_hash: None,
        snapshot_seqno: 0,
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };

    AttestationBundle {
        document_b64: BASE64.encode(
            serde_json::to_vec(&document).expect("local attestation document must serialize"),
        ),
        is_local_dev: true,
        recipient_public_key_pem: Some(recipient_public_key_pem.to_string()),
    }
}

pub fn build_static_nitro_attestation(document_b64: String) -> AttestationBundle {
    AttestationBundle {
        document_b64,
        is_local_dev: false,
        recipient_public_key_pem: None,
    }
}

impl AttestationProvider {
    pub fn from_bootstrap_bundle(
        bundle: AttestationBundle,
        tls_binding: Option<TlsBindingInfo>,
        manifest_hash: Option<String>,
    ) -> Result<Self, String> {
        let mode = if should_use_dynamic_nitro_attestation() {
            AttestationMode::NitroDynamic
        } else if bundle.is_local_dev {
            AttestationMode::LocalDev {
                recipient_public_key_pem: bundle.recipient_public_key_pem.ok_or_else(|| {
                    "local-dev attestation bundle missing recipient key".to_string()
                })?,
            }
        } else {
            AttestationMode::NitroStatic {
                document_b64: bundle.document_b64,
            }
        };

        Ok(Self {
            mode,
            tls_binding,
            manifest_hash,
        })
    }

    pub fn runtime_attestation(
        &self,
        vault_config: Pubkey,
        vault_signer: Pubkey,
        attestation_policy_hash: [u8; 32],
        snapshot_seqno: u64,
    ) -> Result<RuntimeAttestation, String> {
        match &self.mode {
            AttestationMode::LocalDev {
                recipient_public_key_pem,
            } => Ok(RuntimeAttestation {
                document_b64: build_runtime_local_dev_attestation(
                    vault_config,
                    vault_signer,
                    attestation_policy_hash,
                    snapshot_seqno,
                    recipient_public_key_pem,
                    self.tls_binding.as_ref(),
                    self.manifest_hash.as_deref(),
                )?,
                is_local_dev: true,
                snapshot_seqno,
                tls_public_key_sha256: self
                    .tls_binding
                    .as_ref()
                    .map(|binding| binding.public_key_sha256.clone()),
                manifest_hash: self.manifest_hash.clone(),
            }),
            AttestationMode::NitroDynamic => Ok(RuntimeAttestation {
                document_b64: build_dynamic_nitro_attestation(
                    vault_config,
                    vault_signer,
                    attestation_policy_hash,
                    snapshot_seqno,
                    self.tls_binding.as_ref(),
                    self.manifest_hash.as_deref(),
                )?,
                is_local_dev: false,
                snapshot_seqno,
                tls_public_key_sha256: self
                    .tls_binding
                    .as_ref()
                    .map(|binding| binding.public_key_sha256.clone()),
                manifest_hash: self.manifest_hash.clone(),
            }),
            AttestationMode::NitroStatic { document_b64 } => Ok(RuntimeAttestation {
                document_b64: document_b64.clone(),
                is_local_dev: false,
                snapshot_seqno,
                tls_public_key_sha256: self
                    .tls_binding
                    .as_ref()
                    .map(|binding| binding.public_key_sha256.clone()),
                manifest_hash: self.manifest_hash.clone(),
            }),
        }
    }

    pub fn test_local_dev() -> Self {
        Self {
            mode: AttestationMode::LocalDev {
                recipient_public_key_pem:
                    "-----BEGIN PUBLIC KEY-----\nZmFrZS1rZXk=\n-----END PUBLIC KEY-----\n"
                        .to_string(),
            },
            tls_binding: None,
            manifest_hash: None,
        }
    }
}

fn build_runtime_local_dev_attestation(
    vault_config: Pubkey,
    vault_signer: Pubkey,
    attestation_policy_hash: [u8; 32],
    snapshot_seqno: u64,
    recipient_public_key_pem: &str,
    tls_binding: Option<&TlsBindingInfo>,
    manifest_hash: Option<&str>,
) -> Result<String, String> {
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
        tls_public_key_pem: tls_binding.map(|binding| binding.public_key_spki_pem.clone()),
        tls_public_key_sha256: tls_binding.map(|binding| binding.public_key_sha256.clone()),
        manifest_hash: manifest_hash.map(str::to_string),
        snapshot_seqno,
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };

    serde_json::to_vec(&document)
        .map(|json| BASE64.encode(json))
        .map_err(|error| format!("failed to serialize local attestation document: {error}"))
}

fn build_a402_user_data(
    vault_config: Pubkey,
    vault_signer: Pubkey,
    attestation_policy_hash: [u8; 32],
    snapshot_seqno: u64,
    tls_binding: Option<&TlsBindingInfo>,
    manifest_hash: Option<&str>,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&A402NitroUserDataEnvelope {
        version: 1,
        vault_config: vault_config.to_string(),
        vault_signer: vault_signer.to_string(),
        attestation_policy_hash: hex::encode(attestation_policy_hash),
        snapshot_seqno,
        tls_public_key_sha256: tls_binding.map(|binding| binding.public_key_sha256.as_str()),
        manifest_hash,
    })
    .map_err(|error| format!("failed to serialize Nitro user_data envelope: {error}"))
}

#[cfg(target_os = "linux")]
fn build_dynamic_nitro_attestation(
    vault_config: Pubkey,
    vault_signer: Pubkey,
    attestation_policy_hash: [u8; 32],
    snapshot_seqno: u64,
    tls_binding: Option<&TlsBindingInfo>,
    manifest_hash: Option<&str>,
) -> Result<String, String> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use serde_bytes::ByteBuf;

    let user_data = build_a402_user_data(
        vault_config,
        vault_signer,
        attestation_policy_hash,
        snapshot_seqno,
        tls_binding,
        manifest_hash,
    )?;

    let fd = nsm_init();
    if fd < 0 {
        return Err("failed to open /dev/nsm for Nitro attestation".to_string());
    }

    let response = nsm_process_request(
        fd,
        Request::Attestation {
            user_data: Some(ByteBuf::from(user_data)),
            nonce: None,
            public_key: tls_binding
                .map(|binding| ByteBuf::from(binding.public_key_spki_der.clone())),
        },
    );
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => Ok(BASE64.encode(document)),
        Response::Error(error) => Err(format!("NSM attestation request failed: {error:?}")),
        other => Err(format!("unexpected NSM attestation response: {other:?}")),
    }
}

#[cfg(not(target_os = "linux"))]
fn build_dynamic_nitro_attestation(
    _vault_config: Pubkey,
    _vault_signer: Pubkey,
    _attestation_policy_hash: [u8; 32],
    _snapshot_seqno: u64,
    _tls_binding: Option<&TlsBindingInfo>,
    _manifest_hash: Option<&str>,
) -> Result<String, String> {
    Err("dynamic Nitro attestation is only available on Linux Nitro hosts".to_string())
}

#[cfg(target_os = "linux")]
fn should_use_dynamic_nitro_attestation() -> bool {
    if std::env::var("A402_DISABLE_DYNAMIC_NITRO_ATTESTATION")
        .ok()
        .as_deref()
        == Some("1")
    {
        return false;
    }
    std::path::Path::new("/dev/nsm").exists()
}

#[cfg(not(target_os = "linux"))]
fn should_use_dynamic_nitro_attestation() -> bool {
    false
}

pub fn response_window() -> (DateTime<Utc>, DateTime<Utc>) {
    let issued_at = Utc::now();
    (issued_at, issued_at + Duration::minutes(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_dev_runtime_attestation_binds_snapshot_and_tls_metadata() {
        let provider = AttestationProvider {
            mode: AttestationMode::LocalDev {
                recipient_public_key_pem:
                    "-----BEGIN PUBLIC KEY-----\nZmFrZS1rZXk=\n-----END PUBLIC KEY-----\n"
                        .to_string(),
            },
            tls_binding: Some(TlsBindingInfo {
                public_key_spki_der: vec![1, 2, 3],
                public_key_spki_pem: "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n"
                    .to_string(),
                public_key_sha256: "11".repeat(32),
            }),
            manifest_hash: Some("22".repeat(32)),
        };

        let attestation = provider
            .runtime_attestation(Pubkey::new_unique(), Pubkey::new_unique(), [0x33; 32], 7)
            .unwrap();

        let decoded = BASE64.decode(attestation.document_b64).unwrap();
        let document: LocalDevAttestationDocument = serde_json::from_slice(&decoded).unwrap();
        let expected_tls_hash = "11".repeat(32);
        let expected_manifest_hash = "22".repeat(32);
        assert_eq!(document.snapshot_seqno, 7);
        assert_eq!(
            document.tls_public_key_sha256.as_deref(),
            Some(expected_tls_hash.as_str())
        );
        assert_eq!(
            document.manifest_hash.as_deref(),
            Some(expected_manifest_hash.as_str())
        );
        assert!(document
            .tls_public_key_pem
            .as_deref()
            .unwrap_or_default()
            .contains("BEGIN PUBLIC KEY"));
    }
}
