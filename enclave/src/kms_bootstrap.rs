use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use solana_sdk::pubkey::Pubkey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::attestation::{
    build_local_dev_attestation, build_static_nitro_attestation, AttestationBundle,
};
use crate::interconnect::{connect_tcp, ParentInterconnect};
use crate::snapshot_store::SnapshotStoreClient;

const DEFAULT_KMS_PROXY_ADDR: &str = "127.0.0.1:5002";

#[derive(Debug)]
pub struct BootstrapMaterials {
    pub signing_key: SigningKey,
    pub storage_key: [u8; 32],
    pub attestation: AttestationBundle,
}

pub async fn bootstrap_materials(
    vault_config: Pubkey,
    attestation_policy_hash: [u8; 32],
    snapshot_store: Option<SnapshotStoreClient>,
) -> Result<BootstrapMaterials, String> {
    let recipient_keys = RecipientKeyPair::generate()?;
    let nitro_document = std::env::var("A402_NITRO_ATTESTATION_DOCUMENT_B64").ok();

    let signing_key =
        load_signing_key(vault_config, nitro_document.as_deref(), &recipient_keys).await?;
    let storage_key = load_storage_key(
        vault_config,
        &signing_key,
        nitro_document.as_deref(),
        &recipient_keys,
        snapshot_store.as_ref(),
    )
    .await?;

    let vault_signer = Pubkey::new_from_array(signing_key.verifying_key().to_bytes());
    let attestation = if let Some(document_b64) = nitro_document {
        build_static_nitro_attestation(document_b64)
    } else {
        build_local_dev_attestation(
            vault_config,
            vault_signer,
            attestation_policy_hash,
            recipient_keys.public_key_pem(),
        )
    };

    Ok(BootstrapMaterials {
        signing_key,
        storage_key,
        attestation,
    })
}

struct RecipientKeyPair {
    private_key: RsaPrivateKey,
    public_key_pem: String,
}

impl RecipientKeyPair {
    fn generate() -> Result<Self, String> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|error| format!("failed to generate bootstrap recipient key: {error}"))?;
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|error| format!("failed to encode bootstrap recipient public key: {error}"))?;
        Ok(Self {
            private_key,
            public_key_pem,
        })
    }

    fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    fn decrypt_b64(&self, ciphertext_b64: &str) -> Result<Vec<u8>, String> {
        let ciphertext = BASE64
            .decode(ciphertext_b64)
            .map_err(|error| format!("invalid base64 ciphertextForRecipient: {error}"))?;
        self.private_key
            .decrypt(Oaep::new::<Sha256>(), &ciphertext)
            .map_err(|error| format!("failed to decrypt ciphertextForRecipient: {error}"))
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KmsProxyRequest<'a> {
    action: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_spec: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    number_of_bytes: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext_blob: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_attestation_document: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_context: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmsProxyResponse {
    ok: bool,
    action: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    plaintext: Option<String>,
    #[serde(default)]
    ciphertext_blob: Option<String>,
    #[serde(default)]
    ciphertext_for_recipient: Option<String>,
}

async fn load_signing_key(
    vault_config: Pubkey,
    nitro_document_b64: Option<&str>,
    recipient_keys: &RecipientKeyPair,
) -> Result<SigningKey, String> {
    if let Ok(encoded) = std::env::var("A402_VAULT_SIGNER_SECRET_KEY_B64") {
        return decode_signing_key(&encoded);
    }

    if let Ok(ciphertext_b64) = std::env::var("A402_VAULT_SIGNER_SEED_CIPHERTEXT_B64") {
        let plaintext = decrypt_kms_ciphertext(
            &ciphertext_b64,
            nitro_document_b64,
            recipient_keys,
            Some(signer_encryption_context(vault_config)),
        )
        .await?;
        return signing_key_from_bytes(&plaintext);
    }

    Ok(SigningKey::generate(&mut OsRng))
}

async fn load_storage_key(
    vault_config: Pubkey,
    signing_key: &SigningKey,
    nitro_document_b64: Option<&str>,
    recipient_keys: &RecipientKeyPair,
    snapshot_store: Option<&SnapshotStoreClient>,
) -> Result<[u8; 32], String> {
    if let Ok(encoded) = std::env::var("A402_STORAGE_KEY_B64") {
        return decode_fixed_b64::<32>(&encoded, "A402_STORAGE_KEY_B64");
    }

    if let Ok(ciphertext_b64) = std::env::var("A402_STORAGE_KEY_CIPHERTEXT_B64") {
        let plaintext = decrypt_kms_ciphertext(
            &ciphertext_b64,
            nitro_document_b64,
            recipient_keys,
            Some(storage_encryption_context(vault_config)),
        )
        .await?;
        return fixed_32_from_bytes(&plaintext, "storage key plaintext");
    }

    if let (Some(document_b64), Some(snapshot_store), Ok(key_id)) = (
        nitro_document_b64,
        snapshot_store,
        std::env::var("A402_SNAPSHOT_DATA_KEY_ID"),
    ) {
        let metadata_key = std::env::var("A402_STORAGE_KEY_METADATA_KEY")
            .unwrap_or_else(|_| format!("meta/{vault_config}/snapshot-data-key.ciphertext"));
        if let Some(ciphertext_blob) = snapshot_store
            .get(&metadata_key)
            .await
            .map_err(|error| format!("failed to read snapshot data key metadata: {error}"))?
        {
            let ciphertext_b64 = BASE64.encode(ciphertext_blob);
            let plaintext = decrypt_kms_ciphertext(
                &ciphertext_b64,
                Some(document_b64),
                recipient_keys,
                Some(storage_encryption_context(vault_config)),
            )
            .await?;
            return fixed_32_from_bytes(&plaintext, "snapshot data key plaintext");
        }

        let response = call_kms_proxy(KmsProxyRequest {
            action: "TrentService.GenerateDataKey",
            key_id: Some(&key_id),
            key_spec: Some("AES_256"),
            number_of_bytes: None,
            ciphertext_blob: None,
            recipient_attestation_document: Some(document_b64),
            encryption_context: Some(storage_encryption_context(vault_config)),
        })
        .await?;

        let ciphertext_blob = response
            .ciphertext_blob
            .clone()
            .ok_or_else(|| "GenerateDataKey response missing ciphertextBlob".to_string())?;
        let plaintext = resolve_kms_plaintext(&response, recipient_keys)?;

        snapshot_store
            .put(
                &metadata_key,
                &BASE64
                    .decode(ciphertext_blob)
                    .map_err(|error| format!("invalid base64 ciphertextBlob from KMS: {error}"))?,
            )
            .await
            .map_err(|error| format!("failed to persist snapshot data key metadata: {error}"))?;

        return fixed_32_from_bytes(&plaintext, "generated snapshot data key");
    }

    derive_local_storage_key(signing_key, vault_config)
}

async fn decrypt_kms_ciphertext(
    ciphertext_b64: &str,
    nitro_document_b64: Option<&str>,
    recipient_keys: &RecipientKeyPair,
    encryption_context: Option<std::collections::HashMap<String, String>>,
) -> Result<Vec<u8>, String> {
    let response = call_kms_proxy(KmsProxyRequest {
        action: "TrentService.Decrypt",
        key_id: None,
        key_spec: None,
        number_of_bytes: None,
        ciphertext_blob: Some(ciphertext_b64),
        recipient_attestation_document: nitro_document_b64,
        encryption_context,
    })
    .await?;

    resolve_kms_plaintext(&response, recipient_keys)
}

async fn call_kms_proxy(request: KmsProxyRequest<'_>) -> Result<KmsProxyResponse, String> {
    let parent_interconnect = ParentInterconnect::from_env();
    let addr = std::env::var("A402_KMS_PROXY_ADDR").ok();
    let port = std::env::var("A402_ENCLAVE_KMS_PORT")
        .ok()
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|_| panic!("A402_ENCLAVE_KMS_PORT must be a valid u32"))
        })
        .unwrap_or(5002);
    let payload = serde_json::to_vec(&request)
        .map_err(|error| format!("failed to serialize KMS request: {error}"))?;

    let mut stream = match addr {
        Some(addr) => connect_tcp(&addr)
            .await
            .map_err(|error| format!("failed to connect to KMS proxy {addr}: {error}"))?,
        None => parent_interconnect
            .connect(port, DEFAULT_KMS_PROXY_ADDR.to_string())
            .await
            .map_err(|error| format!("failed to connect to KMS proxy on port {port}: {error}"))?,
    };
    stream
        .write_u32_le(payload.len() as u32)
        .await
        .map_err(|error| format!("failed to write KMS request length: {error}"))?;
    stream
        .write_all(&payload)
        .await
        .map_err(|error| format!("failed to write KMS request payload: {error}"))?;

    let len = stream
        .read_u32_le()
        .await
        .map_err(|error| format!("failed to read KMS response length: {error}"))?
        as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|error| format!("failed to read KMS response payload: {error}"))?;

    let response: KmsProxyResponse = serde_json::from_slice(&buf)
        .map_err(|error| format!("invalid JSON from KMS proxy: {error}"))?;
    if response.ok {
        Ok(response)
    } else {
        Err(format!(
            "KMS proxy {} failed: {}",
            response.action,
            response.message.unwrap_or_else(|| response
                .error
                .unwrap_or_else(|| "unknown error".to_string()))
        ))
    }
}

fn resolve_kms_plaintext(
    response: &KmsProxyResponse,
    recipient_keys: &RecipientKeyPair,
) -> Result<Vec<u8>, String> {
    if let Some(ciphertext_for_recipient) = response.ciphertext_for_recipient.as_deref() {
        return recipient_keys.decrypt_b64(ciphertext_for_recipient);
    }
    if let Some(plaintext) = response.plaintext.as_deref() {
        return BASE64
            .decode(plaintext)
            .map_err(|error| format!("invalid base64 plaintext from KMS proxy: {error}"));
    }
    Err(format!(
        "{} response did not include plaintext or ciphertextForRecipient",
        response.action
    ))
}

fn derive_local_storage_key(
    signing_key: &SigningKey,
    vault_config: Pubkey,
) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha256>::new(Some(vault_config.as_ref()), &signing_key.to_bytes());
    let mut out = [0u8; 32];
    hkdf.expand(b"a402-local-storage-key", &mut out)
        .map_err(|_| "failed to derive local storage key".to_string())?;
    Ok(out)
}

fn decode_signing_key(encoded: &str) -> Result<SigningKey, String> {
    let bytes = decode_fixed_b64::<32>(encoded, "A402_VAULT_SIGNER_SECRET_KEY_B64")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&fixed_32_from_bytes(
        bytes,
        "vault signer plaintext",
    )?))
}

fn fixed_32_from_bytes(bytes: &[u8], label: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be exactly 32 bytes"))
}

fn decode_fixed_b64<const N: usize>(encoded: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = BASE64
        .decode(encoded)
        .map_err(|error| format!("{label} must be valid base64: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must decode to exactly {N} bytes"))
}

fn signer_encryption_context(vault_config: Pubkey) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("a402:component".to_string(), "vault-signer".to_string()),
        ("a402:vaultConfig".to_string(), vault_config.to_string()),
    ])
}

fn storage_encryption_context(vault_config: Pubkey) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        (
            "a402:component".to_string(),
            "snapshot-data-key".to_string(),
        ),
        ("a402:vaultConfig".to_string(), vault_config.to_string()),
    ])
}
