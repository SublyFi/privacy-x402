//! KMS Proxy: forwards attested KMS operations from the enclave to AWS KMS.
//!
//! The parent instance has network access but must never learn plaintext
//! secrets meant for the enclave. In production, the enclave provides a Nitro
//! attestation document in the `recipientAttestationDocument` field; KMS then
//! returns `ciphertextForRecipient`, not plaintext.

use aws_config::{meta::region::RegionProviderChain, BehaviorVersion, Region};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{DataKeySpec, KeyEncryptionMechanism, RecipientInfo};
use aws_sdk_kms::Client;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::ParentConfig;

/// Maximum KMS request/response size (256 KB)
const MAX_KMS_MSG_SIZE: usize = 262144;

/// Allowed KMS API actions (whitelist for safety)
const ALLOWED_KMS_ACTIONS: &[&str] = &[
    "TrentService.Decrypt",
    "TrentService.GenerateDataKey",
    "TrentService.GenerateRandom",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KmsProxyRequest {
    action: String,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    key_spec: Option<String>,
    #[serde(default)]
    number_of_bytes: Option<i32>,
    #[serde(default)]
    ciphertext_blob: Option<String>,
    #[serde(default)]
    recipient_attestation_document: Option<String>,
    #[serde(default)]
    encryption_context: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct KmsProxyResponse {
    ok: bool,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plaintext: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext_blob: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext_for_recipient: Option<String>,
}

#[derive(Debug, Serialize)]
struct KmsProxyErrorResponse<'a> {
    ok: bool,
    action: &'a str,
    error: &'a str,
    message: String,
}

/// Run the KMS proxy: listen for enclave KMS requests, forward to AWS KMS.
pub async fn run(config: &ParentConfig) -> io::Result<()> {
    let listen_addr = format!("127.0.0.1:{}", config.enclave_kms_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("KMS proxy listening on {listen_addr}");

    let region_provider =
        RegionProviderChain::first_try(Some(Region::new(config.kms_region.clone())))
            .or_default_provider();
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    let client = Client::new(&shared_config);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept KMS proxy connection: {e}");
                continue;
            }
        };

        let kms = client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_kms_request(stream, kms).await {
                error!("KMS proxy error: {e}");
            }
        });
    }
}

/// Handle a single KMS request from the enclave.
async fn handle_kms_request(mut stream: tokio::net::TcpStream, kms: Client) -> io::Result<()> {
    let len = stream.read_u32_le().await? as usize;
    if len > MAX_KMS_MSG_SIZE {
        return write_error(
            &mut stream,
            "",
            "request_too_large",
            format!("request exceeds max size {MAX_KMS_MSG_SIZE}"),
        )
        .await;
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let request: KmsProxyRequest = serde_json::from_slice(&buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid JSON: {e}")))?;

    if !ALLOWED_KMS_ACTIONS.iter().any(|a| *a == request.action) {
        warn!("KMS proxy: blocked disallowed action '{}'", request.action);
        return write_error(
            &mut stream,
            &request.action,
            "action_not_allowed",
            format!("disallowed action {}", request.action),
        )
        .await;
    }

    info!("KMS proxy: forwarding {}", request.action);

    match execute_request(&kms, request).await {
        Ok(response) => write_response(&mut stream, &serde_json::to_vec(&response)?).await,
        Err((action, error, message)) => write_error(&mut stream, &action, &error, message).await,
    }
}

async fn execute_request(
    kms: &Client,
    request: KmsProxyRequest,
) -> Result<KmsProxyResponse, (String, String, String)> {
    match request.action.as_str() {
        "TrentService.GenerateDataKey" => generate_data_key(kms, request).await,
        "TrentService.Decrypt" => decrypt(kms, request).await,
        "TrentService.GenerateRandom" => generate_random(kms, request).await,
        other => Err((
            other.to_string(),
            "action_not_allowed".to_string(),
            format!("unsupported action {other}"),
        )),
    }
}

async fn generate_data_key(
    kms: &Client,
    request: KmsProxyRequest,
) -> Result<KmsProxyResponse, (String, String, String)> {
    let key_id = request
        .key_id
        .clone()
        .ok_or_else(|| missing_field("TrentService.GenerateDataKey", "keyId"))?;
    let key_spec = parse_data_key_spec(request.key_spec.as_deref())
        .map_err(|message| ("TrentService.GenerateDataKey".to_string(), "invalid_request".to_string(), message))?;

    let mut builder = kms.generate_data_key().key_id(key_id.clone());
    if let Some(spec) = key_spec {
        builder = builder.key_spec(spec);
    }
    if let Some(number_of_bytes) = request.number_of_bytes {
        builder = builder.number_of_bytes(number_of_bytes);
    }
    if let Some(context) = request.encryption_context {
        builder = builder.set_encryption_context(Some(context));
    }
    if let Some(recipient) = build_recipient(request.recipient_attestation_document)
        .map_err(|message| ("TrentService.GenerateDataKey".to_string(), "invalid_request".to_string(), message))?
    {
        builder = builder.recipient(recipient);
    }

    let response = builder.send().await.map_err(|e| {
        (
            "TrentService.GenerateDataKey".to_string(),
            "kms_error".to_string(),
            e.to_string(),
        )
    })?;

    Ok(KmsProxyResponse {
        ok: true,
        action: "TrentService.GenerateDataKey".to_string(),
        key_id: response.key_id().map(|value| value.to_string()),
        plaintext: response.plaintext().map(blob_to_b64),
        ciphertext_blob: response.ciphertext_blob().map(blob_to_b64),
        ciphertext_for_recipient: response.ciphertext_for_recipient().map(blob_to_b64),
    })
}

async fn decrypt(
    kms: &Client,
    request: KmsProxyRequest,
) -> Result<KmsProxyResponse, (String, String, String)> {
    let ciphertext_blob = request
        .ciphertext_blob
        .ok_or_else(|| missing_field("TrentService.Decrypt", "ciphertextBlob"))
        .and_then(|value| {
            b64_to_blob(&value).map_err(|message| {
                (
                    "TrentService.Decrypt".to_string(),
                    "invalid_request".to_string(),
                    message,
                )
            })
        })?;

    let mut builder = kms.decrypt().ciphertext_blob(ciphertext_blob);
    if let Some(key_id) = request.key_id {
        builder = builder.key_id(key_id);
    }
    if let Some(context) = request.encryption_context {
        builder = builder.set_encryption_context(Some(context));
    }
    if let Some(recipient) = build_recipient(request.recipient_attestation_document)
        .map_err(|message| ("TrentService.Decrypt".to_string(), "invalid_request".to_string(), message))?
    {
        builder = builder.recipient(recipient);
    }

    let response = builder.send().await.map_err(|e| {
        (
            "TrentService.Decrypt".to_string(),
            "kms_error".to_string(),
            e.to_string(),
        )
    })?;

    Ok(KmsProxyResponse {
        ok: true,
        action: "TrentService.Decrypt".to_string(),
        key_id: response.key_id().map(|value| value.to_string()),
        plaintext: response.plaintext().map(blob_to_b64),
        ciphertext_blob: None,
        ciphertext_for_recipient: response.ciphertext_for_recipient().map(blob_to_b64),
    })
}

async fn generate_random(
    kms: &Client,
    request: KmsProxyRequest,
) -> Result<KmsProxyResponse, (String, String, String)> {
    let number_of_bytes = request
        .number_of_bytes
        .ok_or_else(|| missing_field("TrentService.GenerateRandom", "numberOfBytes"))?;

    let mut builder = kms.generate_random().number_of_bytes(number_of_bytes);
    if let Some(recipient) = build_recipient(request.recipient_attestation_document)
        .map_err(|message| ("TrentService.GenerateRandom".to_string(), "invalid_request".to_string(), message))?
    {
        builder = builder.recipient(recipient);
    }

    let response = builder.send().await.map_err(|e| {
        (
            "TrentService.GenerateRandom".to_string(),
            "kms_error".to_string(),
            e.to_string(),
        )
    })?;

    Ok(KmsProxyResponse {
        ok: true,
        action: "TrentService.GenerateRandom".to_string(),
        key_id: None,
        plaintext: response.plaintext().map(blob_to_b64),
        ciphertext_blob: None,
        ciphertext_for_recipient: response.ciphertext_for_recipient().map(blob_to_b64),
    })
}

fn parse_data_key_spec(value: Option<&str>) -> Result<Option<DataKeySpec>, String> {
    match value {
        None => Ok(None),
        Some(spec) => match spec {
            "AES_128" => Ok(Some(DataKeySpec::Aes128)),
            "AES_256" => Ok(Some(DataKeySpec::Aes256)),
            other => Err(format!("unsupported keySpec {other}")),
        },
    }
}

fn build_recipient(
    attestation_document_b64: Option<String>,
) -> Result<Option<RecipientInfo>, String> {
    let Some(document) = attestation_document_b64 else {
        return Ok(None);
    };
    let bytes = BASE64
        .decode(document)
        .map_err(|e| format!("invalid recipient attestationDocument base64: {e}"))?;
    Ok(Some(
        RecipientInfo::builder()
            .attestation_document(Blob::new(bytes))
            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
            .build(),
    ))
}

fn blob_to_b64(blob: &Blob) -> String {
    BASE64.encode(blob.as_ref())
}

fn b64_to_blob(value: &str) -> Result<Blob, String> {
    let bytes = BASE64
        .decode(value)
        .map_err(|e| format!("invalid base64 blob: {e}"))?;
    Ok(Blob::new(bytes))
}

fn missing_field(action: &str, field: &str) -> (String, String, String) {
    (
        action.to_string(),
        "invalid_request".to_string(),
        format!("missing required field {field}"),
    )
}

async fn write_response(stream: &mut tokio::net::TcpStream, data: &[u8]) -> io::Result<()> {
    stream.write_u32_le(data.len() as u32).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

async fn write_error(
    stream: &mut tokio::net::TcpStream,
    action: &str,
    error: &str,
    message: String,
) -> io::Result<()> {
    let body = serde_json::to_vec(&KmsProxyErrorResponse {
        ok: false,
        action,
        error,
        message,
    })?;
    write_response(stream, &body).await
}
