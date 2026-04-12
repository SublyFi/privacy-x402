//! KMS Proxy: Forwards KMS requests from the enclave to AWS KMS.
//!
//! The Nitro Enclave cannot access the network directly. KMS operations
//! (Decrypt, GenerateDataKey) must be proxied through the parent instance.
//!
//! Security model:
//!   - The parent forwards raw KMS API requests but CANNOT decrypt responses.
//!   - KMS key policy restricts Decrypt/GenerateDataKey to requests accompanied
//!     by a valid Nitro Attestation Document with expected PCR values.
//!   - The parent cannot forge attestation documents → cannot access secrets.
//!
//! Protocol (over vsock, or TCP for local dev):
//!   1. Enclave sends a length-prefixed JSON request:
//!      [4 bytes LE length][JSON payload]
//!   2. Parent forwards to KMS HTTPS endpoint
//!   3. Parent returns the raw KMS response in the same framing

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

/// Run the KMS proxy: listen for enclave KMS requests, forward to AWS KMS.
pub async fn run(config: &ParentConfig) -> io::Result<()> {
    // Production: listen on vsock
    // Local dev: listen on TCP loopback
    let listen_addr = format!("127.0.0.1:{}", config.enclave_kms_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("KMS proxy listening on {listen_addr}");

    let kms_region = config.kms_region.clone();

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept KMS proxy connection: {e}");
                continue;
            }
        };

        let region = kms_region.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_kms_request(stream, &region).await {
                error!("KMS proxy error: {e}");
            }
        });
    }
}

/// Handle a single KMS request from the enclave.
async fn handle_kms_request(
    mut stream: tokio::net::TcpStream,
    _kms_region: &str,
) -> io::Result<()> {
    // Read length-prefixed request
    let len = stream.read_u32_le().await? as usize;
    if len > MAX_KMS_MSG_SIZE {
        let err_resp = serde_json::json!({
            "error": "request too large",
            "max_size": MAX_KMS_MSG_SIZE,
        });
        write_response(&mut stream, &serde_json::to_vec(&err_resp)?).await?;
        return Ok(());
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    // Parse the request to validate it's an allowed KMS action
    let request: serde_json::Value = serde_json::from_slice(&buf).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("invalid JSON: {e}"))
    })?;

    let action = request
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !ALLOWED_KMS_ACTIONS.iter().any(|a| *a == action) {
        warn!("KMS proxy: blocked disallowed action '{action}'");
        let err_resp = serde_json::json!({
            "error": "action not allowed",
            "action": action,
        });
        write_response(&mut stream, &serde_json::to_vec(&err_resp)?).await?;
        return Ok(());
    }

    info!("KMS proxy: forwarding {action}");

    // In production: forward to AWS KMS via HTTPS
    //   let kms_endpoint = format!("https://kms.{}.amazonaws.com", kms_region);
    //   let http_client = reqwest::Client::new();
    //   let resp = http_client.post(&kms_endpoint)
    //       .header("X-Amz-Target", action)
    //       .header("Content-Type", "application/x-amz-json-1.1")
    //       .body(buf)
    //       .send().await?;
    //   let resp_bytes = resp.bytes().await?;
    //   write_response(&mut stream, &resp_bytes).await?;

    // Local dev: return a stub response
    let stub_resp = serde_json::json!({
        "status": "ok",
        "action": action,
        "stub": true,
        "message": "KMS proxy stub — production will forward to AWS KMS",
    });
    write_response(&mut stream, &serde_json::to_vec(&stub_resp)?).await?;

    Ok(())
}

/// Write a length-prefixed response back to the enclave.
async fn write_response(
    stream: &mut tokio::net::TcpStream,
    data: &[u8],
) -> io::Result<()> {
    stream.write_u32_le(data.len() as u32).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}
