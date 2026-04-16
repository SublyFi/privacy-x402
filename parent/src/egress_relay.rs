//! L4 Egress Relay: vsock → TCP
//!
//! Listens for outbound connection requests from the Nitro Enclave (via vsock)
//! and forwards them to external TCP destinations (Solana RPC, Provider HTTPS).
//!
//! The enclave establishes TLS internally — the parent only sees encrypted bytes.
//! This ensures the parent cannot read or tamper with RPC requests or responses.
//!
//! Protocol:
//!   1. Enclave connects to parent on vsock egress port
//!   2. Enclave sends a connect request: "<host>:<port>\n"
//!   3. Parent opens TCP to the target and relays bytes bidirectionally
//!   4. Parent responds "OK\n" on success or "ERR <reason>\n" on failure

use std::io;
use tokio::io::{split, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{error, info, warn};

use crate::interconnect::{bind_parent_service, InterconnectStream};
use crate::ParentConfig;

/// Run the egress relay: listen on vsock (or TCP for dev), forward to external targets.
pub async fn run(config: &ParentConfig) -> io::Result<()> {
    let listener =
        bind_parent_service(config.interconnect_mode, config.enclave_egress_port).await?;
    info!(
        mode = config.interconnect_mode.label(),
        port = config.enclave_egress_port,
        "Egress relay listening"
    );

    loop {
        let (enclave_stream, peer_label) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept egress connection: {e}");
                continue;
            }
        };

        tokio::spawn(async move {
            if let Err(e) = handle_egress_request(enclave_stream).await {
                error!("Egress relay error for {peer_label}: {e}");
            }
        });
    }
}

/// Handle a single egress request from the enclave.
async fn handle_egress_request(enclave_stream: InterconnectStream) -> io::Result<()> {
    let (enclave_read, mut enclave_write) = split(enclave_stream);
    let mut reader = BufReader::new(enclave_read);

    // Read the target address line: "host:port\n"
    let mut target_line = String::new();
    reader.read_line(&mut target_line).await?;
    let target = target_line.trim();

    if target.is_empty() {
        enclave_write.write_all(b"ERR empty target\n").await?;
        return Ok(());
    }

    info!("Egress: connecting to {target}");

    // Connect to external target
    let target_stream = match TcpStream::connect(target).await {
        Ok(s) => {
            enclave_write.write_all(b"OK\n").await?;
            s
        }
        Err(e) => {
            let msg = format!("ERR {e}\n");
            enclave_write.write_all(msg.as_bytes()).await?;
            return Ok(());
        }
    };

    let (mut target_read, mut target_write) = target_stream.into_split();
    let mut enclave_read = reader.into_inner();

    // Bidirectional relay
    let enclave_to_target = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = enclave_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            target_write.write_all(&buf[..n]).await?;
        }
        target_write.shutdown().await?;
        Ok::<(), io::Error>(())
    };

    let target_to_enclave = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = target_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            enclave_write.write_all(&buf[..n]).await?;
        }
        enclave_write.shutdown().await?;
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        res = enclave_to_target => res?,
        res = target_to_enclave => res?,
    }

    Ok(())
}
