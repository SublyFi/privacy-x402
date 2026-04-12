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
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::ParentConfig;

const RELAY_BUF_SIZE: usize = 65536;

/// Run the egress relay: listen on vsock (or TCP for dev), forward to external targets.
pub async fn run(config: &ParentConfig) -> io::Result<()> {
    // Production: listen on vsock for enclave egress requests
    //   let listener = VsockListener::bind(VMADDR_CID_ANY, config.enclave_egress_port)?;
    //
    // Local dev: listen on TCP loopback
    let listen_addr = format!("127.0.0.1:{}", config.enclave_egress_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!("Egress relay listening on {listen_addr}");

    loop {
        let (enclave_stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept egress connection: {e}");
                continue;
            }
        };

        tokio::spawn(async move {
            if let Err(e) = handle_egress_request(enclave_stream).await {
                error!("Egress relay error: {e}");
            }
        });
    }
}

/// Handle a single egress request from the enclave.
async fn handle_egress_request(enclave_stream: TcpStream) -> io::Result<()> {
    let (enclave_read, mut enclave_write) = enclave_stream.into_split();
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
    let enclave_read = reader.into_inner();

    // Bidirectional relay
    let enclave_to_target = async {
        let mut buf = vec![0u8; RELAY_BUF_SIZE];
        let mut enclave_read = enclave_read;
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
        let mut buf = vec![0u8; RELAY_BUF_SIZE];
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
