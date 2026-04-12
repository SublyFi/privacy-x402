//! L4 Ingress Relay: TCP → vsock
//!
//! Accepts incoming TCP connections from clients/providers and forwards raw
//! bytes to the Nitro Enclave over vsock. The parent instance never terminates
//! TLS — it is a transparent L4 relay. TLS is terminated inside the enclave.

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::ParentConfig;

/// Size of the relay buffer (64 KB)
const RELAY_BUF_SIZE: usize = 65536;

/// Run the ingress relay: listen on TCP, forward to enclave vsock.
pub async fn run(config: &ParentConfig) -> io::Result<()> {
    let listener = TcpListener::bind(&config.ingress_listen_addr).await?;
    info!("Ingress relay listening on {}", config.ingress_listen_addr);

    let enclave_cid = config.enclave_cid;
    let enclave_port = config.enclave_ingress_port;

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept TCP connection: {e}");
                continue;
            }
        };

        info!("Ingress: new connection from {peer_addr}");

        tokio::spawn(async move {
            if let Err(e) = relay_tcp_to_vsock(tcp_stream, enclave_cid, enclave_port).await {
                error!("Ingress relay error for {peer_addr}: {e}");
            }
        });
    }
}

/// Relay bidirectionally between a TCP stream and a vsock connection.
///
/// In production on a Nitro-enabled instance, this uses the vsock AF_VSOCK
/// socket family. For local development, we fall back to a TCP loopback
/// connection to simulate the enclave.
async fn relay_tcp_to_vsock(
    tcp_stream: tokio::net::TcpStream,
    _enclave_cid: u32,
    _enclave_port: u32,
) -> io::Result<()> {
    // Production: connect to enclave via vsock
    //   let vsock_stream = VsockStream::connect(enclave_cid, enclave_port).await?;
    //
    // Local dev: connect to enclave via TCP loopback (enclave runs as a normal process)
    let vsock_stream =
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", _enclave_port)).await?;

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
    let (mut vsock_read, mut vsock_write) = vsock_stream.into_split();

    // Bidirectional relay
    let client_to_enclave = async {
        let mut buf = vec![0u8; RELAY_BUF_SIZE];
        loop {
            let n = tcp_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            vsock_write.write_all(&buf[..n]).await?;
        }
        vsock_write.shutdown().await?;
        Ok::<(), io::Error>(())
    };

    let enclave_to_client = async {
        let mut buf = vec![0u8; RELAY_BUF_SIZE];
        loop {
            let n = vsock_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            tcp_write.write_all(&buf[..n]).await?;
        }
        tcp_write.shutdown().await?;
        Ok::<(), io::Error>(())
    };

    tokio::select! {
        res = client_to_enclave => res?,
        res = enclave_to_client => res?,
    }

    Ok(())
}
