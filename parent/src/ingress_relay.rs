//! L4 Ingress Relay: TCP → vsock
//!
//! Accepts incoming TCP connections from clients/providers and forwards raw
//! bytes to the Nitro Enclave over vsock. The parent instance never terminates
//! TLS — it is a transparent L4 relay. TLS is terminated inside the enclave.

use std::io;
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::interconnect::{connect_to_enclave, InterconnectMode};
use crate::ParentConfig;

/// Run the ingress relay: listen on TCP, forward to enclave vsock.
pub async fn run(config: &ParentConfig) -> io::Result<()> {
    let listener = TcpListener::bind(&config.ingress_listen_addr).await?;
    info!("Ingress relay listening on {}", config.ingress_listen_addr);

    let enclave_cid = config.enclave_cid;
    let enclave_port = config.enclave_ingress_port;
    let interconnect_mode = config.interconnect_mode;

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
            if let Err(e) =
                relay_tcp_to_vsock(tcp_stream, enclave_cid, enclave_port, interconnect_mode).await
            {
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
    mut tcp_stream: tokio::net::TcpStream,
    enclave_cid: u32,
    enclave_port: u32,
    interconnect_mode: InterconnectMode,
) -> io::Result<()> {
    let mut enclave_stream =
        connect_to_enclave(interconnect_mode, enclave_cid, enclave_port).await?;
    copy_bidirectional(&mut tcp_stream, &mut enclave_stream).await?;

    Ok(())
}
