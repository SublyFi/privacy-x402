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
        let allowlist = config.egress_allowlist.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_egress_request(enclave_stream, &allowlist).await {
                error!("Egress relay error for {peer_label}: {e}");
            }
        });
    }
}

/// Handle a single egress request from the enclave.
async fn handle_egress_request(
    enclave_stream: InterconnectStream,
    allowlist: &[String],
) -> io::Result<()> {
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

    let (host, port) = match parse_target(target) {
        Ok(parts) => parts,
        Err(reason) => {
            let msg = format!("ERR {reason}\n");
            enclave_write.write_all(msg.as_bytes()).await?;
            return Ok(());
        }
    };

    if !allowlist.is_empty() && !allowlist_matches(allowlist, &host, port) {
        let msg = format!("ERR target {host}:{port} is not allowed\n");
        enclave_write.write_all(msg.as_bytes()).await?;
        return Ok(());
    }

    info!("Egress: connecting to {target}");

    // Connect to external target
    let target_stream = match TcpStream::connect(format!("{host}:{port}")).await {
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

fn parse_target(target: &str) -> Result<(String, u16), &'static str> {
    if let Some(host_end) = target.find("]:").filter(|_| target.starts_with('[')) {
        let host = &target[1..host_end];
        let port = target[host_end + 2..]
            .parse::<u16>()
            .map_err(|_| "invalid port")?;
        if host.is_empty() {
            return Err("empty host");
        }
        return Ok((host.to_string(), port));
    }

    let (host, port) = target.rsplit_once(':').ok_or("missing port")?;
    if host.is_empty() {
        return Err("empty host");
    }
    let port = port.parse::<u16>().map_err(|_| "invalid port")?;
    Ok((host.to_string(), port))
}

fn allowlist_matches(allowlist: &[String], host: &str, port: u16) -> bool {
    allowlist
        .iter()
        .any(|rule| allow_rule_matches(rule, host, port))
}

fn allow_rule_matches(rule: &str, host: &str, port: u16) -> bool {
    let (host_rule, port_rule) = parse_allow_rule(rule);
    let port_matches = port_rule.map(|expected| expected == port).unwrap_or(true);
    if !port_matches {
        return false;
    }

    if host_rule == "*" {
        return true;
    }
    if let Some(suffix) = host_rule.strip_prefix("*.") {
        return host == suffix
            || host
                .strip_suffix(suffix)
                .map(|prefix| prefix.ends_with('.'))
                .unwrap_or(false);
    }

    host_rule.eq_ignore_ascii_case(host)
}

fn parse_allow_rule(rule: &str) -> (&str, Option<u16>) {
    if let Some(host_end) = rule.find("]:").filter(|_| rule.starts_with('[')) {
        let host = &rule[1..host_end];
        let port = rule[host_end + 2..].parse::<u16>().ok();
        return (host, port);
    }

    if let Some((host, port)) = rule.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host, Some(port));
        }
    }

    (rule, None)
}

#[cfg(test)]
mod tests {
    use super::{allow_rule_matches, allowlist_matches, parse_target};

    #[test]
    fn parse_target_accepts_host_port() {
        let parsed = parse_target("api.example.com:443").unwrap();
        assert_eq!(parsed.0, "api.example.com");
        assert_eq!(parsed.1, 443);
    }

    #[test]
    fn allowlist_matches_exact_and_wildcard_rules() {
        assert!(allow_rule_matches(
            "api.example.com:443",
            "api.example.com",
            443
        ));
        assert!(allow_rule_matches(
            "*.example.com:443",
            "rpc.example.com",
            443
        ));
        assert!(allow_rule_matches("*.example.com", "example.com", 443));
        assert!(!allow_rule_matches(
            "api.example.com:443",
            "api.example.com",
            80
        ));
        assert!(!allow_rule_matches(
            "*.example.com:443",
            "api.other.com",
            443
        ));
    }

    #[test]
    fn allowlist_matches_any_rule() {
        let allowlist = vec![
            "rpc.example.com:443".to_string(),
            "*.amazonaws.com:443".to_string(),
        ];
        assert!(allowlist_matches(
            &allowlist,
            "kms.us-east-1.amazonaws.com",
            443
        ));
        assert!(allowlist_matches(&allowlist, "rpc.example.com", 443));
        assert!(!allowlist_matches(&allowlist, "rpc.example.com", 80));
    }
}
