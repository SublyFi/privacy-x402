use std::env;
use tracing::info;

mod egress_relay;
mod ingress_relay;
mod interconnect;
mod kms_proxy;
mod snapshot_store;

use interconnect::InterconnectMode;

/// Configuration for the parent instance services.
pub struct ParentConfig {
    /// TCP listen address for client/provider ingress (e.g., "0.0.0.0:443")
    pub ingress_listen_addr: String,
    /// Transport used between the parent instance and enclave
    pub interconnect_mode: InterconnectMode,
    /// vsock CID of the enclave
    pub enclave_cid: u32,
    /// vsock port the enclave listens on for ingress
    pub enclave_ingress_port: u32,
    /// vsock port the enclave sends egress requests to
    pub enclave_egress_port: u32,
    /// vsock port for KMS proxy requests
    pub enclave_kms_port: u32,
    /// Local directory for encrypted snapshot/WAL storage
    pub snapshot_dir: String,
    /// vsock port the enclave uses for snapshot I/O
    pub enclave_snapshot_port: u32,
    /// AWS region for KMS
    pub kms_region: String,
}

impl Default for ParentConfig {
    fn default() -> Self {
        Self {
            ingress_listen_addr: "0.0.0.0:443".to_string(),
            interconnect_mode: InterconnectMode::Tcp,
            enclave_cid: 16, // Default Nitro enclave CID
            enclave_ingress_port: 5000,
            enclave_egress_port: 5001,
            enclave_kms_port: 5002,
            snapshot_dir: "/var/lib/a402/snapshots".to_string(),
            enclave_snapshot_port: 5003,
            kms_region: "us-east-1".to_string(),
        }
    }
}

impl ParentConfig {
    fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            ingress_listen_addr: env::var("A402_PARENT_INGRESS_LISTEN")
                .unwrap_or(defaults.ingress_listen_addr),
            interconnect_mode: InterconnectMode::from_env_var(
                "A402_PARENT_INTERCONNECT_MODE",
                defaults.interconnect_mode,
            ),
            enclave_cid: read_env_u32("A402_ENCLAVE_CID").unwrap_or(defaults.enclave_cid),
            enclave_ingress_port: read_env_u32("A402_ENCLAVE_INGRESS_PORT")
                .unwrap_or(defaults.enclave_ingress_port),
            enclave_egress_port: read_env_u32("A402_ENCLAVE_EGRESS_PORT")
                .unwrap_or(defaults.enclave_egress_port),
            enclave_kms_port: read_env_u32("A402_ENCLAVE_KMS_PORT")
                .unwrap_or(defaults.enclave_kms_port),
            snapshot_dir: env::var("A402_SNAPSHOT_DIR").unwrap_or(defaults.snapshot_dir),
            enclave_snapshot_port: read_env_u32("A402_ENCLAVE_SNAPSHOT_PORT")
                .unwrap_or(defaults.enclave_snapshot_port),
            kms_region: env::var("A402_KMS_REGION")
                .or_else(|_| env::var("AWS_REGION"))
                .unwrap_or(defaults.kms_region),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = ParentConfig::from_env();

    info!("Starting A402 parent instance services");
    info!("  Ingress listen: {}", config.ingress_listen_addr);
    info!("  Interconnect: {}", config.interconnect_mode.label());
    info!("  Enclave CID: {}", config.enclave_cid);
    info!("  Snapshot dir: {}", config.snapshot_dir);

    // Launch all relay services concurrently
    tokio::select! {
        res = ingress_relay::run(&config) => {
            if let Err(e) = res {
                tracing::error!("Ingress relay exited: {e}");
            }
        }
        res = egress_relay::run(&config) => {
            if let Err(e) = res {
                tracing::error!("Egress relay exited: {e}");
            }
        }
        res = kms_proxy::run(&config) => {
            if let Err(e) = res {
                tracing::error!("KMS proxy exited: {e}");
            }
        }
        res = snapshot_store::run(&config) => {
            if let Err(e) = res {
                tracing::error!("Snapshot store exited: {e}");
            }
        }
    }
}

fn read_env_u32(name: &str) -> Option<u32> {
    env::var(name).ok().map(|value| {
        value
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a valid u32"))
    })
}
