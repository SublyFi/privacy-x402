use tracing::info;

mod egress_relay;
mod ingress_relay;
mod kms_proxy;
mod snapshot_store;

/// Configuration for the parent instance services.
pub struct ParentConfig {
    /// TCP listen address for client/provider ingress (e.g., "0.0.0.0:443")
    pub ingress_listen_addr: String,
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = ParentConfig::default();

    info!("Starting A402 parent instance services");
    info!("  Ingress listen: {}", config.ingress_listen_addr);
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
