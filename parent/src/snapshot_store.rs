//! Encrypted Snapshot & WAL Store
//!
//! Persists encrypted snapshots and WAL segments from the enclave to local
//! storage (EBS) or S3. The parent instance stores only encrypted blobs —
//! it cannot decrypt them without the KMS data encryption key, which is
//! only available inside an attested enclave.
//!
//! Protocol (over vsock, or TCP for local dev):
//!   Request frame: [1 byte op][4 bytes LE key_len][key bytes][4 bytes LE data_len][data bytes]
//!   Operations:
//!     0x01 = PUT (key, data) → store encrypted blob
//!     0x02 = GET (key)       → retrieve encrypted blob
//!     0x03 = LIST (prefix)   → list keys matching prefix
//!     0x04 = DELETE (key)    → remove encrypted blob
//!   Response frame: [1 byte status][4 bytes LE data_len][data bytes]
//!     status: 0x00 = OK, 0x01 = NOT_FOUND, 0x02 = ERROR

use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::ParentConfig;

const MAX_BLOB_SIZE: usize = 64 * 1024 * 1024; // 64 MB max blob
const MAX_KEY_SIZE: usize = 512;

const OP_PUT: u8 = 0x01;
const OP_GET: u8 = 0x02;
const OP_LIST: u8 = 0x03;
const OP_DELETE: u8 = 0x04;

const STATUS_OK: u8 = 0x00;
const STATUS_NOT_FOUND: u8 = 0x01;
const STATUS_ERROR: u8 = 0x02;

/// Run the snapshot store: accept put/get requests for encrypted blobs.
pub async fn run(config: &ParentConfig) -> io::Result<()> {
    // Ensure snapshot directory exists
    fs::create_dir_all(&config.snapshot_dir).await?;

    let listen_addr = format!("127.0.0.1:{}", config.enclave_snapshot_port);
    let listener = TcpListener::bind(&listen_addr).await?;
    info!(
        "Snapshot store listening on {listen_addr}, dir={}",
        config.snapshot_dir
    );

    let base_dir = PathBuf::from(&config.snapshot_dir);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept snapshot connection: {e}");
                continue;
            }
        };

        let dir = base_dir.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_snapshot_request(stream, &dir).await {
                error!("Snapshot store error: {e}");
            }
        });
    }
}

async fn handle_snapshot_request(
    mut stream: tokio::net::TcpStream,
    base_dir: &Path,
) -> io::Result<()> {
    loop {
        // Read operation byte
        let op = match stream.read_u8().await {
            Ok(op) => op,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };

        match op {
            OP_PUT => handle_put(&mut stream, base_dir).await?,
            OP_GET => handle_get(&mut stream, base_dir).await?,
            OP_LIST => handle_list(&mut stream, base_dir).await?,
            OP_DELETE => handle_delete(&mut stream, base_dir).await?,
            _ => {
                send_error(&mut stream, "unknown operation").await?;
            }
        }
    }
}

async fn handle_put(stream: &mut tokio::net::TcpStream, base_dir: &Path) -> io::Result<()> {
    let key = read_key(stream).await?;
    let data = read_blob(stream).await?;

    let file_path = key_to_path(base_dir, &key);
    if let Some(parent) = file_path.parent() {
        fs::create_dir_all(parent).await?;
    }

    // Write atomically: write to temp file, then rename
    let tmp_path = file_path.with_extension("tmp");
    fs::write(&tmp_path, &data).await?;
    fs::rename(&tmp_path, &file_path).await?;

    info!("Snapshot PUT: {} ({} bytes)", key, data.len());
    send_ok(stream, &[]).await
}

async fn handle_get(stream: &mut tokio::net::TcpStream, base_dir: &Path) -> io::Result<()> {
    let key = read_key(stream).await?;
    let file_path = key_to_path(base_dir, &key);

    match fs::read(&file_path).await {
        Ok(data) => {
            info!("Snapshot GET: {} ({} bytes)", key, data.len());
            send_ok(stream, &data).await
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => send_not_found(stream).await,
        Err(e) => send_error(stream, &format!("read error: {e}")).await,
    }
}

async fn handle_list(stream: &mut tokio::net::TcpStream, base_dir: &Path) -> io::Result<()> {
    let prefix = read_key(stream).await?;

    let mut entries = Vec::new();
    collect_entries(base_dir, base_dir, &prefix, &mut entries).await?;

    let result = serde_json::to_vec(&entries).unwrap_or_default();
    info!(
        "Snapshot LIST: prefix='{}' → {} entries",
        prefix,
        entries.len()
    );
    send_ok(stream, &result).await
}

async fn handle_delete(stream: &mut tokio::net::TcpStream, base_dir: &Path) -> io::Result<()> {
    let key = read_key(stream).await?;
    let file_path = key_to_path(base_dir, &key);

    match fs::remove_file(&file_path).await {
        Ok(()) => {
            info!("Snapshot DELETE: {}", key);
            send_ok(stream, &[]).await
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => send_not_found(stream).await,
        Err(e) => send_error(stream, &format!("delete error: {e}")).await,
    }
}

/// Recursively collect file entries matching a prefix.
async fn collect_entries(
    base_dir: &Path,
    dir: &Path,
    prefix: &str,
    entries: &mut Vec<String>,
) -> io::Result<()> {
    let mut read_dir = match fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()),
    };

    while let Some(entry) = read_dir.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            Box::pin(collect_entries(base_dir, &path, prefix, entries)).await?;
        } else {
            let rel = path
                .strip_prefix(base_dir)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            if rel.starts_with(prefix) && !rel.ends_with(".tmp") {
                entries.push(rel);
            }
        }
    }
    Ok(())
}

/// Convert a logical key to a filesystem path, using SHA-256 prefix
/// to prevent directory traversal and distribute files.
fn key_to_path(base_dir: &Path, key: &str) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let hash = hex::encode(hasher.finalize());
    // Use first 4 hex chars as subdirectory for distribution
    let subdir = &hash[..4];
    base_dir.join(subdir).join(key.replace('/', "_"))
}

async fn read_key(stream: &mut tokio::net::TcpStream) -> io::Result<String> {
    let len = stream.read_u32_le().await? as usize;
    if len > MAX_KEY_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "key too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn read_blob(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
    let len = stream.read_u32_le().await? as usize;
    if len > MAX_BLOB_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "blob too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn send_ok(stream: &mut tokio::net::TcpStream, data: &[u8]) -> io::Result<()> {
    stream.write_u8(STATUS_OK).await?;
    stream.write_u32_le(data.len() as u32).await?;
    if !data.is_empty() {
        stream.write_all(data).await?;
    }
    stream.flush().await
}

async fn send_not_found(stream: &mut tokio::net::TcpStream) -> io::Result<()> {
    stream.write_u8(STATUS_NOT_FOUND).await?;
    stream.write_u32_le(0).await?;
    stream.flush().await
}

async fn send_error(stream: &mut tokio::net::TcpStream, msg: &str) -> io::Result<()> {
    stream.write_u8(STATUS_ERROR).await?;
    let bytes = msg.as_bytes();
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}
