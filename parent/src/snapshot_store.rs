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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{error, info, warn};

use crate::interconnect::{bind_parent_service, InterconnectStream};
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

    let listener =
        bind_parent_service(config.interconnect_mode, config.enclave_snapshot_port).await?;
    info!(
        mode = config.interconnect_mode.label(),
        port = config.enclave_snapshot_port,
        dir = config.snapshot_dir,
        "Snapshot store listening"
    );

    let base_dir = PathBuf::from(&config.snapshot_dir);

    loop {
        let (stream, peer_label) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept snapshot connection: {e}");
                continue;
            }
        };

        let dir = base_dir.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_snapshot_request(stream, &dir).await {
                error!("Snapshot store error for {peer_label}: {e}");
            }
        });
    }
}

async fn handle_snapshot_request(
    mut stream: InterconnectStream,
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

async fn handle_put<S>(stream: &mut S, base_dir: &Path) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
    write_key_sidecar(&file_path, &key).await?;

    info!("Snapshot PUT: {} ({} bytes)", key, data.len());
    send_ok(stream, &[]).await
}

async fn handle_get<S>(stream: &mut S, base_dir: &Path) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

async fn handle_list<S>(stream: &mut S, base_dir: &Path) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let prefix = read_key(stream).await?;

    let mut entries = Vec::new();
    collect_entries(base_dir, base_dir, &prefix, &mut entries).await?;
    entries.sort();
    entries.dedup();

    let result = serde_json::to_vec(&entries).unwrap_or_default();
    info!(
        "Snapshot LIST: prefix='{}' → {} entries",
        prefix,
        entries.len()
    );
    send_ok(stream, &result).await
}

async fn handle_delete<S>(stream: &mut S, base_dir: &Path) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let key = read_key(stream).await?;
    let file_path = key_to_path(base_dir, &key);

    match fs::remove_file(&file_path).await {
        Ok(()) => {
            let _ = fs::remove_file(key_sidecar_path(&file_path)).await;
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
        } else if is_blob_path(&path) {
            let logical_key = match fs::read_to_string(key_sidecar_path(&path)).await {
                Ok(key) => Some(key),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    legacy_logical_key_from_path(&path)
                }
                Err(e) => return Err(e),
            };

            if let Some(logical_key) = logical_key {
                if logical_key.starts_with(prefix) {
                    entries.push(logical_key);
                }
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

fn key_sidecar_path(blob_path: &Path) -> PathBuf {
    let Some(file_name) = blob_path.file_name() else {
        return blob_path.with_extension("key");
    };
    let sidecar_name = format!("{}.key", file_name.to_string_lossy());
    blob_path.with_file_name(sidecar_name)
}

async fn write_key_sidecar(blob_path: &Path, key: &str) -> io::Result<()> {
    let sidecar_path = key_sidecar_path(blob_path);
    let tmp_path = sidecar_path.with_extension("tmp");
    fs::write(&tmp_path, key.as_bytes()).await?;
    fs::rename(&tmp_path, sidecar_path).await
}

fn is_blob_path(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    !file_name.ends_with(".tmp") && !file_name.ends_with(".key")
}

fn legacy_logical_key_from_path(path: &Path) -> Option<String> {
    let file_name = path.file_name()?.to_str()?;
    parse_legacy_key(file_name)
}

fn parse_legacy_key(file_name: &str) -> Option<String> {
    if let Some(rest) = file_name.strip_prefix("wal_") {
        let (vault, object) = rest.split_once("_wal-")?;
        return Some(format!("wal/{vault}/wal-{object}"));
    }

    if let Some(rest) = file_name.strip_prefix("snapshot_") {
        let (vault, object) = rest.split_once("_snapshot-")?;
        return Some(format!("snapshot/{vault}/snapshot-{object}"));
    }

    if let Some(rest) = file_name.strip_prefix("meta_") {
        let (vault, object) = rest.split_once("_snapshot-data-key.")?;
        return Some(format!("meta/{vault}/snapshot-data-key.{object}"));
    }

    None
}

async fn read_key<S>(stream: &mut S) -> io::Result<String>
where
    S: AsyncRead + Unpin,
{
    let len = stream.read_u32_le().await? as usize;
    if len > MAX_KEY_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "key too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn read_blob<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let len = stream.read_u32_le().await? as usize;
    if len > MAX_BLOB_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "blob too large"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn send_ok<S>(stream: &mut S, data: &[u8]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_u8(STATUS_OK).await?;
    stream.write_u32_le(data.len() as u32).await?;
    if !data.is_empty() {
        stream.write_all(data).await?;
    }
    stream.flush().await
}

async fn send_not_found<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_u8(STATUS_NOT_FOUND).await?;
    stream.write_u32_le(0).await?;
    stream.flush().await
}

async fn send_error<S>(stream: &mut S, msg: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_u8(STATUS_ERROR).await?;
    let bytes = msg.as_bytes();
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMP_DIR_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_snapshot_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let id = NEXT_TEMP_DIR_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "subly402-parent-snapshot-store-{}-{nonce}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn parses_legacy_hashed_storage_names_to_logical_keys() {
        assert_eq!(
            parse_legacy_key("wal_4616xGE_wal-00000000000000000001.json").as_deref(),
            Some("wal/4616xGE/wal-00000000000000000001.json")
        );
        assert_eq!(
            parse_legacy_key("snapshot_4616xGE_snapshot-00000000000000000002.json").as_deref(),
            Some("snapshot/4616xGE/snapshot-00000000000000000002.json")
        );
        assert_eq!(
            parse_legacy_key("meta_4616xGE_snapshot-data-key.ciphertext").as_deref(),
            Some("meta/4616xGE/snapshot-data-key.ciphertext")
        );
        assert!(parse_legacy_key("unrelated_file.json").is_none());
    }

    #[tokio::test]
    async fn collect_entries_lists_logical_keys_from_sidecars() {
        let base_dir = temp_snapshot_dir();
        let key = "wal/4616xGE/wal-00000000000000000001.json";
        let blob_path = key_to_path(&base_dir, key);
        fs::create_dir_all(blob_path.parent().unwrap())
            .await
            .unwrap();
        fs::write(&blob_path, b"encrypted-wal").await.unwrap();
        write_key_sidecar(&blob_path, key).await.unwrap();

        let mut entries = Vec::new();
        collect_entries(&base_dir, &base_dir, "wal/4616xGE", &mut entries)
            .await
            .unwrap();

        assert_eq!(entries, vec![key.to_string()]);
        let _ = fs::remove_dir_all(base_dir).await;
    }

    #[tokio::test]
    async fn collect_entries_lists_legacy_wal_files_without_sidecars() {
        let base_dir = temp_snapshot_dir();
        let legacy_dir = base_dir.join("abcd");
        fs::create_dir_all(&legacy_dir).await.unwrap();
        fs::write(
            legacy_dir.join("wal_4616xGE_wal-00000000000000000001.json"),
            b"encrypted-wal",
        )
        .await
        .unwrap();

        let mut entries = Vec::new();
        collect_entries(&base_dir, &base_dir, "wal/4616xGE", &mut entries)
            .await
            .unwrap();

        assert_eq!(
            entries,
            vec!["wal/4616xGE/wal-00000000000000000001.json".to_string()]
        );
        let _ = fs::remove_dir_all(base_dir).await;
    }
}
