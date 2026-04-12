use serde_json::from_slice;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const OP_PUT: u8 = 0x01;
const OP_GET: u8 = 0x02;
const OP_LIST: u8 = 0x03;
const OP_DELETE: u8 = 0x04;

const STATUS_OK: u8 = 0x00;
const STATUS_NOT_FOUND: u8 = 0x01;
const STATUS_ERROR: u8 = 0x02;

#[derive(Clone, Debug)]
pub struct SnapshotStoreClient {
    addr: String,
}

impl SnapshotStoreClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    pub fn from_env() -> Option<Self> {
        std::env::var("A402_SNAPSHOT_STORE_ADDR")
            .ok()
            .map(Self::new)
    }

    pub async fn put(&self, key: &str, data: &[u8]) -> io::Result<()> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        stream.write_u8(OP_PUT).await?;
        write_key(&mut stream, key).await?;
        write_blob(&mut stream, data).await?;
        match read_response(&mut stream).await? {
            SnapshotResponse::Ok(_) => Ok(()),
            SnapshotResponse::NotFound => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "snapshot store unexpectedly returned not_found for PUT",
            )),
            SnapshotResponse::Error(message) => {
                Err(io::Error::new(io::ErrorKind::Other, message))
            }
        }
    }

    pub async fn get(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        stream.write_u8(OP_GET).await?;
        write_key(&mut stream, key).await?;
        match read_response(&mut stream).await? {
            SnapshotResponse::Ok(data) => Ok(Some(data)),
            SnapshotResponse::NotFound => Ok(None),
            SnapshotResponse::Error(message) => {
                Err(io::Error::new(io::ErrorKind::Other, message))
            }
        }
    }

    pub async fn list(&self, prefix: &str) -> io::Result<Vec<String>> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        stream.write_u8(OP_LIST).await?;
        write_key(&mut stream, prefix).await?;
        match read_response(&mut stream).await? {
            SnapshotResponse::Ok(data) => {
                let items = from_slice::<Vec<String>>(&data).map_err(|error| {
                    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                })?;
                Ok(items)
            }
            SnapshotResponse::NotFound => Ok(Vec::new()),
            SnapshotResponse::Error(message) => {
                Err(io::Error::new(io::ErrorKind::Other, message))
            }
        }
    }

    #[allow(dead_code)]
    pub async fn delete(&self, key: &str) -> io::Result<()> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        stream.write_u8(OP_DELETE).await?;
        write_key(&mut stream, key).await?;
        match read_response(&mut stream).await? {
            SnapshotResponse::Ok(_) | SnapshotResponse::NotFound => Ok(()),
            SnapshotResponse::Error(message) => {
                Err(io::Error::new(io::ErrorKind::Other, message))
            }
        }
    }
}

enum SnapshotResponse {
    Ok(Vec<u8>),
    NotFound,
    Error(String),
}

async fn write_key(stream: &mut TcpStream, key: &str) -> io::Result<()> {
    let bytes = key.as_bytes();
    stream.write_u32_le(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

async fn write_blob(stream: &mut TcpStream, blob: &[u8]) -> io::Result<()> {
    stream.write_u32_le(blob.len() as u32).await?;
    stream.write_all(blob).await?;
    Ok(())
}

async fn read_response(stream: &mut TcpStream) -> io::Result<SnapshotResponse> {
    let status = stream.read_u8().await?;
    let len = stream.read_u32_le().await? as usize;
    let mut buf = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut buf).await?;
    }

    match status {
        STATUS_OK => Ok(SnapshotResponse::Ok(buf)),
        STATUS_NOT_FOUND => Ok(SnapshotResponse::NotFound),
        STATUS_ERROR => Ok(SnapshotResponse::Error(
            String::from_utf8(buf)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?,
        )),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown snapshot store status {other}"),
        )),
    }
}
