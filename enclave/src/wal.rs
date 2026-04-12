use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::info;

/// WAL entry types for Phase 1
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WalEntry {
    DepositApplied {
        client: String,
        amount: u64,
        slot: u64,
        tx_signature: String,
    },
    ReservationCreated {
        verification_id: String,
        payment_id: String,
        client: String,
        provider_id: String,
        amount: u64,
    },
    ReservationCancelled {
        verification_id: String,
        reason: String,
    },
    ReservationExpired {
        verification_id: String,
    },
    SettlementCommitted {
        settlement_id: String,
        verification_id: String,
        provider_id: String,
        amount: u64,
    },
    ParticipantReceiptIssued {
        participant: String,
        participant_kind: u8,
        nonce: u64,
    },
    BatchSubmitted {
        batch_id: u64,
        provider_count: usize,
        total_amount: u64,
    },
    BatchConfirmed {
        batch_id: u64,
        tx_signature: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalRecord {
    pub seqno: u64,
    pub timestamp: i64,
    pub entry: WalEntry,
}

/// Write-Ahead Log for durable state changes.
/// Phase 1: Simple file-based append-only log (not encrypted).
/// Production: encrypted via KMS, stored on parent instance.
pub struct Wal {
    path: PathBuf,
    seqno: std::sync::atomic::AtomicU64,
}

impl Wal {
    pub async fn new(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.ok();
        }
        // Count existing entries to set seqno
        let seqno = if path.exists() {
            let content = fs::read_to_string(&path).await.unwrap_or_default();
            content.lines().count() as u64
        } else {
            0
        };

        Self {
            path,
            seqno: std::sync::atomic::AtomicU64::new(seqno),
        }
    }

    /// Durably append a WAL entry. Returns only after write is flushed.
    pub async fn append(&self, entry: WalEntry) -> Result<u64, std::io::Error> {
        let seqno = self.seqno.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let now = chrono::Utc::now().timestamp();

        let record = WalRecord {
            seqno,
            timestamp: now,
            entry,
        };

        let mut line = serde_json::to_string(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.flush().await?;
        file.sync_all().await?;

        info!(seqno, "WAL entry appended");
        Ok(seqno)
    }
}
