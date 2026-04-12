//! Per-participant latest ParticipantReceipt store.
//!
//! The watchtower maintains the most recent signed receipt for every participant
//! (client or provider). When a force_settle_init is observed on-chain with a
//! stale nonce, the challenger module uses the stored receipt to submit a
//! force_settle_challenge.
//!
//! Persistence: file-backed JSON for simplicity. Production could use RocksDB.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::path::PathBuf;
use tokio::fs;
use tracing::{info, warn};

/// A stored ParticipantReceipt with all data needed for on-chain challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredReceipt {
    pub participant: String,
    pub participant_kind: u8,
    pub recipient_ata: String,
    pub free_balance: u64,
    pub locked_balance: u64,
    pub max_lock_expires_at: i64,
    pub nonce: u64,
    pub timestamp: i64,
    pub snapshot_seqno: u64,
    pub vault_config: String,
    /// Ed25519 signature bytes (base64)
    pub signature: String,
    /// Serialized receipt message (base64)
    pub message: String,
}

/// Composite key for per-participant receipts: (vault, participant, participant_kind)
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ReceiptKey {
    pub vault: Pubkey,
    pub participant: Pubkey,
    pub participant_kind: u8,
}

impl ReceiptKey {
    fn storage_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.vault,
            self.participant,
            self.participant_kind
        )
    }
}

pub struct ReceiptStore {
    /// In-memory latest receipts
    receipts: DashMap<String, StoredReceipt>,
    /// File path for persistence
    persist_path: PathBuf,
}

impl ReceiptStore {
    pub async fn new(persist_path: PathBuf) -> Self {
        let store = Self {
            receipts: DashMap::new(),
            persist_path,
        };
        store.load_from_disk().await;
        store
    }

    /// Store a receipt, only if its nonce is strictly newer.
    /// Returns true if the receipt was stored (newer than existing).
    pub fn store_receipt(&self, key: &ReceiptKey, receipt: StoredReceipt) -> bool {
        let storage_key = key.storage_key();

        let should_store = match self.receipts.get(&storage_key) {
            Some(existing) => receipt.nonce > existing.nonce,
            None => true,
        };

        if should_store {
            info!(
                participant = %key.participant,
                kind = key.participant_kind,
                nonce = receipt.nonce,
                "Stored newer receipt"
            );
            self.receipts.insert(storage_key, receipt);
            true
        } else {
            false
        }
    }

    /// Get the latest receipt for a participant.
    pub fn get_receipt(&self, key: &ReceiptKey) -> Option<StoredReceipt> {
        self.receipts.get(&key.storage_key()).map(|r| r.clone())
    }

    /// Get the latest receipt nonce for a participant (0 if none stored).
    pub fn get_nonce(&self, key: &ReceiptKey) -> u64 {
        self.receipts
            .get(&key.storage_key())
            .map(|r| r.nonce)
            .unwrap_or(0)
    }

    /// Get all stored receipts (for status/debug endpoints).
    pub fn all_receipts(&self) -> Vec<(String, StoredReceipt)> {
        self.receipts
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Persist current state to disk.
    pub async fn persist(&self) {
        let entries: Vec<(String, StoredReceipt)> = self
            .receipts
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();

        match serde_json::to_string_pretty(&entries) {
            Ok(json) => {
                if let Some(parent) = self.persist_path.parent() {
                    let _ = fs::create_dir_all(parent).await;
                }
                if let Err(e) = fs::write(&self.persist_path, json).await {
                    warn!(error = %e, "Failed to persist receipt store");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to serialize receipt store");
            }
        }
    }

    /// Load from disk on startup.
    async fn load_from_disk(&self) {
        if !self.persist_path.exists() {
            return;
        }

        match fs::read_to_string(&self.persist_path).await {
            Ok(json) => {
                match serde_json::from_str::<Vec<(String, StoredReceipt)>>(&json) {
                    Ok(entries) => {
                        for (key, receipt) in entries {
                            self.receipts.insert(key, receipt);
                        }
                        info!(
                            count = self.receipts.len(),
                            "Loaded receipts from disk"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to parse receipt store file");
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to read receipt store file");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> ReceiptKey {
        ReceiptKey {
            vault: Pubkey::new_unique(),
            participant: Pubkey::new_unique(),
            participant_kind: 0,
        }
    }

    fn test_receipt(nonce: u64) -> StoredReceipt {
        StoredReceipt {
            participant: Pubkey::new_unique().to_string(),
            participant_kind: 0,
            recipient_ata: Pubkey::new_unique().to_string(),
            free_balance: 1_000_000,
            locked_balance: 0,
            max_lock_expires_at: 0,
            nonce,
            timestamp: 1000,
            snapshot_seqno: 1,
            vault_config: Pubkey::new_unique().to_string(),
            signature: "sig".to_string(),
            message: "msg".to_string(),
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let store = ReceiptStore::new("/tmp/test_receipt_store_1.json".into()).await;
        let key = test_key();

        assert!(store.get_receipt(&key).is_none());

        store.store_receipt(&key, test_receipt(1));
        let stored = store.get_receipt(&key).unwrap();
        assert_eq!(stored.nonce, 1);
    }

    #[tokio::test]
    async fn test_newer_nonce_replaces() {
        let store = ReceiptStore::new("/tmp/test_receipt_store_2.json".into()).await;
        let key = test_key();

        store.store_receipt(&key, test_receipt(1));
        assert!(store.store_receipt(&key, test_receipt(5)));
        assert_eq!(store.get_nonce(&key), 5);
    }

    #[tokio::test]
    async fn test_stale_nonce_rejected() {
        let store = ReceiptStore::new("/tmp/test_receipt_store_3.json".into()).await;
        let key = test_key();

        store.store_receipt(&key, test_receipt(10));
        assert!(!store.store_receipt(&key, test_receipt(5)));
        assert!(!store.store_receipt(&key, test_receipt(10)));
        assert_eq!(store.get_nonce(&key), 10);
    }
}
