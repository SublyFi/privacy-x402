use sha2::{Digest, Sha256};

use crate::instructions::record_audit::AuditRecordData;
use crate::instructions::settle_vault::SettlementEntry;

/// Compute the batch chunk hash shared by `settle_vault` and `record_audit`.
///
/// The hash binds the provider-aggregated settlement list and the per-request
/// encrypted audit records into a single atomic chunk identity.
pub fn compute_batch_chunk_hash(
    batch_id: u64,
    settlements: &[SettlementEntry],
    records: &[AuditRecordData],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"subly402-batch-chunk-v1");
    hasher.update(batch_id.to_le_bytes());

    for settlement in settlements {
        hasher.update(settlement.provider_token_account.as_ref());
        hasher.update(settlement.amount.to_le_bytes());
    }

    for record in records {
        hasher.update(&record.encrypted_sender);
        hasher.update(&record.encrypted_amount);
        hasher.update(record.provider.as_ref());
        hasher.update(record.timestamp.to_le_bytes());
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}
