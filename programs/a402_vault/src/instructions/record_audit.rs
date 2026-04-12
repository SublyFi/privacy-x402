use anchor_lang::prelude::*;

use crate::constants::{VAULT_STATUS_ACTIVE, VAULT_STATUS_MIGRATING};
use crate::error::VaultError;
use crate::state::VaultConfig;

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AuditRecordData {
    pub encrypted_sender: [u8; 64],
    pub encrypted_amount: [u8; 64],
    pub provider: Pubkey,
    pub timestamp: i64,
}

#[derive(Accounts)]
#[instruction(batch_id: u64, _batch_chunk_hash: [u8; 32], _records: Vec<AuditRecordData>)]
pub struct RecordAudit<'info> {
    #[account(mut)]
    pub vault_signer: Signer<'info>,

    #[account(
        constraint = vault_config.vault_signer_pubkey == vault_signer.key()
            @ VaultError::InvalidVaultSigner,
        constraint = vault_config.status == VAULT_STATUS_ACTIVE
            || vault_config.status == VAULT_STATUS_MIGRATING
            @ VaultError::VaultInactive,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    _ctx: Context<RecordAudit>,
    _batch_id: u64,
    _batch_chunk_hash: [u8; 32],
    _records: Vec<AuditRecordData>,
) -> Result<()> {
    // Phase 2: Full implementation with atomic settle_vault + record_audit pairing
    // Phase 1: Stub — audit records are not yet required
    Ok(())
}
