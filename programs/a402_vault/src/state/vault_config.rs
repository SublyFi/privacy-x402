use anchor_lang::prelude::*;

#[account]
pub struct VaultConfig {
    pub bump: u8,
    pub vault_id: u64,
    pub governance: Pubkey,
    pub status: u8,
    pub vault_signer_pubkey: Pubkey,
    pub usdc_mint: Pubkey,
    pub vault_token_account: Pubkey,
    pub auditor_master_pubkey: [u8; 32],
    pub auditor_epoch: u32,
    pub attestation_policy_hash: [u8; 32],
    pub successor_vault: Pubkey,
    pub exit_deadline: i64,
    pub lifetime_deposited: u64,
    pub lifetime_withdrawn: u64,
    pub lifetime_settled: u64,
}

impl VaultConfig {
    pub const LEN: usize = 8  // discriminator
        + 1   // bump
        + 8   // vault_id
        + 32  // governance
        + 1   // status
        + 32  // vault_signer_pubkey
        + 32  // usdc_mint
        + 32  // vault_token_account
        + 32  // auditor_master_pubkey
        + 4   // auditor_epoch
        + 32  // attestation_policy_hash
        + 32  // successor_vault
        + 8   // exit_deadline
        + 8   // lifetime_deposited
        + 8   // lifetime_withdrawn
        + 8;  // lifetime_settled
}
