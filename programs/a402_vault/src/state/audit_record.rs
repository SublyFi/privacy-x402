use anchor_lang::prelude::*;

#[account]
pub struct AuditRecord {
    pub bump: u8,
    pub vault: Pubkey,
    pub batch_id: u64,
    pub index: u8,
    pub encrypted_sender: [u8; 64],
    pub encrypted_amount: [u8; 64],
    pub provider: Pubkey,
    pub timestamp: i64,
    pub auditor_epoch: u32,
}

impl AuditRecord {
    pub const LEN: usize = 8  // discriminator
        + 1   // bump
        + 32  // vault
        + 8   // batch_id
        + 1   // index
        + 64  // encrypted_sender
        + 64  // encrypted_amount
        + 32  // provider
        + 8   // timestamp
        + 4; // auditor_epoch
}
