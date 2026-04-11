use anchor_lang::prelude::*;

#[account]
pub struct ForceSettleRequest {
    pub bump: u8,
    pub vault: Pubkey,
    pub participant: Pubkey,
    pub participant_kind: u8,
    pub recipient_ata: Pubkey,
    pub free_balance_due: u64,
    pub locked_balance_due: u64,
    pub max_lock_expires_at: i64,
    pub receipt_nonce: u64,
    pub receipt_signature: [u8; 64],
    pub initiated_at: i64,
    pub dispute_deadline: i64,
    pub is_resolved: bool,
}

impl ForceSettleRequest {
    pub const LEN: usize = 8  // discriminator
        + 1   // bump
        + 32  // vault
        + 32  // participant
        + 1   // participant_kind
        + 32  // recipient_ata
        + 8   // free_balance_due
        + 8   // locked_balance_due
        + 8   // max_lock_expires_at
        + 8   // receipt_nonce
        + 64  // receipt_signature
        + 8   // initiated_at
        + 8   // dispute_deadline
        + 1;  // is_resolved
}
