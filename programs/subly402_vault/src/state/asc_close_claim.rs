use anchor_lang::prelude::*;

#[account]
pub struct AscCloseClaim {
    pub bump: u8,
    pub vault: Pubkey,
    pub channel_id_hash: [u8; 32],
    pub request_id_hash: [u8; 32],
    pub request_hash: [u8; 32],
    pub provider_pubkey: [u8; 32],
    pub full_sig_r: [u8; 32],
    pub full_sig_s: [u8; 32],
    pub amount: u64,
    pub voucher_issued_at: i64,
    pub claimed_at: i64,
}

impl AscCloseClaim {
    pub const LEN: usize = 8  // discriminator
        + 1   // bump
        + 32  // vault
        + 32  // channel_id_hash
        + 32  // request_id_hash
        + 32  // request_hash
        + 32  // provider_pubkey
        + 32  // full_sig_r
        + 32  // full_sig_s
        + 8   // amount
        + 8   // voucher_issued_at
        + 8; // claimed_at
}
