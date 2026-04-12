use anchor_lang::prelude::*;

#[account]
pub struct UsedWithdrawNonce {
    pub bump: u8,
    pub vault: Pubkey,
    pub client: Pubkey,
    pub withdraw_nonce: u64,
}

impl UsedWithdrawNonce {
    pub const LEN: usize = 8  // discriminator
        + 1   // bump
        + 32  // vault
        + 32  // client
        + 8; // withdraw_nonce
}
