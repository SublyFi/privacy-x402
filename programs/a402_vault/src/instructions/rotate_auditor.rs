use anchor_lang::prelude::*;

use crate::error::VaultError;
use crate::state::VaultConfig;

#[derive(Accounts)]
pub struct RotateAuditor<'info> {
    pub governance: Signer<'info>,

    #[account(
        mut,
        constraint = vault_config.governance == governance.key(),
    )]
    pub vault_config: Account<'info, VaultConfig>,
}

pub fn handler(ctx: Context<RotateAuditor>, new_auditor_master_pubkey: [u8; 32]) -> Result<()> {
    let vault = &mut ctx.accounts.vault_config;
    vault.auditor_master_pubkey = new_auditor_master_pubkey;
    vault.auditor_epoch = vault
        .auditor_epoch
        .checked_add(1)
        .ok_or(VaultError::ArithmeticOverflow)?;
    Ok(())
}
