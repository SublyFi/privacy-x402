use anchor_lang::prelude::*;

use crate::constants::{VAULT_STATUS_ACTIVE, VAULT_STATUS_PAUSED};
use crate::error::VaultError;
use crate::state::VaultConfig;

#[derive(Accounts)]
pub struct PauseVault<'info> {
    pub governance: Signer<'info>,

    #[account(
        mut,
        constraint = vault_config.governance == governance.key(),
        constraint = vault_config.status == VAULT_STATUS_ACTIVE @ VaultError::VaultAlreadyPaused,
    )]
    pub vault_config: Account<'info, VaultConfig>,
}

pub fn handler(ctx: Context<PauseVault>) -> Result<()> {
    ctx.accounts.vault_config.status = VAULT_STATUS_PAUSED;
    Ok(())
}
