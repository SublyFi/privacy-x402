use anchor_lang::prelude::*;

use crate::constants::{VAULT_STATUS_MIGRATING, VAULT_STATUS_PAUSED, VAULT_STATUS_RETIRED};
use crate::error::VaultError;
use crate::state::VaultConfig;

#[derive(Accounts)]
pub struct RetireVault<'info> {
    pub governance: Signer<'info>,

    #[account(
        mut,
        constraint = vault_config.governance == governance.key(),
        constraint = vault_config.status == VAULT_STATUS_PAUSED
            || vault_config.status == VAULT_STATUS_MIGRATING
            @ VaultError::InvalidStatusTransition,
    )]
    pub vault_config: Account<'info, VaultConfig>,
}

pub fn handler(ctx: Context<RetireVault>) -> Result<()> {
    let vault = &mut ctx.accounts.vault_config;

    if vault.status == VAULT_STATUS_MIGRATING {
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp >= vault.exit_deadline,
            VaultError::ExitDeadlineNotReached
        );
    }

    vault.status = VAULT_STATUS_RETIRED;
    Ok(())
}
