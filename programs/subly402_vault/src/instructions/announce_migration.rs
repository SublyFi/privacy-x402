use anchor_lang::prelude::*;

use crate::constants::{VAULT_STATUS_ACTIVE, VAULT_STATUS_MIGRATING};
use crate::error::VaultError;
use crate::state::VaultConfig;

#[derive(Accounts)]
pub struct AnnounceMigration<'info> {
    pub governance: Signer<'info>,

    #[account(
        mut,
        constraint = vault_config.governance == governance.key(),
        constraint = vault_config.status == VAULT_STATUS_ACTIVE @ VaultError::VaultInactive,
    )]
    pub vault_config: Account<'info, VaultConfig>,
}

pub fn handler(
    ctx: Context<AnnounceMigration>,
    successor_vault: Pubkey,
    exit_deadline: i64,
) -> Result<()> {
    let clock = Clock::get()?;
    require!(
        exit_deadline > clock.unix_timestamp,
        VaultError::ExitDeadlineExceeded
    );

    let vault = &mut ctx.accounts.vault_config;
    vault.status = VAULT_STATUS_MIGRATING;
    vault.successor_vault = successor_vault;
    vault.exit_deadline = exit_deadline;

    Ok(())
}
