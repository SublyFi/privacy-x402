use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

use crate::constants::VAULT_STATUS_ACTIVE;
use crate::error::VaultError;
use crate::state::VaultConfig;

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    #[account(
        mut,
        constraint = vault_config.status == VAULT_STATUS_ACTIVE @ VaultError::VaultInactive,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        mut,
        constraint = client_token_account.mint == vault_config.usdc_mint,
        constraint = client_token_account.owner == client.key(),
    )]
    pub client_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        address = vault_config.vault_token_account,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    require!(amount > 0, VaultError::InvalidAmount);

    token::transfer(
        CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.client_token_account.to_account_info(),
                to: ctx.accounts.vault_token_account.to_account_info(),
                authority: ctx.accounts.client.to_account_info(),
            },
        ),
        amount,
    )?;

    let vault = &mut ctx.accounts.vault_config;
    vault.lifetime_deposited = vault
        .lifetime_deposited
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;

    Ok(())
}
