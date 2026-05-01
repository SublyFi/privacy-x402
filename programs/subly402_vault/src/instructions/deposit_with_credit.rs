use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

use crate::constants::{DEPOSIT_CREDIT_STATUS_PENDING, VAULT_STATUS_ACTIVE};
use crate::error::VaultError;
use crate::state::{DepositCredit, VaultConfig};

#[derive(Accounts)]
#[instruction(amount: u64, deposit_nonce: u64)]
pub struct DepositWithCredit<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    #[account(
        mut,
        constraint = vault_config.status == VAULT_STATUS_ACTIVE @ VaultError::VaultInactive,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        init,
        payer = client,
        space = DepositCredit::LEN,
        seeds = [
            b"deposit_credit",
            vault_config.key().as_ref(),
            client.key().as_ref(),
            &deposit_nonce.to_le_bytes(),
        ],
        bump,
    )]
    pub deposit_credit: Account<'info, DepositCredit>,

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

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<DepositWithCredit>, amount: u64, deposit_nonce: u64) -> Result<()> {
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

    let clock = Clock::get()?;
    let deposit_credit = &mut ctx.accounts.deposit_credit;
    deposit_credit.bump = ctx.bumps.deposit_credit;
    deposit_credit.vault_config = ctx.accounts.vault_config.key();
    deposit_credit.client = ctx.accounts.client.key();
    deposit_credit.deposit_nonce = deposit_nonce;
    deposit_credit.amount = amount;
    deposit_credit.status = DEPOSIT_CREDIT_STATUS_PENDING;
    deposit_credit.created_at = clock.unix_timestamp;
    deposit_credit.applied_state_version = 0;

    Ok(())
}
