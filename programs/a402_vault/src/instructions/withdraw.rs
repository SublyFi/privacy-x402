use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

use crate::constants::{VAULT_STATUS_ACTIVE, VAULT_STATUS_MIGRATING};
use crate::ed25519_utils::verify_ed25519_signature;
use crate::error::VaultError;
use crate::state::{UsedWithdrawNonce, VaultConfig};

#[derive(Accounts)]
#[instruction(amount: u64, withdraw_nonce: u64)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub client: Signer<'info>,

    #[account(
        mut,
        constraint = vault_config.status == VAULT_STATUS_ACTIVE
            || vault_config.status == VAULT_STATUS_MIGRATING
            @ VaultError::VaultInactive,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        mut,
        address = vault_config.vault_token_account,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = client_token_account.mint == vault_config.usdc_mint,
        constraint = client_token_account.owner == client.key(),
    )]
    pub client_token_account: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = client,
        space = UsedWithdrawNonce::LEN,
        seeds = [
            b"withdraw_nonce",
            vault_config.key().as_ref(),
            client.key().as_ref(),
            &withdraw_nonce.to_le_bytes(),
        ],
        bump,
    )]
    pub used_withdraw_nonce: Account<'info, UsedWithdrawNonce>,

    /// CHECK: Instructions sysvar for Ed25519 signature verification
    #[account(address = sysvar_instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
}

pub fn handler(
    ctx: Context<Withdraw>,
    amount: u64,
    withdraw_nonce: u64,
    expires_at: i64,
    _enclave_signature: [u8; 64],
) -> Result<()> {
    require!(amount > 0, VaultError::InvalidAmount);

    let vault = &ctx.accounts.vault_config;

    // Check migration deadline
    if vault.status == VAULT_STATUS_MIGRATING {
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp <= vault.exit_deadline,
            VaultError::ExitDeadlineExceeded
        );
    }

    // Check expiration
    let clock = Clock::get()?;
    require!(clock.unix_timestamp <= expires_at, VaultError::WithdrawExpired);

    // Verify Ed25519 signature via precompile instruction
    let signed_message =
        verify_ed25519_signature(&ctx.accounts.instructions_sysvar, &vault.vault_signer_pubkey)?;

    // Verify message content matches WithdrawAuthorization:
    // client (32) + recipient_ata (32) + amount (8) + withdraw_nonce (8) + expires_at (8) + vault_config (32) = 120 bytes
    let mut expected_message = Vec::with_capacity(120);
    expected_message.extend_from_slice(ctx.accounts.client.key.as_ref());
    expected_message.extend_from_slice(ctx.accounts.client_token_account.key().as_ref());
    expected_message.extend_from_slice(&amount.to_le_bytes());
    expected_message.extend_from_slice(&withdraw_nonce.to_le_bytes());
    expected_message.extend_from_slice(&expires_at.to_le_bytes());
    expected_message.extend_from_slice(ctx.accounts.vault_config.key().as_ref());

    require!(
        signed_message == expected_message,
        VaultError::InvalidParticipantReceipt
    );

    // Transfer tokens from vault to client
    let governance_key = vault.governance.key();
    let vault_id_bytes = vault.vault_id.to_le_bytes();
    let bump = &[vault.bump];
    let signer_seeds: &[&[&[u8]]] = &[&[
        b"vault_config",
        governance_key.as_ref(),
        vault_id_bytes.as_ref(),
        bump,
    ]];

    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_token_account.to_account_info(),
                to: ctx.accounts.client_token_account.to_account_info(),
                authority: ctx.accounts.vault_config.to_account_info(),
            },
            signer_seeds,
        ),
        amount,
    )?;

    // Record used nonce
    let nonce_account = &mut ctx.accounts.used_withdraw_nonce;
    nonce_account.bump = ctx.bumps.used_withdraw_nonce;
    nonce_account.vault = ctx.accounts.vault_config.key();
    nonce_account.client = ctx.accounts.client.key();
    nonce_account.withdraw_nonce = withdraw_nonce;

    // Update lifetime counter
    let vault = &mut ctx.accounts.vault_config;
    vault.lifetime_withdrawn = vault
        .lifetime_withdrawn
        .checked_add(amount)
        .ok_or(VaultError::ArithmeticOverflow)?;

    Ok(())
}
