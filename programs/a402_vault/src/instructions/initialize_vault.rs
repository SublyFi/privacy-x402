use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

use crate::constants::VAULT_STATUS_ACTIVE;
use crate::state::VaultConfig;

#[derive(Accounts)]
#[instruction(vault_id: u64)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,

    #[account(
        init,
        payer = governance,
        space = VaultConfig::LEN,
        seeds = [b"vault_config", governance.key().as_ref(), &vault_id.to_le_bytes()],
        bump,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    pub usdc_mint: Account<'info, Mint>,

    #[account(
        init,
        payer = governance,
        token::mint = usdc_mint,
        token::authority = vault_config,
        seeds = [b"vault_token", vault_config.key().as_ref()],
        bump,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub rent: Sysvar<'info, Rent>,
}

pub fn handler(
    ctx: Context<InitializeVault>,
    vault_id: u64,
    vault_signer_pubkey: Pubkey,
    auditor_master_pubkey: [u8; 32],
    attestation_policy_hash: [u8; 32],
) -> Result<()> {
    let vault = &mut ctx.accounts.vault_config;

    vault.bump = ctx.bumps.vault_config;
    vault.vault_id = vault_id;
    vault.governance = ctx.accounts.governance.key();
    vault.status = VAULT_STATUS_ACTIVE;
    vault.vault_signer_pubkey = vault_signer_pubkey;
    vault.usdc_mint = ctx.accounts.usdc_mint.key();
    vault.vault_token_account = ctx.accounts.vault_token_account.key();
    vault.auditor_master_pubkey = auditor_master_pubkey;
    vault.auditor_epoch = 0;
    vault.attestation_policy_hash = attestation_policy_hash;
    vault.successor_vault = Pubkey::default();
    vault.exit_deadline = 0;
    vault.lifetime_deposited = 0;
    vault.lifetime_withdrawn = 0;
    vault.lifetime_settled = 0;

    Ok(())
}
