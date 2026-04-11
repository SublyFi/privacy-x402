use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

use crate::constants::{MAX_SETTLEMENTS_PER_TX, VAULT_STATUS_ACTIVE, VAULT_STATUS_MIGRATING};
use crate::error::VaultError;
use crate::state::VaultConfig;

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SettlementEntry {
    pub provider_token_account: Pubkey,
    pub amount: u64,
}

#[derive(Accounts)]
pub struct SettleVault<'info> {
    pub vault_signer: Signer<'info>,

    #[account(
        mut,
        constraint = vault_config.vault_signer_pubkey == vault_signer.key()
            @ VaultError::InvalidVaultSigner,
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

    pub token_program: Program<'info, Token>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, 'info, 'info, SettleVault<'info>>,
    _batch_id: u64,
    _batch_chunk_hash: [u8; 32],
    settlements: Vec<SettlementEntry>,
) -> Result<()> {
    require!(
        settlements.len() <= MAX_SETTLEMENTS_PER_TX,
        VaultError::TooManySettlements
    );
    require!(!settlements.is_empty(), VaultError::InvalidAmount);

    let vault = &ctx.accounts.vault_config;

    // Check migration deadline
    if vault.status == VAULT_STATUS_MIGRATING {
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp <= vault.exit_deadline,
            VaultError::ExitDeadlineExceeded
        );
    }

    let governance_key = vault.governance.key();
    let vault_id_bytes = vault.vault_id.to_le_bytes();
    let bump = &[vault.bump];
    let signer_seeds: &[&[&[u8]]] = &[&[
        b"vault_config",
        governance_key.as_ref(),
        vault_id_bytes.as_ref(),
        bump,
    ]];

    let remaining_accounts = &ctx.remaining_accounts;
    require!(
        remaining_accounts.len() == settlements.len(),
        VaultError::InvalidAmount
    );

    let mut total_settled: u64 = 0;

    for (i, entry) in settlements.iter().enumerate() {
        require!(entry.amount > 0, VaultError::InvalidAmount);

        let provider_account = &remaining_accounts[i];
        require!(
            provider_account.key() == entry.provider_token_account,
            VaultError::InvalidAmount
        );

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault_token_account.to_account_info(),
                    to: provider_account.to_account_info(),
                    authority: ctx.accounts.vault_config.to_account_info(),
                },
                signer_seeds,
            ),
            entry.amount,
        )?;

        total_settled = total_settled
            .checked_add(entry.amount)
            .ok_or(VaultError::ArithmeticOverflow)?;
    }

    let vault = &mut ctx.accounts.vault_config;
    vault.lifetime_settled = vault
        .lifetime_settled
        .checked_add(total_settled)
        .ok_or(VaultError::ArithmeticOverflow)?;

    Ok(())
}
