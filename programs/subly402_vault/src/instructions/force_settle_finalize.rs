use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

use crate::error::VaultError;
use crate::state::{ForceSettleRequest, VaultConfig};

#[derive(Accounts)]
pub struct ForceSettleFinalize<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,

    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        mut,
        constraint = force_settle_request.vault == vault_config.key(),
        constraint = !force_settle_request.is_resolved @ VaultError::AlreadyResolved,
    )]
    pub force_settle_request: Account<'info, ForceSettleRequest>,

    #[account(
        mut,
        address = vault_config.vault_token_account,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        address = force_settle_request.recipient_ata,
    )]
    pub recipient_token_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

pub fn handler(ctx: Context<ForceSettleFinalize>) -> Result<()> {
    let clock = Clock::get()?;
    let request = &ctx.accounts.force_settle_request;

    // Dispute window must have elapsed
    require!(
        clock.unix_timestamp > request.dispute_deadline,
        VaultError::DisputeWindowActive
    );

    // Calculate claimable amount
    let free = request.free_balance_due;
    let locked = if clock.unix_timestamp >= request.max_lock_expires_at {
        request.locked_balance_due
    } else {
        0
    };

    let claimable = free
        .checked_add(locked)
        .ok_or(VaultError::ArithmeticOverflow)?;

    if claimable == 0 {
        // Only resolve if locked_balance_due is also zero (i.e., nothing left to claim)
        if request.locked_balance_due == 0 {
            let request = &mut ctx.accounts.force_settle_request;
            request.is_resolved = true;
        }
        return Ok(());
    }

    // Check solvency
    require!(
        ctx.accounts.vault_token_account.amount >= claimable,
        VaultError::VaultInsolvent
    );

    // Transfer
    let vault = &ctx.accounts.vault_config;
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
                to: ctx.accounts.recipient_token_account.to_account_info(),
                authority: ctx.accounts.vault_config.to_account_info(),
            },
            signer_seeds,
        ),
        claimable,
    )?;

    // Update request per design doc:
    // free_balance_due = 0
    // if current_time >= max_lock_expires_at { locked_balance_due = 0 }
    // Both 0 → is_resolved = true
    let request = &mut ctx.accounts.force_settle_request;
    request.free_balance_due = 0;
    if clock.unix_timestamp >= request.max_lock_expires_at {
        request.locked_balance_due = 0;
    }
    if request.free_balance_due == 0 && request.locked_balance_due == 0 {
        request.is_resolved = true;
    }

    Ok(())
}
