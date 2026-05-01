use anchor_lang::prelude::*;

use crate::constants::YIELD_EPOCH_STATUS_CLOSED;
use crate::error::VaultError;
use crate::state::{ArciumConfig, VaultConfig, YieldEpoch};

#[derive(Accounts)]
#[instruction(epoch_id: u64)]
pub struct RecordYieldEpoch<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        constraint = vault_config.key() == arcium_config.vault_config @ VaultError::InvalidArciumConfig,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(mut)]
    pub arcium_config: Account<'info, ArciumConfig>,

    #[account(
        init,
        payer = authority,
        space = YieldEpoch::LEN,
        seeds = [
            b"yield_epoch",
            vault_config.key().as_ref(),
            &epoch_id.to_le_bytes(),
        ],
        bump,
    )]
    pub yield_epoch: Account<'info, YieldEpoch>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<RecordYieldEpoch>,
    epoch_id: u64,
    realized_yield_amount: u64,
    total_eligible_shares: u64,
    strategy_receipt_hash: [u8; 32],
) -> Result<()> {
    let authority = ctx.accounts.authority.key();
    require!(
        authority == ctx.accounts.vault_config.governance
            || authority == ctx.accounts.arcium_config.strategy_controller,
        VaultError::Unauthorized
    );
    require!(
        epoch_id
            == ctx
                .accounts
                .arcium_config
                .last_recorded_yield_epoch
                .checked_add(1)
                .ok_or(VaultError::ArithmeticOverflow)?,
        VaultError::InvalidYieldEpoch
    );

    let previous_yield_index_q64 = ctx.accounts.arcium_config.current_yield_index_q64;
    let index_delta_q64 = if total_eligible_shares == 0 {
        0
    } else {
        let numerator = (realized_yield_amount as u128)
            .checked_shl(64)
            .ok_or(VaultError::ArithmeticOverflow)?;
        numerator / total_eligible_shares as u128
    };
    let new_yield_index_q64 = previous_yield_index_q64
        .checked_add(index_delta_q64)
        .ok_or(VaultError::ArithmeticOverflow)?;

    let yield_epoch = &mut ctx.accounts.yield_epoch;
    yield_epoch.bump = ctx.bumps.yield_epoch;
    yield_epoch.vault_config = ctx.accounts.vault_config.key();
    yield_epoch.epoch_id = epoch_id;
    yield_epoch.realized_yield_amount = realized_yield_amount;
    yield_epoch.total_eligible_shares = total_eligible_shares;
    yield_epoch.previous_yield_index_q64 = previous_yield_index_q64;
    yield_epoch.new_yield_index_q64 = new_yield_index_q64;
    yield_epoch.strategy_receipt_hash = strategy_receipt_hash;
    yield_epoch.status = YIELD_EPOCH_STATUS_CLOSED;

    let arcium_config = &mut ctx.accounts.arcium_config;
    arcium_config.last_recorded_yield_epoch = epoch_id;
    arcium_config.current_yield_index_q64 = new_yield_index_q64;

    Ok(())
}
