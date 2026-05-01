use anchor_lang::prelude::*;

use crate::constants::{
    ARCIUM_STATUS_DISABLED, ARCIUM_STATUS_ENFORCED, ARCIUM_STATUS_MIRROR, ARCIUM_STATUS_PAUSED,
};
use crate::error::VaultError;
use crate::state::{ArciumConfig, VaultConfig};

#[derive(Accounts)]
pub struct InitializeArciumConfig<'info> {
    #[account(mut)]
    pub governance: Signer<'info>,

    #[account(
        constraint = vault_config.governance == governance.key() @ VaultError::Unauthorized,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        init,
        payer = governance,
        space = ArciumConfig::LEN,
        seeds = [b"arcium_config", vault_config.key().as_ref()],
        bump,
    )]
    pub arcium_config: Account<'info, ArciumConfig>,

    pub system_program: Program<'info, System>,
}

#[allow(clippy::too_many_arguments)]
pub fn handler(
    ctx: Context<InitializeArciumConfig>,
    status: u8,
    arcium_program_id: Pubkey,
    mxe_account: Pubkey,
    cluster_account: Pubkey,
    mempool_account: Pubkey,
    comp_def_version: u32,
    tee_x25519_pubkey: [u8; 32],
    strategy_controller: Pubkey,
    min_liquid_reserve_bps: u16,
    max_strategy_allocation_bps: u16,
    settlement_buffer_amount: u64,
    strategy_withdrawal_sla_sec: u64,
) -> Result<()> {
    require!(
        matches!(
            status,
            ARCIUM_STATUS_DISABLED
                | ARCIUM_STATUS_MIRROR
                | ARCIUM_STATUS_ENFORCED
                | ARCIUM_STATUS_PAUSED
        ),
        VaultError::InvalidArciumStatus
    );
    require!(
        status != ARCIUM_STATUS_ENFORCED,
        VaultError::InvalidArciumStatus
    );
    require!(
        min_liquid_reserve_bps <= 10_000 && max_strategy_allocation_bps <= 10_000,
        VaultError::InvalidArciumConfig
    );

    let arcium_config = &mut ctx.accounts.arcium_config;
    arcium_config.bump = ctx.bumps.arcium_config;
    arcium_config.vault_config = ctx.accounts.vault_config.key();
    arcium_config.status = status;
    arcium_config.arcium_program_id = arcium_program_id;
    arcium_config.mxe_account = mxe_account;
    arcium_config.cluster_account = cluster_account;
    arcium_config.mempool_account = mempool_account;
    arcium_config.comp_def_version = comp_def_version;
    arcium_config.tee_x25519_pubkey = tee_x25519_pubkey;
    arcium_config.attestation_policy_hash = ctx.accounts.vault_config.attestation_policy_hash;
    arcium_config.strategy_controller = strategy_controller;
    arcium_config.last_recorded_yield_epoch = 0;
    arcium_config.current_yield_index_q64 = 0;
    arcium_config.min_liquid_reserve_bps = min_liquid_reserve_bps;
    arcium_config.max_strategy_allocation_bps = max_strategy_allocation_bps;
    arcium_config.settlement_buffer_amount = settlement_buffer_amount;
    arcium_config.strategy_withdrawal_sla_sec = strategy_withdrawal_sla_sec;

    Ok(())
}
