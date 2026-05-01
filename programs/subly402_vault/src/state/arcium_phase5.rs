use anchor_lang::prelude::*;

use crate::constants::{
    AGENT_VAULT_SCALARS, ARCIUM_STATUS_ENFORCED, ARCIUM_STATUS_MIRROR, BUDGET_GRANT_SCALARS,
    BUDGET_GRANT_STATE_SCALARS, WITHDRAWAL_GRANT_SCALARS, WITHDRAWAL_GRANT_STATE_SCALARS,
};

#[account]
pub struct ArciumConfig {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub status: u8,
    pub arcium_program_id: Pubkey,
    pub mxe_account: Pubkey,
    pub cluster_account: Pubkey,
    pub mempool_account: Pubkey,
    pub comp_def_version: u32,
    pub tee_x25519_pubkey: [u8; 32],
    pub attestation_policy_hash: [u8; 32],
    pub strategy_controller: Pubkey,
    pub last_recorded_yield_epoch: u64,
    pub current_yield_index_q64: u128,
    pub min_liquid_reserve_bps: u16,
    pub max_strategy_allocation_bps: u16,
    pub settlement_buffer_amount: u64,
    pub strategy_withdrawal_sla_sec: u64,
}

impl ArciumConfig {
    pub const LEN: usize =
        8 + 1 + 32 + 1 + 32 + 32 + 32 + 32 + 4 + 32 + 32 + 32 + 8 + 16 + 2 + 2 + 8 + 8;

    pub fn writes_enabled(&self) -> bool {
        self.status == ARCIUM_STATUS_MIRROR || self.status == ARCIUM_STATUS_ENFORCED
    }
}

#[account]
pub struct ClientVaultState {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client: Pubkey,
    pub status: u8,
    pub state_version: u64,
    pub pending_offset: u64,
    pub pending_started_at: i64,
    pub agent_vault_ciphertexts: [[u8; 32]; AGENT_VAULT_SCALARS],
    pub agent_vault_nonce: [u8; 16],
}

impl ClientVaultState {
    pub const LEN: usize = 8 + 1 + 32 + 32 + 1 + 8 + 8 + 8 + (32 * AGENT_VAULT_SCALARS) + 16;
}

#[account]
pub struct DepositCredit {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client: Pubkey,
    pub deposit_nonce: u64,
    pub amount: u64,
    pub status: u8,
    pub created_at: i64,
    pub applied_state_version: u64,
}

impl DepositCredit {
    pub const LEN: usize = 8 + 1 + 32 + 32 + 8 + 8 + 1 + 8 + 8;
}

#[account]
pub struct BudgetGrant {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client_vault_state: Pubkey,
    pub client: Pubkey,
    pub budget_id: u64,
    pub request_nonce: u64,
    pub status: u8,
    pub created_at: i64,
    pub expires_at: i64,
    pub state_version_at_authorization: u64,
    pub grant_state_ciphertexts: [[u8; 32]; BUDGET_GRANT_STATE_SCALARS],
    pub grant_state_nonce: [u8; 16],
    pub grant_ciphertexts: [[u8; 32]; BUDGET_GRANT_SCALARS],
    pub grant_nonce: [u8; 16],
}

impl BudgetGrant {
    pub const LEN: usize = 8
        + 1
        + 32
        + 32
        + 32
        + 8
        + 8
        + 1
        + 8
        + 8
        + 8
        + (32 * BUDGET_GRANT_STATE_SCALARS)
        + 16
        + (32 * BUDGET_GRANT_SCALARS)
        + 16;
}

#[account]
pub struct WithdrawalGrant {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client_vault_state: Pubkey,
    pub client: Pubkey,
    pub withdrawal_id: u64,
    pub status: u8,
    pub recipient_ata: Pubkey,
    pub expires_at: i64,
    pub grant_state_ciphertexts: [[u8; 32]; WITHDRAWAL_GRANT_STATE_SCALARS],
    pub grant_state_nonce: [u8; 16],
    pub grant_ciphertexts: [[u8; 32]; WITHDRAWAL_GRANT_SCALARS],
    pub grant_nonce: [u8; 16],
}

impl WithdrawalGrant {
    pub const LEN: usize = 8
        + 1
        + 32
        + 32
        + 32
        + 8
        + 1
        + 32
        + 8
        + (32 * WITHDRAWAL_GRANT_STATE_SCALARS)
        + 16
        + (32 * WITHDRAWAL_GRANT_SCALARS)
        + 16;
}

#[account]
pub struct YieldEpoch {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub epoch_id: u64,
    pub realized_yield_amount: u64,
    pub total_eligible_shares: u64,
    pub previous_yield_index_q64: u128,
    pub new_yield_index_q64: u128,
    pub strategy_receipt_hash: [u8; 32],
    pub status: u8,
}

impl YieldEpoch {
    pub const LEN: usize = 8 + 1 + 32 + 8 + 8 + 8 + 16 + 16 + 32 + 1;
}

#[account]
pub struct RecoveryClaim {
    pub bump: u8,
    pub vault_config: Pubkey,
    pub client_vault_state: Pubkey,
    pub client: Pubkey,
    pub recipient_ata: Pubkey,
    pub recovery_nonce: u64,
    pub status: u8,
    pub free_balance_due: u64,
    pub locked_balance_due: u64,
    pub max_lock_expires_at: i64,
    pub state_version: u64,
    pub initiated_at: i64,
    pub dispute_deadline: i64,
}

impl RecoveryClaim {
    pub const LEN: usize = 8 + 1 + 32 + 32 + 32 + 32 + 8 + 1 + 8 + 8 + 8 + 8 + 8 + 8;
}
