use anchor_lang::prelude::*;

pub mod constants;
pub mod ed25519_utils;
pub mod error;
pub mod instructions;
pub mod state;

use instructions::*;

declare_id!("GjxYKTUpPFhBectiPfKJkUKJnP7MaZU3kEG5kAFyMj3E");

#[program]
pub mod a402_vault {
    use super::*;

    pub fn initialize_vault(
        ctx: Context<InitializeVault>,
        vault_id: u64,
        vault_signer_pubkey: Pubkey,
        auditor_master_pubkey: [u8; 32],
        attestation_policy_hash: [u8; 32],
    ) -> Result<()> {
        instructions::initialize_vault::handler(
            ctx,
            vault_id,
            vault_signer_pubkey,
            auditor_master_pubkey,
            attestation_policy_hash,
        )
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::deposit::handler(ctx, amount)
    }

    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
        withdraw_nonce: u64,
        expires_at: i64,
        enclave_signature: [u8; 64],
    ) -> Result<()> {
        instructions::withdraw::handler(ctx, amount, withdraw_nonce, expires_at, enclave_signature)
    }

    pub fn settle_vault<'info>(
        ctx: Context<'_, '_, 'info, 'info, SettleVault<'info>>,
        batch_id: u64,
        batch_chunk_hash: [u8; 32],
        settlements: Vec<SettlementEntry>,
    ) -> Result<()> {
        instructions::settle_vault::handler(ctx, batch_id, batch_chunk_hash, settlements)
    }

    pub fn record_audit(
        ctx: Context<RecordAudit>,
        batch_id: u64,
        batch_chunk_hash: [u8; 32],
        records: Vec<AuditRecordData>,
    ) -> Result<()> {
        instructions::record_audit::handler(ctx, batch_id, batch_chunk_hash, records)
    }

    pub fn pause_vault(ctx: Context<PauseVault>) -> Result<()> {
        instructions::pause_vault::handler(ctx)
    }

    pub fn announce_migration(
        ctx: Context<AnnounceMigration>,
        successor_vault: Pubkey,
        exit_deadline: i64,
    ) -> Result<()> {
        instructions::announce_migration::handler(ctx, successor_vault, exit_deadline)
    }

    pub fn retire_vault(ctx: Context<RetireVault>) -> Result<()> {
        instructions::retire_vault::handler(ctx)
    }

    pub fn rotate_auditor(
        ctx: Context<RotateAuditor>,
        new_auditor_master_pubkey: [u8; 32],
    ) -> Result<()> {
        instructions::rotate_auditor::handler(ctx, new_auditor_master_pubkey)
    }

    pub fn force_settle_init(
        ctx: Context<ForceSettleInit>,
        participant_kind: u8,
        recipient_ata: Pubkey,
        free_balance: u64,
        locked_balance: u64,
        max_lock_expires_at: i64,
        receipt_nonce: u64,
        receipt_signature: [u8; 64],
        receipt_message: Vec<u8>,
    ) -> Result<()> {
        instructions::force_settle_init::handler(
            ctx,
            participant_kind,
            recipient_ata,
            free_balance,
            locked_balance,
            max_lock_expires_at,
            receipt_nonce,
            receipt_signature,
            receipt_message,
        )
    }

    pub fn force_settle_challenge(
        ctx: Context<ForceSettleChallenge>,
        newer_free_balance: u64,
        newer_locked_balance: u64,
        newer_max_lock_expires_at: i64,
        newer_receipt_nonce: u64,
        newer_receipt_signature: [u8; 64],
        newer_receipt_message: Vec<u8>,
    ) -> Result<()> {
        instructions::force_settle_challenge::handler(
            ctx,
            newer_free_balance,
            newer_locked_balance,
            newer_max_lock_expires_at,
            newer_receipt_nonce,
            newer_receipt_signature,
            newer_receipt_message,
        )
    }

    pub fn force_settle_finalize(ctx: Context<ForceSettleFinalize>) -> Result<()> {
        instructions::force_settle_finalize::handler(ctx)
    }
}
