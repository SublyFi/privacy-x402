use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;

use crate::constants::DISPUTE_WINDOW_SEC;
use crate::ed25519_utils::{decode_participant_receipt_message, verify_ed25519_signature_details};
use crate::error::VaultError;
use crate::state::{ForceSettleRequest, VaultConfig};

#[derive(Accounts)]
#[instruction(
    participant_kind: u8,
)]
pub struct ForceSettleInit<'info> {
    #[account(mut)]
    pub participant: Signer<'info>,

    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        init,
        payer = participant,
        space = ForceSettleRequest::LEN,
        seeds = [
            b"force_settle",
            vault_config.key().as_ref(),
            participant.key().as_ref(),
            &[participant_kind],
        ],
        bump,
    )]
    pub force_settle_request: Account<'info, ForceSettleRequest>,

    /// CHECK: Instructions sysvar for Ed25519 signature verification
    #[account(address = sysvar_instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
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
    // Verify Ed25519 signature via precompile
    let verified = verify_ed25519_signature_details(
        &ctx.accounts.instructions_sysvar,
        &ctx.accounts.vault_config.vault_signer_pubkey,
    )?;

    // Verify message matches receipt_message (the raw ParticipantReceipt bytes)
    require!(
        verified.message == receipt_message,
        VaultError::InvalidParticipantReceipt
    );
    require!(
        verified.signature == receipt_signature,
        VaultError::InvalidParticipantReceipt
    );

    let decoded = decode_participant_receipt_message(&receipt_message)?;
    require!(
        decoded.participant == ctx.accounts.participant.key(),
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.participant_kind == participant_kind,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.recipient_ata == recipient_ata,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.free_balance == free_balance,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.locked_balance == locked_balance,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.max_lock_expires_at == max_lock_expires_at,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.nonce == receipt_nonce,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.vault_config == ctx.accounts.vault_config.key(),
        VaultError::InvalidReceiptMessage
    );

    let clock = Clock::get()?;

    let request = &mut ctx.accounts.force_settle_request;
    request.bump = ctx.bumps.force_settle_request;
    request.vault = ctx.accounts.vault_config.key();
    request.participant = ctx.accounts.participant.key();
    request.participant_kind = participant_kind;
    request.recipient_ata = recipient_ata;
    request.free_balance_due = free_balance;
    request.locked_balance_due = locked_balance;
    request.max_lock_expires_at = max_lock_expires_at;
    request.receipt_nonce = receipt_nonce;
    request.receipt_signature = receipt_signature;
    request.initiated_at = clock.unix_timestamp;
    request.dispute_deadline = clock
        .unix_timestamp
        .checked_add(DISPUTE_WINDOW_SEC)
        .ok_or(VaultError::ArithmeticOverflow)?;
    request.is_resolved = false;

    Ok(())
}
