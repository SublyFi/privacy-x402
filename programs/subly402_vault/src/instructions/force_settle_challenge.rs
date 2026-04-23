use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;

use crate::ed25519_utils::{decode_participant_receipt_message, verify_ed25519_signature_details};
use crate::error::VaultError;
use crate::state::{ForceSettleRequest, VaultConfig};

#[derive(Accounts)]
pub struct ForceSettleChallenge<'info> {
    pub challenger: Signer<'info>,

    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        mut,
        constraint = force_settle_request.vault == vault_config.key(),
        constraint = !force_settle_request.is_resolved @ VaultError::AlreadyResolved,
    )]
    pub force_settle_request: Account<'info, ForceSettleRequest>,

    /// CHECK: Instructions sysvar for Ed25519 signature verification
    #[account(address = sysvar_instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

pub fn handler(
    ctx: Context<ForceSettleChallenge>,
    newer_recipient_ata: Pubkey,
    newer_free_balance: u64,
    newer_locked_balance: u64,
    newer_max_lock_expires_at: i64,
    newer_receipt_nonce: u64,
    newer_receipt_signature: [u8; 64],
    newer_receipt_message: Vec<u8>,
) -> Result<()> {
    let request = &ctx.accounts.force_settle_request;

    // Challenge must be within dispute window
    let clock = Clock::get()?;
    require!(
        clock.unix_timestamp <= request.dispute_deadline,
        VaultError::DisputeWindowExpired
    );

    // Newer receipt must have higher nonce
    require!(
        newer_receipt_nonce > request.receipt_nonce,
        VaultError::StaleReceiptNonce
    );

    // Verify Ed25519 signature
    let verified = verify_ed25519_signature_details(
        &ctx.accounts.instructions_sysvar,
        &ctx.accounts.vault_config.vault_signer_pubkey,
    )?;

    // Verify message matches the newer receipt message
    require!(
        verified.message == newer_receipt_message,
        VaultError::InvalidParticipantReceipt
    );
    require!(
        verified.signature == newer_receipt_signature,
        VaultError::InvalidParticipantReceipt
    );

    let decoded = decode_participant_receipt_message(&newer_receipt_message)?;
    require!(
        decoded.participant == request.participant,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.participant_kind == request.participant_kind,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.recipient_ata == newer_recipient_ata,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.free_balance == newer_free_balance,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.locked_balance == newer_locked_balance,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.max_lock_expires_at == newer_max_lock_expires_at,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.nonce == newer_receipt_nonce,
        VaultError::InvalidReceiptMessage
    );
    require!(
        decoded.vault_config == ctx.accounts.vault_config.key(),
        VaultError::InvalidReceiptMessage
    );

    // Update with newer receipt data
    let request = &mut ctx.accounts.force_settle_request;
    request.recipient_ata = newer_recipient_ata;
    request.free_balance_due = newer_free_balance;
    request.locked_balance_due = newer_locked_balance;
    request.max_lock_expires_at = newer_max_lock_expires_at;
    request.receipt_nonce = newer_receipt_nonce;
    request.receipt_signature = newer_receipt_signature;

    Ok(())
}
