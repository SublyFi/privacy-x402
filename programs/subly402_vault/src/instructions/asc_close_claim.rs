use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;

use crate::asc_claim::{build_asc_payment_message_from_hashes, parse_asc_claim_voucher_message};
use crate::ed25519_utils::verify_ed25519_signature_details_relative;
use crate::error::VaultError;
use crate::state::{AscCloseClaim, VaultConfig};

#[derive(Accounts)]
#[instruction(
    channel_id_hash: [u8; 32],
    request_id_hash: [u8; 32],
)]
pub struct AscCloseClaimAccounts<'info> {
    #[account(mut)]
    pub caller: Signer<'info>,

    pub vault_config: Account<'info, VaultConfig>,

    #[account(
        init,
        payer = caller,
        space = AscCloseClaim::LEN,
        seeds = [
            b"asc_close_claim",
            vault_config.key().as_ref(),
            channel_id_hash.as_ref(),
            request_id_hash.as_ref(),
        ],
        bump,
    )]
    pub asc_close_claim: Account<'info, AscCloseClaim>,

    /// CHECK: Instructions sysvar for Ed25519 signature verification
    #[account(address = sysvar_instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler(
    ctx: Context<AscCloseClaimAccounts>,
    channel_id_hash: [u8; 32],
    request_id_hash: [u8; 32],
) -> Result<()> {
    let voucher_verified = verify_ed25519_signature_details_relative(
        &ctx.accounts.instructions_sysvar,
        2,
        &ctx.accounts.vault_config.vault_signer_pubkey.to_bytes(),
    )?;
    let voucher = parse_asc_claim_voucher_message(&voucher_verified.message)
        .ok_or(error!(VaultError::InvalidAscClaimVoucher))?;
    require!(
        voucher.channel_id_hash == channel_id_hash,
        VaultError::InvalidAscClaimVoucher
    );
    require!(
        voucher.request_id_hash == request_id_hash,
        VaultError::InvalidAscClaimVoucher
    );
    require!(
        voucher.vault_config == ctx.accounts.vault_config.key().to_bytes(),
        VaultError::InvalidAscClaimVoucher
    );

    let payment_verified = verify_ed25519_signature_details_relative(
        &ctx.accounts.instructions_sysvar,
        1,
        &voucher.provider_pubkey,
    )?;
    let payment_message = build_asc_payment_message_from_hashes(
        &channel_id_hash,
        &request_id_hash,
        voucher.amount,
        &voucher.request_hash,
    );
    require!(
        payment_verified.message == payment_message,
        VaultError::InvalidAscCloseClaim
    );
    require!(
        payment_verified.signature.len() == 64,
        VaultError::InvalidAscCloseClaim
    );

    let mut full_sig_r = [0u8; 32];
    full_sig_r.copy_from_slice(&payment_verified.signature[..32]);
    let mut full_sig_s = [0u8; 32];
    full_sig_s.copy_from_slice(&payment_verified.signature[32..]);

    let clock = Clock::get()?;
    let claim = &mut ctx.accounts.asc_close_claim;
    claim.bump = ctx.bumps.asc_close_claim;
    claim.vault = ctx.accounts.vault_config.key();
    claim.channel_id_hash = channel_id_hash;
    claim.request_id_hash = request_id_hash;
    claim.request_hash = voucher.request_hash;
    claim.provider_pubkey = voucher.provider_pubkey;
    claim.full_sig_r = full_sig_r;
    claim.full_sig_s = full_sig_s;
    claim.amount = voucher.amount;
    claim.voucher_issued_at = voucher.issued_at;
    claim.claimed_at = clock.unix_timestamp;

    Ok(())
}
