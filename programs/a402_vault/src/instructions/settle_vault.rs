use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use sha2::{Digest, Sha256};

use crate::constants::{MAX_SETTLEMENTS_PER_TX, VAULT_STATUS_ACTIVE, VAULT_STATUS_MIGRATING};
use crate::error::VaultError;
use crate::instructions::record_audit::AuditRecordData;
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

    /// CHECK: Instructions sysvar for verifying atomic pairing with record_audit
    #[account(address = sysvar_instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

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

    verify_record_audit_pairing(
        &ctx.accounts.instructions_sysvar,
        _batch_id,
        _batch_chunk_hash,
        &ctx.accounts.vault_config.key(),
        &settlements,
    )?;

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

fn verify_record_audit_pairing(
    instructions_sysvar: &AccountInfo,
    expected_batch_id: u64,
    expected_batch_chunk_hash: [u8; 32],
    expected_vault_config: &Pubkey,
    expected_settlements: &[SettlementEntry],
) -> Result<()> {
    let current_index = sysvar_instructions::load_current_index_checked(instructions_sysvar)
        .map_err(|_| error!(VaultError::SettleVaultWithoutAudit))?;

    let record_audit_disc = instruction_discriminator("record_audit");

    for i in 0..32u16 {
        if i == current_index {
            continue;
        }

        let ix =
            match sysvar_instructions::load_instruction_at_checked(i as usize, instructions_sysvar)
            {
                Ok(ix) => ix,
                Err(_) => break,
            };

        let Some(parsed) = parse_record_audit_instruction(&ix, record_audit_disc) else {
            continue;
        };

        if parsed.batch_id != expected_batch_id
            || parsed.batch_chunk_hash != expected_batch_chunk_hash
            || ix.accounts.len() < 2
            || ix.accounts[1].pubkey != *expected_vault_config
        {
            continue;
        }

        require!(
            parsed.records.len() == expected_settlements.len(),
            VaultError::AtomicChunkHashMismatch
        );

        for (settlement, record) in expected_settlements.iter().zip(parsed.records.iter()) {
            require!(
                settlement.provider_token_account == record.provider,
                VaultError::AuditRecordIndexOutOfOrder
            );
        }

        return Ok(());
    }

    Err(error!(VaultError::SettleVaultWithoutAudit))
}

struct ParsedRecordAudit {
    batch_id: u64,
    batch_chunk_hash: [u8; 32],
    records: Vec<AuditRecordData>,
}

fn parse_record_audit_instruction(
    ix: &Instruction,
    expected_discriminator: [u8; 8],
) -> Option<ParsedRecordAudit> {
    if ix.program_id != crate::ID || ix.data.len() < 48 || ix.data[..8] != expected_discriminator {
        return None;
    }

    let mut data: &[u8] = &ix.data[8..];
    let batch_id = u64::deserialize(&mut data).ok()?;
    let batch_chunk_hash = <[u8; 32]>::deserialize(&mut data).ok()?;
    let records = Vec::<AuditRecordData>::deserialize(&mut data).ok()?;

    Some(ParsedRecordAudit {
        batch_id,
        batch_chunk_hash,
        records,
    })
}

fn instruction_discriminator(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(format!("global:{name}").as_bytes());
    let hash = hasher.finalize();
    let mut discriminator = [0u8; 8];
    discriminator.copy_from_slice(&hash[..8]);
    discriminator
}
