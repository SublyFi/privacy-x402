use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;

use crate::constants::{MAX_ATOMIC_AUDITS_PER_TX, VAULT_STATUS_ACTIVE, VAULT_STATUS_MIGRATING};
use crate::error::VaultError;
use crate::state::{AuditRecord, VaultConfig};

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AuditRecordData {
    pub encrypted_sender: [u8; 64],
    pub encrypted_amount: [u8; 64],
    pub provider: Pubkey,
    pub timestamp: i64,
}

#[derive(Accounts)]
#[instruction(batch_id: u64, _batch_chunk_hash: [u8; 32], _records: Vec<AuditRecordData>)]
pub struct RecordAudit<'info> {
    #[account(mut)]
    pub vault_signer: Signer<'info>,

    #[account(
        constraint = vault_config.vault_signer_pubkey == vault_signer.key()
            @ VaultError::InvalidVaultSigner,
        constraint = vault_config.status == VAULT_STATUS_ACTIVE
            || vault_config.status == VAULT_STATUS_MIGRATING
            @ VaultError::VaultInactive,
    )]
    pub vault_config: Account<'info, VaultConfig>,

    /// CHECK: Instructions sysvar for verifying atomic pairing with settle_vault
    #[account(address = sysvar_instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

pub fn handler<'info>(
    ctx: Context<'_, '_, 'info, 'info, RecordAudit<'info>>,
    batch_id: u64,
    batch_chunk_hash: [u8; 32],
    records: Vec<AuditRecordData>,
) -> Result<()> {
    require!(
        !records.is_empty() && records.len() <= MAX_ATOMIC_AUDITS_PER_TX,
        VaultError::InvalidAmount
    );

    // Check migration deadline
    let vault = &ctx.accounts.vault_config;
    if vault.status == VAULT_STATUS_MIGRATING {
        let clock = Clock::get()?;
        require!(
            clock.unix_timestamp <= vault.exit_deadline,
            VaultError::ExitDeadlineExceeded
        );
    }

    // Verify atomic pairing: a settle_vault instruction must exist in the same tx
    // with matching batch_id and batch_chunk_hash
    verify_settle_vault_pairing(
        &ctx.accounts.instructions_sysvar,
        batch_id,
        batch_chunk_hash,
        &ctx.accounts.vault_config.key(),
    )?;

    // Create AuditRecord PDAs via remaining_accounts
    let remaining = &ctx.remaining_accounts;
    require!(
        remaining.len() == records.len(),
        VaultError::InvalidAmount
    );

    let vault_key = ctx.accounts.vault_config.key();
    let auditor_epoch = ctx.accounts.vault_config.auditor_epoch;

    for (i, record_data) in records.iter().enumerate() {
        let index = i as u8;

        // Verify PDA derivation
        let (expected_pda, bump) = Pubkey::find_program_address(
            &[
                b"audit",
                vault_key.as_ref(),
                &batch_id.to_le_bytes(),
                &[index],
            ],
            ctx.program_id,
        );

        let audit_account = &remaining[i];
        require!(
            audit_account.key() == expected_pda,
            VaultError::AuditRecordIndexOutOfOrder
        );

        // Create and initialize the AuditRecord account
        let space = AuditRecord::LEN;
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(space);

        let batch_id_bytes = batch_id.to_le_bytes();
        let seeds: &[&[u8]] = &[
            b"audit",
            vault_key.as_ref(),
            &batch_id_bytes,
            &[index],
            &[bump],
        ];

        anchor_lang::system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.vault_signer.to_account_info(),
                    to: audit_account.to_account_info(),
                },
                &[seeds],
            ),
            lamports,
            space as u64,
            ctx.program_id,
        )?;

        // Write discriminator + data
        let mut data = audit_account.try_borrow_mut_data()?;
        let disc = AuditRecord::DISCRIMINATOR;
        data[..8].copy_from_slice(&disc);

        let audit_record = AuditRecord {
            bump,
            vault: vault_key,
            batch_id,
            index,
            encrypted_sender: record_data.encrypted_sender,
            encrypted_amount: record_data.encrypted_amount,
            provider: record_data.provider,
            timestamp: record_data.timestamp,
            auditor_epoch,
        };

        let serialized = audit_record.try_to_vec()?;
        data[8..8 + serialized.len()].copy_from_slice(&serialized);
    }

    Ok(())
}

/// Anchor discriminator for settle_vault: sha256("global:settle_vault")[..8]
fn settle_vault_discriminator() -> [u8; 8] {
    use anchor_lang::solana_program::hash::hash;
    let full = hash(b"global:settle_vault");
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&full.to_bytes()[..8]);
    disc
}

/// Verify that a settle_vault instruction exists in the same transaction
/// with matching batch_id and batch_chunk_hash.
///
/// Per design doc §6.3: record_audit must be paired with settle_vault.
/// Standalone execution is rejected.
fn verify_settle_vault_pairing(
    instructions_sysvar: &AccountInfo,
    expected_batch_id: u64,
    expected_batch_chunk_hash: [u8; 32],
    expected_vault_config: &Pubkey,
) -> Result<()> {
    let current_index = sysvar_instructions::load_current_index_checked(instructions_sysvar)
        .map_err(|_| error!(VaultError::RecordAuditWithoutSettle))?;

    let settle_disc = settle_vault_discriminator();

    // Iterate through all instructions in the transaction
    // Try indices 0..16 (practical max for Solana tx)
    for i in 0..16u16 {
        if i == current_index {
            continue; // Skip self
        }

        let ix = match sysvar_instructions::load_instruction_at_checked(i as usize, instructions_sysvar) {
            Ok(ix) => ix,
            Err(_) => break, // No more instructions
        };

        // Check if this is our program's settle_vault instruction
        if ix.program_id != crate::ID {
            continue;
        }

        // settle_vault instruction data layout:
        //   [8 bytes discriminator][8 bytes batch_id][32 bytes batch_chunk_hash]...
        if ix.data.len() < 48 {
            continue;
        }

        if ix.data[..8] != settle_disc {
            continue;
        }

        // Extract batch_id (bytes 8..16, little-endian u64)
        let batch_id_bytes: [u8; 8] = ix.data[8..16].try_into().unwrap();
        let batch_id = u64::from_le_bytes(batch_id_bytes);

        // Extract batch_chunk_hash (bytes 16..48)
        let chunk_hash: [u8; 32] = ix.data[16..48].try_into().unwrap();

        if batch_id == expected_batch_id && chunk_hash == expected_batch_chunk_hash {
            // Also verify the vault_config account matches
            // In settle_vault accounts: [vault_signer, vault_config, ...]
            if ix.accounts.len() >= 2 && ix.accounts[1].pubkey == *expected_vault_config {
                return Ok(());
            }
        }
    }

    Err(error!(VaultError::RecordAuditWithoutSettle))
}
