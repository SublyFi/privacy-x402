use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;

use crate::error::VaultError;

/// Verify Ed25519 signature via the precompile instruction and return the signed message bytes.
/// The caller is responsible for verifying the message content matches expected parameters.
pub fn verify_ed25519_signature(
    instructions_sysvar: &AccountInfo,
    expected_pubkey: &Pubkey,
) -> Result<Vec<u8>> {
    let current_index =
        sysvar_instructions::load_current_index_checked(instructions_sysvar)
            .map_err(|_| error!(VaultError::InvalidEd25519Instruction))?;

    require!(current_index > 0, VaultError::InvalidEd25519Instruction);

    let ed25519_ix = sysvar_instructions::load_instruction_at_checked(
        (current_index - 1) as usize,
        instructions_sysvar,
    )
    .map_err(|_| error!(VaultError::InvalidEd25519Instruction))?;

    require!(
        ed25519_ix.program_id == solana_sdk_ids::ed25519_program::ID,
        VaultError::InvalidEd25519Instruction
    );

    // Ed25519 instruction data format:
    // [0]: num_signatures (1 byte)
    // [1]: padding (1 byte)
    // [2..4]: signature_offset (2 bytes LE)
    // [4..6]: signature_instruction_index (2 bytes LE)
    // [6..8]: public_key_offset (2 bytes LE)
    // [8..10]: public_key_instruction_index (2 bytes LE)
    // [10..12]: message_data_offset (2 bytes LE)
    // [12..14]: message_data_size (2 bytes LE)
    // [14..16]: message_instruction_index (2 bytes LE)
    let ix_data = &ed25519_ix.data;
    require!(ix_data.len() >= 16, VaultError::InvalidEd25519Instruction);
    require!(ix_data[0] == 1, VaultError::InvalidEd25519Instruction); // exactly 1 signature

    let pubkey_offset = u16::from_le_bytes([ix_data[6], ix_data[7]]) as usize;
    require!(
        ix_data.len() >= pubkey_offset + 32,
        VaultError::InvalidEd25519Instruction
    );

    let pubkey_bytes = &ix_data[pubkey_offset..pubkey_offset + 32];
    require!(
        pubkey_bytes == expected_pubkey.as_ref(),
        VaultError::InvalidVaultSigner
    );

    // Extract message data
    let message_offset = u16::from_le_bytes([ix_data[10], ix_data[11]]) as usize;
    let message_size = u16::from_le_bytes([ix_data[12], ix_data[13]]) as usize;
    require!(
        ix_data.len() >= message_offset + message_size,
        VaultError::InvalidEd25519Instruction
    );

    let message = ix_data[message_offset..message_offset + message_size].to_vec();

    Ok(message)
}
