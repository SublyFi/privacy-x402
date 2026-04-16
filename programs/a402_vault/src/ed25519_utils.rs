use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions as sysvar_instructions;

use crate::error::VaultError;

pub const PARTICIPANT_RECEIPT_MESSAGE_LEN: usize = 145;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEd25519Signature {
    pub signature: [u8; 64],
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParticipantReceiptMessage {
    pub participant: Pubkey,
    pub participant_kind: u8,
    pub recipient_ata: Pubkey,
    pub free_balance: u64,
    pub locked_balance: u64,
    pub max_lock_expires_at: i64,
    pub nonce: u64,
    pub timestamp: i64,
    pub snapshot_seqno: u64,
    pub vault_config: Pubkey,
}

/// Verify Ed25519 signature via the precompile instruction and return the signed message bytes.
/// The caller is responsible for verifying the message content matches expected parameters.
pub fn verify_ed25519_signature(
    instructions_sysvar: &AccountInfo,
    expected_pubkey: &Pubkey,
) -> Result<Vec<u8>> {
    Ok(verify_ed25519_signature_details(instructions_sysvar, expected_pubkey)?.message)
}

/// Verify Ed25519 signature via the precompile instruction and return the verified signature + message.
pub fn verify_ed25519_signature_details(
    instructions_sysvar: &AccountInfo,
    expected_pubkey: &Pubkey,
) -> Result<VerifiedEd25519Signature> {
    verify_ed25519_signature_details_relative(
        instructions_sysvar,
        1,
        expected_pubkey.as_ref().try_into().unwrap(),
    )
}

pub fn verify_ed25519_signature_details_relative(
    instructions_sysvar: &AccountInfo,
    offset_from_current: usize,
    expected_pubkey: &[u8; 32],
) -> Result<VerifiedEd25519Signature> {
    let current_index = sysvar_instructions::load_current_index_checked(instructions_sysvar)
        .map_err(|_| error!(VaultError::InvalidEd25519Instruction))?;

    require!(
        current_index as usize >= offset_from_current,
        VaultError::InvalidEd25519Instruction
    );

    let target_index = current_index - offset_from_current as u16;

    let ed25519_ix = sysvar_instructions::load_instruction_at_checked(
        target_index as usize,
        instructions_sysvar,
    )
    .map_err(|_| error!(VaultError::InvalidEd25519Instruction))?;

    require!(
        ed25519_ix.program_id == solana_sdk_ids::ed25519_program::ID,
        VaultError::InvalidEd25519Instruction
    );
    let ed25519_index = target_index;

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

    let signature_instruction_index = u16::from_le_bytes([ix_data[4], ix_data[5]]);
    require!(
        instruction_index_refs_embedded_data(signature_instruction_index, ed25519_index),
        VaultError::InvalidEd25519Instruction
    );

    let signature_offset = u16::from_le_bytes([ix_data[2], ix_data[3]]) as usize;
    require!(
        ix_data.len() >= signature_offset + 64,
        VaultError::InvalidEd25519Instruction
    );
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&ix_data[signature_offset..signature_offset + 64]);

    let pubkey_offset = u16::from_le_bytes([ix_data[6], ix_data[7]]) as usize;
    require!(
        ix_data.len() >= pubkey_offset + 32,
        VaultError::InvalidEd25519Instruction
    );

    let public_key_instruction_index = u16::from_le_bytes([ix_data[8], ix_data[9]]);
    require!(
        instruction_index_refs_embedded_data(public_key_instruction_index, ed25519_index),
        VaultError::InvalidEd25519Instruction
    );

    let pubkey_bytes = &ix_data[pubkey_offset..pubkey_offset + 32];
    require!(
        pubkey_bytes == expected_pubkey,
        VaultError::InvalidVaultSigner
    );

    // Extract message data
    let message_instruction_index = u16::from_le_bytes([ix_data[14], ix_data[15]]);
    require!(
        instruction_index_refs_embedded_data(message_instruction_index, ed25519_index),
        VaultError::InvalidEd25519Instruction
    );

    let message_offset = u16::from_le_bytes([ix_data[10], ix_data[11]]) as usize;
    let message_size = u16::from_le_bytes([ix_data[12], ix_data[13]]) as usize;
    require!(
        ix_data.len() >= message_offset + message_size,
        VaultError::InvalidEd25519Instruction
    );

    let message = ix_data[message_offset..message_offset + message_size].to_vec();

    Ok(VerifiedEd25519Signature { signature, message })
}

fn instruction_index_refs_embedded_data(instruction_index: u16, ed25519_index: u16) -> bool {
    instruction_index == u16::MAX || instruction_index == ed25519_index
}

pub fn decode_participant_receipt_message(message: &[u8]) -> Result<ParticipantReceiptMessage> {
    require!(
        message.len() == PARTICIPANT_RECEIPT_MESSAGE_LEN,
        VaultError::InvalidReceiptMessage
    );

    let mut offset = 0;

    let participant = Pubkey::new_from_array(
        message[offset..offset + 32]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );
    offset += 32;

    let participant_kind = message[offset];
    offset += 1;

    let recipient_ata = Pubkey::new_from_array(
        message[offset..offset + 32]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );
    offset += 32;

    let free_balance = u64::from_le_bytes(
        message[offset..offset + 8]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );
    offset += 8;

    let locked_balance = u64::from_le_bytes(
        message[offset..offset + 8]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );
    offset += 8;

    let max_lock_expires_at = i64::from_le_bytes(
        message[offset..offset + 8]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );
    offset += 8;

    let nonce = u64::from_le_bytes(
        message[offset..offset + 8]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );
    offset += 8;

    let timestamp = i64::from_le_bytes(
        message[offset..offset + 8]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );
    offset += 8;

    let snapshot_seqno = u64::from_le_bytes(
        message[offset..offset + 8]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );
    offset += 8;

    let vault_config = Pubkey::new_from_array(
        message[offset..offset + 32]
            .try_into()
            .map_err(|_| error!(VaultError::InvalidReceiptMessage))?,
    );

    Ok(ParticipantReceiptMessage {
        participant,
        participant_kind,
        recipient_ata,
        free_balance,
        locked_balance,
        max_lock_expires_at,
        nonce,
        timestamp,
        snapshot_seqno,
        vault_config,
    })
}

#[cfg(test)]
mod tests {
    use super::instruction_index_refs_embedded_data;

    #[test]
    fn accepts_embedded_ed25519_data_refs() {
        assert!(instruction_index_refs_embedded_data(u16::MAX, 3));
        assert!(instruction_index_refs_embedded_data(3, 3));
    }

    #[test]
    fn rejects_cross_instruction_refs() {
        assert!(!instruction_index_refs_embedded_data(0, 1));
        assert!(!instruction_index_refs_embedded_data(7, 1));
    }
}
