use sha2::{Digest, Sha256};

pub const ASC_CLAIM_VOUCHER_PREFIX: &str = "SUBLY402-ASC-CLAIM-VOUCHER";
pub const ASC_PAYMENT_MESSAGE_PREFIX: &str = "subly402-asc-pay-v1";
pub const ASC_CLAIM_VOUCHER_PREFIX_WITH_NUL_LEN: usize = ASC_CLAIM_VOUCHER_PREFIX.len() + 1;
pub const ASC_CLAIM_VOUCHER_MESSAGE_LEN: usize =
    ASC_CLAIM_VOUCHER_PREFIX_WITH_NUL_LEN + 32 + 32 + 8 + 32 + 32 + 8 + 32;

#[derive(Debug, Clone)]
pub struct AscClaimVoucherFields {
    pub channel_id_hash: [u8; 32],
    pub request_id_hash: [u8; 32],
    pub amount: u64,
    pub request_hash: [u8; 32],
    pub provider_pubkey: [u8; 32],
    pub issued_at: i64,
    pub vault_config: [u8; 32],
}

pub fn build_asc_payment_message(
    channel_id: &str,
    request_id: &str,
    amount: u64,
    request_hash: &[u8; 32],
) -> Vec<u8> {
    build_asc_payment_message_from_hashes(
        &hash_identifier(channel_id),
        &hash_identifier(request_id),
        amount,
        request_hash,
    )
}

pub fn build_asc_payment_message_from_hashes(
    channel_id_hash: &[u8; 32],
    request_id_hash: &[u8; 32],
    amount: u64,
    request_hash: &[u8; 32],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(ASC_PAYMENT_MESSAGE_PREFIX.len() + 32 + 32 + 8 + 32);
    message.extend_from_slice(ASC_PAYMENT_MESSAGE_PREFIX.as_bytes());
    message.extend_from_slice(channel_id_hash);
    message.extend_from_slice(request_id_hash);
    message.extend_from_slice(&amount.to_le_bytes());
    message.extend_from_slice(request_hash);
    message
}

pub fn build_asc_claim_voucher_message(fields: &AscClaimVoucherFields) -> Vec<u8> {
    let mut message = Vec::with_capacity(ASC_CLAIM_VOUCHER_MESSAGE_LEN);
    message.extend_from_slice(ASC_CLAIM_VOUCHER_PREFIX.as_bytes());
    message.push(0);
    message.extend_from_slice(&fields.channel_id_hash);
    message.extend_from_slice(&fields.request_id_hash);
    message.extend_from_slice(&fields.amount.to_le_bytes());
    message.extend_from_slice(&fields.request_hash);
    message.extend_from_slice(&fields.provider_pubkey);
    message.extend_from_slice(&fields.issued_at.to_le_bytes());
    message.extend_from_slice(&fields.vault_config);
    message
}

pub fn parse_asc_claim_voucher_message(message: &[u8]) -> Option<AscClaimVoucherFields> {
    if message.len() != ASC_CLAIM_VOUCHER_MESSAGE_LEN {
        return None;
    }
    let expected_prefix = [ASC_CLAIM_VOUCHER_PREFIX.as_bytes(), b"\0"].concat();
    let (prefix, rest) = message.split_at(ASC_CLAIM_VOUCHER_PREFIX_WITH_NUL_LEN);
    if prefix != expected_prefix.as_slice() {
        return None;
    }

    let mut offset = 0usize;
    let take_32 = |rest: &[u8], offset: &mut usize| -> Option<[u8; 32]> {
        let bytes: [u8; 32] = rest.get(*offset..*offset + 32)?.try_into().ok()?;
        *offset += 32;
        Some(bytes)
    };
    let channel_id_hash = take_32(rest, &mut offset)?;
    let request_id_hash = take_32(rest, &mut offset)?;
    let amount = u64::from_le_bytes(rest.get(offset..offset + 8)?.try_into().ok()?);
    offset += 8;
    let request_hash = take_32(rest, &mut offset)?;
    let provider_pubkey = take_32(rest, &mut offset)?;
    let issued_at = i64::from_le_bytes(rest.get(offset..offset + 8)?.try_into().ok()?);
    offset += 8;
    let vault_config = take_32(rest, &mut offset)?;

    Some(AscClaimVoucherFields {
        channel_id_hash,
        request_id_hash,
        amount,
        request_hash,
        provider_pubkey,
        issued_at,
        vault_config,
    })
}

pub fn hash_identifier(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_message_binds_request_hash() {
        let message = build_asc_payment_message("ch_demo", "req_demo", 42, &[0xcd; 32]);
        let prefix_len = ASC_PAYMENT_MESSAGE_PREFIX.len();
        assert_eq!(
            &message[..prefix_len],
            ASC_PAYMENT_MESSAGE_PREFIX.as_bytes()
        );
        assert_eq!(
            &message[prefix_len..prefix_len + 32],
            &hash_identifier("ch_demo")
        );
        assert_eq!(
            &message[prefix_len + 32..prefix_len + 64],
            &hash_identifier("req_demo")
        );
        assert_eq!(
            &message[prefix_len + 64..prefix_len + 72],
            &42u64.to_le_bytes()
        );
        assert_eq!(&message[prefix_len + 72..prefix_len + 104], &[0xcd; 32]);
    }

    #[test]
    fn identifier_hash_is_stable() {
        assert_eq!(hash_identifier("ch_demo"), hash_identifier("ch_demo"));
        assert_ne!(hash_identifier("ch_demo"), hash_identifier("ch_other"));
    }

    #[test]
    fn claim_voucher_roundtrips() {
        let fields = AscClaimVoucherFields {
            channel_id_hash: [0x11; 32],
            request_id_hash: [0x22; 32],
            amount: 77,
            request_hash: [0x33; 32],
            provider_pubkey: [0x44; 32],
            issued_at: 1234,
            vault_config: [0x55; 32],
        };

        let message = build_asc_claim_voucher_message(&fields);
        assert_eq!(message.len(), ASC_CLAIM_VOUCHER_MESSAGE_LEN);
        assert_eq!(
            parse_asc_claim_voucher_message(&message).unwrap().amount,
            fields.amount
        );
        assert_eq!(
            parse_asc_claim_voucher_message(&message)
                .unwrap()
                .provider_pubkey,
            fields.provider_pubkey
        );
    }
}
