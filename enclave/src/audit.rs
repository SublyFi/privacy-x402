//! ElGamal Encryption + Hierarchical Key Derivation for Audit Records
//!
//! Per design doc §2.4 and §5.7:
//!   - Master auditor secret → per-provider derived secret via HKDF
//!   - Each audit record encrypted with provider-specific ElGamal public key
//!   - Selective disclosure: reveal derived key for specific provider only
//!
//! Ciphertext format (64 bytes):
//!   C1 = r * G           (32 bytes, compressed Ristretto point)
//!   C2 = data XOR KDF(r * P)  (32 bytes)
//! where r is random, P is the ElGamal public key, G is the basepoint.
//!
//! This is an ECIES-like variant of ElGamal that supports arbitrary 32-byte
//! messages while maintaining the algebraic structure needed for key derivation.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;

/// ElGamal key pair for audit encryption.
#[derive(Clone)]
pub struct ElGamalKeyPair {
    pub secret: Scalar,
    pub public: RistrettoPoint,
    pub public_compressed: [u8; 32],
}

/// Encrypted audit record data ready for on-chain storage.
#[derive(Debug, Clone)]
pub struct EncryptedAuditRecord {
    pub encrypted_sender: [u8; 64],
    pub encrypted_amount: [u8; 64],
    pub provider: Pubkey,
    pub timestamp: i64,
    pub auditor_epoch: u32,
}

/// Derive a provider-specific auditor key from the master secret.
///
/// Uses HKDF-SHA256 with the provider address as info:
///   derived_secret = HKDF-Expand(HKDF-Extract(master_secret), provider_address)
///   derived_pubkey = derived_secret * G
pub fn derive_provider_key(
    master_secret: &[u8; 32],
    provider: &Pubkey,
) -> ElGamalKeyPair {
    let hk = Hkdf::<Sha256>::new(Some(b"a402-audit-v1"), master_secret);
    let mut okm = [0u8; 64];
    hk.expand(provider.as_ref(), &mut okm)
        .expect("HKDF expand should not fail with 64-byte output");

    // Reduce to scalar (mod l)
    let secret = Scalar::from_bytes_mod_order_wide(&okm);
    let public = &secret * RISTRETTO_BASEPOINT_POINT;
    let public_compressed = public.compress().to_bytes();

    ElGamalKeyPair {
        secret,
        public,
        public_compressed,
    }
}

/// Encrypt a 32-byte message using ElGamal (ECIES variant).
///
/// Returns 64 bytes: C1 (32 bytes) || C2 (32 bytes)
///   C1 = r * G
///   C2 = message XOR SHA256(r * P)
pub fn elgamal_encrypt(public_key: &RistrettoPoint, plaintext: &[u8; 32]) -> [u8; 64] {
    let r = Scalar::random(&mut OsRng);
    let c1 = (&r * RISTRETTO_BASEPOINT_POINT).compress();
    let shared_secret = &r * public_key;

    // Derive mask from shared secret
    let mask = kdf_mask(&shared_secret.compress().to_bytes());

    let mut c2 = [0u8; 32];
    for i in 0..32 {
        c2[i] = plaintext[i] ^ mask[i];
    }

    let mut ciphertext = [0u8; 64];
    ciphertext[..32].copy_from_slice(&c1.to_bytes());
    ciphertext[32..].copy_from_slice(&c2);
    ciphertext
}

/// Decrypt a 64-byte ElGamal ciphertext.
///
/// Input: C1 (32 bytes) || C2 (32 bytes)
/// Returns 32-byte plaintext or None if C1 is invalid.
pub fn elgamal_decrypt(secret_key: &Scalar, ciphertext: &[u8; 64]) -> Option<[u8; 32]> {
    let c1_bytes: [u8; 32] = ciphertext[..32].try_into().ok()?;
    let c2: &[u8; 32] = ciphertext[32..].try_into().ok()?;

    let c1 = CompressedRistretto::from_slice(&c1_bytes).ok()?;
    let c1_point = c1.decompress()?;
    let shared_secret = (secret_key * c1_point).compress();

    let mask = kdf_mask(&shared_secret.to_bytes());

    let mut plaintext = [0u8; 32];
    for i in 0..32 {
        plaintext[i] = c2[i] ^ mask[i];
    }

    Some(plaintext)
}

/// Generate an encrypted audit record for a settlement.
///
/// Per design doc §5.7:
///   - Encrypt sender pubkey with provider-derived ElGamal key
///   - Encrypt amount (padded to 32 bytes) with same key
///   - Provider address is stored in plaintext (receiver is public)
pub fn generate_audit_record(
    client: &Pubkey,
    provider: &Pubkey,
    amount: u64,
    auditor_epoch: u32,
    auditor_master_secret: &[u8; 32],
) -> EncryptedAuditRecord {
    let provider_key = derive_provider_key(auditor_master_secret, provider);

    // Encrypt sender pubkey (32 bytes)
    let sender_bytes: [u8; 32] = client.to_bytes();
    let encrypted_sender = elgamal_encrypt(&provider_key.public, &sender_bytes);

    // Encrypt amount (u64 → padded to 32 bytes)
    let mut amount_bytes = [0u8; 32];
    amount_bytes[..8].copy_from_slice(&amount.to_le_bytes());
    let encrypted_amount = elgamal_encrypt(&provider_key.public, &amount_bytes);

    let now = chrono::Utc::now().timestamp();

    EncryptedAuditRecord {
        encrypted_sender,
        encrypted_amount,
        provider: *provider,
        timestamp: now,
        auditor_epoch,
    }
}

/// Decrypt the sender pubkey from an audit record.
pub fn decrypt_sender(
    secret_key: &Scalar,
    encrypted_sender: &[u8; 64],
) -> Option<Pubkey> {
    let bytes = elgamal_decrypt(secret_key, encrypted_sender)?;
    Some(Pubkey::new_from_array(bytes))
}

/// Decrypt the amount from an audit record.
pub fn decrypt_amount(
    secret_key: &Scalar,
    encrypted_amount: &[u8; 64],
) -> Option<u64> {
    let bytes = elgamal_decrypt(secret_key, encrypted_amount)?;
    let amount_bytes: [u8; 8] = bytes[..8].try_into().ok()?;
    Some(u64::from_le_bytes(amount_bytes))
}

/// Derive a KDF mask from a shared secret point.
fn kdf_mask(shared_secret_bytes: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"a402-elgamal-mask-v1");
    hasher.update(shared_secret_bytes);
    let result = hasher.finalize();
    let mut mask = [0u8; 32];
    mask.copy_from_slice(&result);
    mask
}

/// Export a provider-derived secret key for selective disclosure.
/// The recipient can use this to decrypt only that provider's audit records.
pub fn export_provider_key(
    master_secret: &[u8; 32],
    provider: &Pubkey,
) -> [u8; 32] {
    let key_pair = derive_provider_key(master_secret, provider);
    key_pair.secret.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let master_secret = [42u8; 32];
        let provider = Pubkey::new_unique();
        let key_pair = derive_provider_key(&master_secret, &provider);

        let plaintext = [7u8; 32];
        let ciphertext = elgamal_encrypt(&key_pair.public, &plaintext);
        let decrypted = elgamal_decrypt(&key_pair.secret, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_audit_record_generation_and_decryption() {
        let master_secret = [99u8; 32];
        let client = Pubkey::new_unique();
        let provider = Pubkey::new_unique();
        let amount = 1_500_000u64;
        let auditor_epoch = 0;

        let record = generate_audit_record(
            &client,
            &provider,
            amount,
            auditor_epoch,
            &master_secret,
        );

        // Decrypt with provider-derived key
        let provider_key = derive_provider_key(&master_secret, &provider);
        let decrypted_sender = decrypt_sender(&provider_key.secret, &record.encrypted_sender).unwrap();
        let decrypted_amount = decrypt_amount(&provider_key.secret, &record.encrypted_amount).unwrap();

        assert_eq!(decrypted_sender, client);
        assert_eq!(decrypted_amount, amount);
    }

    #[test]
    fn test_selective_disclosure() {
        let master_secret = [55u8; 32];
        let provider_a = Pubkey::new_unique();
        let provider_b = Pubkey::new_unique();
        let client = Pubkey::new_unique();

        let record_a = generate_audit_record(&client, &provider_a, 100, 0, &master_secret);
        let record_b = generate_audit_record(&client, &provider_b, 200, 0, &master_secret);

        // Provider A's key can decrypt provider A's records
        let key_a = derive_provider_key(&master_secret, &provider_a);
        let sender_a = decrypt_sender(&key_a.secret, &record_a.encrypted_sender).unwrap();
        assert_eq!(sender_a, client);

        // Provider A's key CANNOT decrypt provider B's records
        let wrong_decrypt = decrypt_sender(&key_a.secret, &record_b.encrypted_sender);
        // It will decrypt to garbage, not the correct sender
        assert_ne!(wrong_decrypt.unwrap_or(Pubkey::default()), client);

        // Provider B's key can decrypt provider B's records
        let key_b = derive_provider_key(&master_secret, &provider_b);
        let sender_b = decrypt_sender(&key_b.secret, &record_b.encrypted_sender).unwrap();
        assert_eq!(sender_b, client);
    }

    #[test]
    fn test_exported_provider_key_works() {
        let master_secret = [77u8; 32];
        let provider = Pubkey::new_unique();
        let client = Pubkey::new_unique();

        let record = generate_audit_record(&client, &provider, 500, 0, &master_secret);

        // Export key and use it independently
        let exported = export_provider_key(&master_secret, &provider);
        let scalar = Scalar::from_canonical_bytes(exported).unwrap();
        let decrypted = decrypt_sender(&scalar, &record.encrypted_sender).unwrap();
        assert_eq!(decrypted, client);
    }
}
