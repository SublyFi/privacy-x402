//! Ed25519 Adaptor Signatures for Atomic Service Channels (Phase 3)
//!
//! Implements the adaptor signature scheme on Ed25519 (Aumayr et al., 2021)
//! for Exec-Pay-Deliver atomicity per design doc §5.5.
//!
//! Protocol:
//!   1. Signer picks random r, computes R' = r·G
//!   2. Adaptor point T = t·G is public (secret t known only to provider TEE)
//!   3. Pre-signature: c = H(R'+T || pk || m), s' = r + c·sk
//!   4. Verification: s'·G == R' + c·pk  (using adapted nonce R'+T in hash)
//!   5. Adapt: s = s' + t, signature = (R'+T, s) — valid Ed25519
//!   6. Extract: t = s - s' (recover secret from published signature)

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Adaptor pre-signature: (R', s') where R' is the unadapted nonce point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptorPreSignature {
    /// R' = r·G (unadapted nonce point, compressed)
    pub r_prime: [u8; 32],
    /// s' = r + H(R'+T, pk, m)·sk (pre-signature scalar)
    pub s_prime: [u8; 32],
}

/// A full adapted Ed25519 signature: (R, s) where R = R'+T.
#[derive(Debug, Clone)]
pub struct AdaptedSignature {
    /// R = R' + T (adapted nonce point, compressed)
    pub r_bytes: [u8; 32],
    /// s = s' + t (adapted scalar)
    pub s_bytes: [u8; 32],
}

/// Adaptor key pair: secret scalar t and public point T = t·G.
#[derive(Debug, Clone)]
pub struct AdaptorKeyPair {
    pub secret: Scalar,
    pub public: EdwardsPoint,
    pub public_compressed: [u8; 32],
}

impl AdaptorKeyPair {
    /// Generate a fresh random adaptor key pair.
    pub fn generate() -> Self {
        let secret = Scalar::random(&mut OsRng);
        let public = &secret * ED25519_BASEPOINT_POINT;
        let public_compressed = public.compress().to_bytes();
        AdaptorKeyPair {
            secret,
            public,
            public_compressed,
        }
    }

    /// Reconstruct from a known secret scalar.
    pub fn from_secret(secret: Scalar) -> Self {
        let public = &secret * ED25519_BASEPOINT_POINT;
        let public_compressed = public.compress().to_bytes();
        AdaptorKeyPair {
            secret,
            public,
            public_compressed,
        }
    }
}

/// Expand an Ed25519 secret key (32 bytes) into the clamped scalar `a`
/// and the hash prefix, matching ed25519-dalek's internal expansion.
fn expand_secret_key(secret_key: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let hash = Sha512::digest(secret_key);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);

    // Clamp per Ed25519 spec
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;

    // In curve25519-dalek v4, from_bits is removed; use from_bytes_mod_order
    // The clamped bytes are already reduced, so mod_order is a no-op here
    let a = Scalar::from_bytes_mod_order(scalar_bytes);
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&hash[32..64]);
    (a, prefix)
}

/// Compute the Ed25519 challenge hash: SHA-512(R || A || m) reduced mod l.
fn challenge_hash(r_bytes: &[u8; 32], pk_bytes: &[u8; 32], message: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(pk_bytes);
    hasher.update(message);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Generate a deterministic nonce r for the pre-signature.
/// Uses SHA-512(prefix || T || message) to derive r, similar to Ed25519's
/// deterministic nonce but incorporating the adaptor point.
fn derive_nonce(prefix: &[u8; 32], adaptor_point: &[u8; 32], message: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(adaptor_point);
    hasher.update(message);
    let hash = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// pSign: Generate an adaptor pre-signature.
///
/// Given signer's secret key, message, and adaptor point T:
///   R' = r·G
///   c = H((R'+T) || pk || m)
///   s' = r + c·a
/// Returns (R', s')
pub fn pre_sign(
    secret_key: &[u8; 32],
    message: &[u8],
    adaptor_point: &EdwardsPoint,
) -> AdaptorPreSignature {
    let (a, prefix) = expand_secret_key(secret_key);
    let pk = (&a * ED25519_BASEPOINT_POINT).compress();

    // Deterministic nonce incorporating adaptor point
    let t_bytes = adaptor_point.compress().to_bytes();
    let r = derive_nonce(&prefix, &t_bytes, message);
    let r_prime_point = &r * ED25519_BASEPOINT_POINT;
    let r_prime = r_prime_point.compress().to_bytes();

    // Adapted nonce for hash computation
    let adapted_r = r_prime_point + adaptor_point;
    let adapted_r_bytes = adapted_r.compress().to_bytes();

    // Challenge: c = H(R'+T || pk || m)
    let c = challenge_hash(&adapted_r_bytes, &pk.to_bytes(), message);

    // Pre-signature scalar: s' = r + c·a
    let s_prime = r + c * a;

    AdaptorPreSignature {
        r_prime,
        s_prime: s_prime.to_bytes(),
    }
}

/// pVerify: Verify an adaptor pre-signature.
///
/// Check: s'·G == R' + H((R'+T) || pk || m)·pk
pub fn pre_verify(
    public_key: &[u8; 32],
    message: &[u8],
    adaptor_point: &EdwardsPoint,
    pre_sig: &AdaptorPreSignature,
) -> bool {
    // Decompress R'
    let r_prime = match CompressedEdwardsY(pre_sig.r_prime).decompress() {
        Some(p) => p,
        None => return false,
    };

    // Decompress public key
    let pk_point = match CompressedEdwardsY(*public_key).decompress() {
        Some(p) => p,
        None => return false,
    };

    // Adapted nonce R'+T
    let adapted_r = r_prime + adaptor_point;
    let adapted_r_bytes = adapted_r.compress().to_bytes();

    // Challenge: c = H(R'+T || pk || m)
    let c = challenge_hash(&adapted_r_bytes, public_key, message);

    // Deserialize s'
    let s_prime = match Scalar::from_canonical_bytes(pre_sig.s_prime).into() {
        Some(s) => s,
        None => return false,
    };

    // Check: s'·G == R' + c·pk
    let lhs = &s_prime * ED25519_BASEPOINT_POINT;
    let rhs = r_prime + &c * pk_point;

    lhs == rhs
}

/// Adapt: Convert a pre-signature into a full Ed25519 signature using the adaptor secret.
///
/// s = s' + t, R = R' + T
pub fn adapt(
    pre_sig: &AdaptorPreSignature,
    adaptor_secret: &Scalar,
    adaptor_point: &EdwardsPoint,
) -> Option<AdaptedSignature> {
    let r_prime = CompressedEdwardsY(pre_sig.r_prime).decompress()?;
    let s_prime: Scalar = Scalar::from_canonical_bytes(pre_sig.s_prime).into_option()?;

    let adapted_r = r_prime + adaptor_point;
    let s = s_prime + adaptor_secret;

    Some(AdaptedSignature {
        r_bytes: adapted_r.compress().to_bytes(),
        s_bytes: s.to_bytes(),
    })
}

/// Extract: Recover the adaptor secret from a full signature and the pre-signature.
///
/// t = s - s'
pub fn extract(full_sig: &AdaptedSignature, pre_sig: &AdaptorPreSignature) -> Option<Scalar> {
    let s: Scalar = Scalar::from_canonical_bytes(full_sig.s_bytes).into_option()?;
    let s_prime: Scalar = Scalar::from_canonical_bytes(pre_sig.s_prime).into_option()?;
    Some(s - s_prime)
}

/// Verify a full adapted signature as a standard Ed25519 signature.
///
/// Check: s·G == R + H(R || pk || m)·pk
pub fn verify_adapted(public_key: &[u8; 32], message: &[u8], sig: &AdaptedSignature) -> bool {
    let r = match CompressedEdwardsY(sig.r_bytes).decompress() {
        Some(p) => p,
        None => return false,
    };

    let pk_point = match CompressedEdwardsY(*public_key).decompress() {
        Some(p) => p,
        None => return false,
    };

    let s: Scalar = match Scalar::from_canonical_bytes(sig.s_bytes).into() {
        Some(s) => s,
        None => return false,
    };

    let c = challenge_hash(&sig.r_bytes, public_key, message);
    let lhs = &s * ED25519_BASEPOINT_POINT;
    let rhs = r + &c * pk_point;

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_keypair() -> ([u8; 32], [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk.to_bytes(), pk)
    }

    #[test]
    fn test_pre_sign_and_verify() {
        let (sk, pk) = test_keypair();
        let adaptor = AdaptorKeyPair::generate();
        let message = b"test message for adaptor sig";

        let pre_sig = pre_sign(&sk, message, &adaptor.public);
        assert!(pre_verify(&pk, message, &adaptor.public, &pre_sig));
    }

    #[test]
    fn test_pre_verify_rejects_wrong_message() {
        let (sk, pk) = test_keypair();
        let adaptor = AdaptorKeyPair::generate();

        let pre_sig = pre_sign(&sk, b"correct message", &adaptor.public);
        assert!(!pre_verify(
            &pk,
            b"wrong message",
            &adaptor.public,
            &pre_sig
        ));
    }

    #[test]
    fn test_pre_verify_rejects_wrong_adaptor() {
        let (sk, pk) = test_keypair();
        let adaptor1 = AdaptorKeyPair::generate();
        let adaptor2 = AdaptorKeyPair::generate();
        let message = b"test message";

        let pre_sig = pre_sign(&sk, message, &adaptor1.public);
        assert!(!pre_verify(&pk, message, &adaptor2.public, &pre_sig));
    }

    #[test]
    fn test_adapt_produces_valid_signature() {
        let (sk, pk) = test_keypair();
        let adaptor = AdaptorKeyPair::generate();
        let message = b"adaptor sig roundtrip test";

        let pre_sig = pre_sign(&sk, message, &adaptor.public);
        assert!(pre_verify(&pk, message, &adaptor.public, &pre_sig));

        let full_sig = adapt(&pre_sig, &adaptor.secret, &adaptor.public).unwrap();
        assert!(verify_adapted(&pk, message, &full_sig));
    }

    #[test]
    fn test_extract_recovers_secret() {
        let (sk, pk) = test_keypair();
        let adaptor = AdaptorKeyPair::generate();
        let message = b"extract secret test";

        let pre_sig = pre_sign(&sk, message, &adaptor.public);
        assert!(pre_verify(&pk, message, &adaptor.public, &pre_sig));

        let full_sig = adapt(&pre_sig, &adaptor.secret, &adaptor.public).unwrap();
        assert!(verify_adapted(&pk, message, &full_sig));

        let extracted_t = extract(&full_sig, &pre_sig).unwrap();
        assert_eq!(extracted_t, adaptor.secret);
    }

    #[test]
    fn test_wrong_adaptor_secret_produces_invalid_sig() {
        let (sk, pk) = test_keypair();
        let adaptor = AdaptorKeyPair::generate();
        let wrong_adaptor = AdaptorKeyPair::generate();
        let message = b"wrong secret test";

        let pre_sig = pre_sign(&sk, message, &adaptor.public);

        // Adapt with wrong secret (but correct point)
        let bad_sig = adapt(&pre_sig, &wrong_adaptor.secret, &adaptor.public).unwrap();
        assert!(!verify_adapted(&pk, message, &bad_sig));
    }

    #[test]
    fn test_full_protocol_flow() {
        // Simulates the full Phase 3 Exec-Pay-Deliver protocol
        let (provider_sk, provider_pk) = test_keypair();
        let (vault_sk, vault_pk) = test_keypair();

        // Stage 1: Provider TEE generates adaptor key pair
        let adaptor = AdaptorKeyPair::generate();

        // Stage 2: Provider TEE executes request and creates pre-signature
        let payment_message = b"channel_id:req_id:amount:1000000";
        let pre_sig = pre_sign(&provider_sk, payment_message, &adaptor.public);

        // Stage 3: Vault verifies pre-signature
        assert!(pre_verify(
            &provider_pk,
            payment_message,
            &adaptor.public,
            &pre_sig
        ));

        // Vault issues conditional payment signature
        let _vault_sig = pre_sign(&vault_sk, payment_message, &adaptor.public);

        // Stage 4a: Off-chain path — provider reveals t
        let full_sig = adapt(&pre_sig, &adaptor.secret, &adaptor.public).unwrap();
        assert!(verify_adapted(&provider_pk, payment_message, &full_sig));

        // Vault extracts t to decrypt result
        let recovered_t = extract(&full_sig, &pre_sig).unwrap();
        assert_eq!(recovered_t, adaptor.secret);

        // Stage 4b: On-chain path would submit full_sig to chain
        // and anyone can extract t from (full_sig, pre_sig)
    }
}
