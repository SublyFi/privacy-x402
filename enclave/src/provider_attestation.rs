use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use sha2::{Digest, Sha256};
use solana_sdk::pubkey::Pubkey;
use std::collections::BTreeMap;

const AWS_NITRO_ROOT_G1_PEM: &str = include_str!("../../sdk/assets/aws_nitro_root_g1.pem");
const COSE_SIGN1_TAG: u64 = 18;
const COSE_ALG_ES256: i128 = -7;
const COSE_ALG_ES384: i128 = -35;
const COSE_ALG_ES512: i128 = -36;
const DEFAULT_MAX_ATTESTATION_AGE_MS: u64 = 10 * 60 * 1000;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAttestationPolicy {
    pub version: u32,
    pub pcrs: BTreeMap<String, String>,
    pub eif_signing_cert_sha256: String,
    pub kms_key_arn_sha256: String,
    pub protocol: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderParticipantAttestationRequest {
    pub document: String,
    pub policy: ProviderAttestationPolicy,
    #[serde(default)]
    pub max_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderAttestationMode {
    LocalDev,
    Nitro,
}

impl ProviderAttestationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalDev => "local-dev",
            Self::Nitro => "nitro",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedProviderAttestation {
    pub policy_hash_hex: String,
    pub verified_at_ms: i64,
    pub mode: ProviderAttestationMode,
    pub manifest_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalDevProviderAttestationDocument {
    version: u32,
    mode: String,
    provider_id: String,
    participant_pubkey: String,
    attestation_policy_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_hash: Option<String>,
    issued_at: String,
    expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderNitroUserDataEnvelope {
    version: u32,
    provider_id: String,
    participant_pubkey: String,
    attestation_policy_hash: String,
    #[serde(default)]
    manifest_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct ParsedCoseSign1 {
    protected_header_bytes: Vec<u8>,
    algorithm: i128,
    payload_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ParsedNitroAttestationDocument {
    timestamp_ms: u64,
    digest: String,
    pcrs: BTreeMap<String, String>,
    certificate_der: Vec<u8>,
    cabundle_der: Vec<Vec<u8>>,
    user_data: Option<Vec<u8>>,
}

pub fn compute_provider_attestation_policy_hash(policy: &ProviderAttestationPolicy) -> String {
    let normalized = normalized_policy_json(policy);
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

pub fn build_local_dev_provider_attestation(
    provider_id: &str,
    participant_pubkey: Pubkey,
    policy: &ProviderAttestationPolicy,
    manifest_hash: Option<&str>,
) -> String {
    let issued_at = Utc::now();
    let expires_at = issued_at + chrono::Duration::minutes(10);
    let document = LocalDevProviderAttestationDocument {
        version: 1,
        mode: "local-dev-provider".to_string(),
        provider_id: provider_id.to_string(),
        participant_pubkey: participant_pubkey.to_string(),
        attestation_policy_hash: compute_provider_attestation_policy_hash(policy),
        manifest_hash: manifest_hash.map(|value| value.to_string()),
        issued_at: issued_at.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
    };

    BASE64.encode(
        serde_json::to_vec(&document).expect("local-dev provider attestation must serialize"),
    )
}

pub fn verify_provider_participant_attestation(
    attestation: &ProviderParticipantAttestationRequest,
    provider_id: &str,
    participant_pubkey: &Pubkey,
) -> Result<VerifiedProviderAttestation, String> {
    let expected_policy_hash = compute_provider_attestation_policy_hash(&attestation.policy);
    let decoded = BASE64
        .decode(&attestation.document)
        .map_err(|error| format!("invalid provider attestation base64: {error}"))?;

    if let Ok(local_document) =
        serde_json::from_slice::<LocalDevProviderAttestationDocument>(&decoded)
    {
        return verify_local_dev_attestation(
            &local_document,
            provider_id,
            participant_pubkey,
            &expected_policy_hash,
            attestation
                .max_age_ms
                .unwrap_or(DEFAULT_MAX_ATTESTATION_AGE_MS),
        );
    }

    verify_nitro_attestation(
        &decoded,
        provider_id,
        participant_pubkey,
        &attestation.policy,
        &expected_policy_hash,
        attestation
            .max_age_ms
            .unwrap_or(DEFAULT_MAX_ATTESTATION_AGE_MS),
    )
}

fn verify_local_dev_attestation(
    document: &LocalDevProviderAttestationDocument,
    provider_id: &str,
    participant_pubkey: &Pubkey,
    expected_policy_hash: &str,
    max_age_ms: u64,
) -> Result<VerifiedProviderAttestation, String> {
    if document.version != 1 {
        return Err("unsupported local-dev provider attestation version".to_string());
    }
    if document.mode != "local-dev-provider" {
        return Err("invalid local-dev provider attestation mode".to_string());
    }
    if document.provider_id != provider_id {
        return Err("provider attestation providerId does not match registration".to_string());
    }
    if document.participant_pubkey != participant_pubkey.to_string() {
        return Err(
            "provider attestation participantPubkey does not match registration".to_string(),
        );
    }
    if normalize_hex(&document.attestation_policy_hash) != normalize_hex(expected_policy_hash) {
        return Err(
            "provider attestation policy hash does not match the expected value".to_string(),
        );
    }

    let issued_at = DateTime::parse_from_rfc3339(&document.issued_at)
        .map_err(|error| format!("invalid local-dev provider attestation issuedAt: {error}"))?
        .timestamp_millis();
    let expires_at = DateTime::parse_from_rfc3339(&document.expires_at)
        .map_err(|error| format!("invalid local-dev provider attestation expiresAt: {error}"))?
        .timestamp_millis();
    verify_attestation_window(issued_at, expires_at, max_age_ms)?;

    Ok(VerifiedProviderAttestation {
        policy_hash_hex: expected_policy_hash.to_string(),
        verified_at_ms: Utc::now().timestamp_millis(),
        mode: ProviderAttestationMode::LocalDev,
        manifest_hash: document.manifest_hash.clone(),
    })
}

fn verify_nitro_attestation(
    document_bytes: &[u8],
    provider_id: &str,
    participant_pubkey: &Pubkey,
    policy: &ProviderAttestationPolicy,
    expected_policy_hash: &str,
    max_age_ms: u64,
) -> Result<VerifiedProviderAttestation, String> {
    let sign1 = parse_cose_sign1(document_bytes)?;
    let document = parse_nitro_attestation_payload(&sign1.payload_bytes)?;
    verify_certificate_chain(&document.certificate_der, &document.cabundle_der)?;
    verify_cose_signature(&sign1, &document.certificate_der)?;
    verify_nitro_timestamp(&document, max_age_ms)?;
    verify_expected_pcrs(&document, policy)?;

    let user_data_bytes = document.user_data.as_ref().ok_or_else(|| {
        "Nitro provider attestation is missing the required user_data".to_string()
    })?;
    let user_data = serde_json::from_slice::<ProviderNitroUserDataEnvelope>(user_data_bytes)
        .map_err(|error| format!("invalid Nitro provider attestation user_data: {error}"))?;
    if user_data.version != 1 {
        return Err("unsupported Nitro provider attestation user_data version".to_string());
    }
    if user_data.provider_id != provider_id {
        return Err(
            "Nitro provider attestation providerId does not match registration".to_string(),
        );
    }
    if user_data.participant_pubkey != participant_pubkey.to_string() {
        return Err(
            "Nitro provider attestation participantPubkey does not match registration".to_string(),
        );
    }
    if normalize_hex(&user_data.attestation_policy_hash) != normalize_hex(expected_policy_hash) {
        return Err(
            "Nitro provider attestation policy hash does not match the expected value".to_string(),
        );
    }

    Ok(VerifiedProviderAttestation {
        policy_hash_hex: expected_policy_hash.to_string(),
        verified_at_ms: Utc::now().timestamp_millis(),
        mode: ProviderAttestationMode::Nitro,
        manifest_hash: user_data.manifest_hash,
    })
}

fn parse_cose_sign1(input: &[u8]) -> Result<ParsedCoseSign1, String> {
    let decoded: CborValue =
        serde_cbor::from_slice(input).map_err(|error| format!("invalid COSE_Sign1: {error}"))?;
    let decoded = unwrap_tag(decoded)?;
    let items = expect_array(decoded, "COSE_Sign1")?;
    if items.len() != 4 {
        return Err("COSE_Sign1 must have exactly 4 items".to_string());
    }

    let protected_header_bytes = expect_bytes(items[0].clone(), "COSE protected header")?;
    let protected_header: CborValue = serde_cbor::from_slice(&protected_header_bytes)
        .map_err(|error| format!("invalid COSE protected header: {error}"))?;
    let protected_map = expect_map(protected_header, "COSE protected header")?;
    let algorithm = protected_map
        .iter()
        .find_map(|(key, value)| match key {
            CborValue::Integer(integer) if *integer == 1 => as_i128(value),
            _ => None,
        })
        .ok_or_else(|| "COSE protected header is missing alg".to_string())?;

    Ok(ParsedCoseSign1 {
        protected_header_bytes,
        algorithm,
        payload_bytes: expect_bytes(items[2].clone(), "COSE payload")?,
        signature_bytes: expect_bytes(items[3].clone(), "COSE signature")?,
    })
}

fn parse_nitro_attestation_payload(
    payload_bytes: &[u8],
) -> Result<ParsedNitroAttestationDocument, String> {
    let payload: CborValue = serde_cbor::from_slice(payload_bytes)
        .map_err(|error| format!("invalid Nitro payload: {error}"))?;
    let payload_map = expect_map(payload, "Nitro attestation payload")?;
    let pcr_map = expect_map(
        payload_map
            .get(&CborValue::Text("pcrs".to_string()))
            .cloned()
            .ok_or_else(|| "Nitro attestation payload is missing pcrs".to_string())?,
        "Nitro attestation pcrs",
    )?;

    let mut pcrs = BTreeMap::new();
    for (index, value) in pcr_map {
        let index = match index {
            CborValue::Integer(integer) => integer.to_string(),
            CborValue::Text(text) => text,
            _ => return Err("Nitro attestation PCR index must be an integer or string".to_string()),
        };
        pcrs.insert(
            index,
            hex::encode(expect_bytes(value, "Nitro attestation PCR value")?),
        );
    }

    let cabundle_values = expect_array(
        payload_map
            .get(&CborValue::Text("cabundle".to_string()))
            .cloned()
            .ok_or_else(|| "Nitro attestation payload is missing cabundle".to_string())?,
        "Nitro attestation cabundle",
    )?;

    let mut cabundle_der = Vec::with_capacity(cabundle_values.len());
    for entry in cabundle_values {
        cabundle_der.push(expect_bytes(
            entry,
            "Nitro attestation cabundle certificate",
        )?);
    }

    Ok(ParsedNitroAttestationDocument {
        timestamp_ms: as_u64(
            payload_map
                .get(&CborValue::Text("timestamp".to_string()))
                .ok_or_else(|| "Nitro attestation payload is missing timestamp".to_string())?,
        )
        .ok_or_else(|| "Nitro attestation timestamp must be an unsigned integer".to_string())?,
        digest: expect_text(
            payload_map
                .get(&CborValue::Text("digest".to_string()))
                .cloned()
                .ok_or_else(|| "Nitro attestation payload is missing digest".to_string())?,
            "Nitro attestation digest",
        )?,
        pcrs,
        certificate_der: expect_bytes(
            payload_map
                .get(&CborValue::Text("certificate".to_string()))
                .cloned()
                .ok_or_else(|| "Nitro attestation payload is missing certificate".to_string())?,
            "Nitro attestation certificate",
        )?,
        cabundle_der,
        user_data: payload_map
            .get(&CborValue::Text("user_data".to_string()))
            .cloned()
            .map(|value| expect_bytes(value, "Nitro attestation user_data"))
            .transpose()?,
    })
}

fn verify_certificate_chain(
    certificate_der: &[u8],
    cabundle_der: &[Vec<u8>],
) -> Result<(), String> {
    let leaf = X509::from_der(certificate_der)
        .map_err(|error| format!("invalid Nitro attestation leaf certificate: {error}"))?;
    let trusted_root = X509::from_pem(AWS_NITRO_ROOT_G1_PEM.as_bytes())
        .map_err(|error| format!("invalid embedded Nitro root certificate: {error}"))?;

    let mut store_builder =
        X509StoreBuilder::new().map_err(|error| format!("failed to build X509 store: {error}"))?;
    store_builder
        .add_cert(trusted_root)
        .map_err(|error| format!("failed to add Nitro root certificate: {error}"))?;
    let store = store_builder.build();

    let mut chain =
        Stack::new().map_err(|error| format!("failed to build X509 chain stack: {error}"))?;
    for certificate_der in cabundle_der {
        let certificate = X509::from_der(certificate_der)
            .map_err(|error| format!("invalid Nitro attestation bundle certificate: {error}"))?;
        chain
            .push(certificate)
            .map_err(|error| format!("failed to append Nitro bundle certificate: {error}"))?;
    }

    let mut context = X509StoreContext::new()
        .map_err(|error| format!("failed to build X509 store context: {error}"))?;
    let verified = context
        .init(&store, &leaf, &chain, |ctx| ctx.verify_cert())
        .map_err(|error| format!("failed to verify Nitro certificate chain: {error}"))?;
    if !verified {
        return Err("Nitro certificate chain verification failed".to_string());
    }

    Ok(())
}

fn verify_cose_signature(sign1: &ParsedCoseSign1, certificate_der: &[u8]) -> Result<(), String> {
    let leaf = X509::from_der(certificate_der)
        .map_err(|error| format!("invalid Nitro attestation leaf certificate: {error}"))?;
    let public_key = leaf
        .public_key()
        .map_err(|error| format!("failed to extract Nitro attestation public key: {error}"))?;

    let to_be_signed = serde_cbor::to_vec(&CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(sign1.protected_header_bytes.clone()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(sign1.payload_bytes.clone()),
    ]))
    .map_err(|error| format!("failed to serialize COSE Sig_structure: {error}"))?;

    let signature_der = p1363_to_der(&sign1.signature_bytes)?;
    let mut verifier = Verifier::new(cose_algorithm_to_digest(sign1.algorithm)?, &public_key)
        .map_err(|error| format!("failed to initialize COSE verifier: {error}"))?;
    verifier
        .update(&to_be_signed)
        .map_err(|error| format!("failed to feed COSE Sig_structure into verifier: {error}"))?;
    let ok = verifier
        .verify(&signature_der)
        .map_err(|error| format!("failed to verify COSE signature: {error}"))?;
    if !ok {
        return Err("Nitro attestation COSE signature verification failed".to_string());
    }
    Ok(())
}

fn verify_nitro_timestamp(
    document: &ParsedNitroAttestationDocument,
    max_age_ms: u64,
) -> Result<(), String> {
    let now_ms = Utc::now().timestamp_millis() as u64;
    if document.timestamp_ms > now_ms.saturating_add(60_000) {
        return Err("Nitro attestation timestamp is in the future".to_string());
    }
    if now_ms.saturating_sub(document.timestamp_ms) > max_age_ms {
        return Err("Nitro attestation is older than the allowed maxAgeMs".to_string());
    }
    if document.digest != "SHA384" {
        return Err(format!(
            "unsupported Nitro attestation digest {}",
            document.digest
        ));
    }
    Ok(())
}

fn verify_expected_pcrs(
    document: &ParsedNitroAttestationDocument,
    policy: &ProviderAttestationPolicy,
) -> Result<(), String> {
    for (index, expected) in &policy.pcrs {
        let actual = document
            .pcrs
            .get(index)
            .ok_or_else(|| format!("Nitro attestation is missing expected PCR{index}"))?;
        if normalize_hex(actual) != normalize_hex(expected) {
            return Err(format!(
                "Nitro attestation PCR{index} does not match the expected value"
            ));
        }
    }
    Ok(())
}

fn verify_attestation_window(
    issued_at_ms: i64,
    expires_at_ms: i64,
    max_age_ms: u64,
) -> Result<(), String> {
    let now_ms = Utc::now().timestamp_millis();
    if issued_at_ms > now_ms + 60_000 {
        return Err("provider attestation issuedAt is in the future".to_string());
    }
    if now_ms - issued_at_ms > max_age_ms as i64 {
        return Err("provider attestation is older than the allowed maxAgeMs".to_string());
    }
    if expires_at_ms < now_ms {
        return Err("provider attestation has expired".to_string());
    }
    Ok(())
}

fn normalized_policy_json(policy: &ProviderAttestationPolicy) -> String {
    let value = serde_json::json!({
        "version": policy.version,
        "pcrs": policy
            .pcrs
            .iter()
            .map(|(index, value)| (index.clone(), serde_json::Value::String(normalize_hex(value))))
            .collect::<BTreeMap<String, serde_json::Value>>(),
        "eifSigningCertSha256": normalize_hex(&policy.eif_signing_cert_sha256),
        "kmsKeyArnSha256": normalize_hex(&policy.kms_key_arn_sha256),
        "protocol": policy.protocol,
    });
    canonical_json(&value)
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Array(entries) => format!(
            "[{}]",
            entries
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        serde_json::Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, entry)| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(key)
                                .expect("JSON key serialization must succeed"),
                            canonical_json(entry)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        _ => serde_json::to_string(value).expect("JSON primitive serialization must succeed"),
    }
}

fn normalize_hex(value: &str) -> String {
    value.trim().trim_start_matches("0x").to_ascii_lowercase()
}

fn cose_algorithm_to_digest(algorithm: i128) -> Result<MessageDigest, String> {
    match algorithm {
        COSE_ALG_ES256 => Ok(MessageDigest::sha256()),
        COSE_ALG_ES384 => Ok(MessageDigest::sha384()),
        COSE_ALG_ES512 => Ok(MessageDigest::sha512()),
        _ => Err(format!("unsupported COSE algorithm {algorithm}")),
    }
}

fn p1363_to_der(signature: &[u8]) -> Result<Vec<u8>, String> {
    if signature.len() % 2 != 0 {
        return Err("COSE signature must have an even length".to_string());
    }
    let half = signature.len() / 2;
    let r = BigNum::from_slice(&signature[..half])
        .map_err(|error| format!("invalid COSE signature r component: {error}"))?;
    let s = BigNum::from_slice(&signature[half..])
        .map_err(|error| format!("invalid COSE signature s component: {error}"))?;
    let ecdsa = EcdsaSig::from_private_components(r, s)
        .map_err(|error| format!("invalid COSE signature components: {error}"))?;
    ecdsa
        .to_der()
        .map_err(|error| format!("failed to DER-encode COSE signature: {error}"))
}

fn unwrap_tag(value: CborValue) -> Result<CborValue, String> {
    match value {
        CborValue::Tag(tag, boxed) if tag == COSE_SIGN1_TAG => Ok(*boxed),
        CborValue::Tag(tag, _) => Err(format!("unexpected CBOR tag {tag} in attestation document")),
        other => Ok(other),
    }
}

fn expect_array(value: CborValue, field: &str) -> Result<Vec<CborValue>, String> {
    match value {
        CborValue::Array(values) => Ok(values),
        _ => Err(format!("{field} must be a CBOR array")),
    }
}

fn expect_map(value: CborValue, field: &str) -> Result<BTreeMap<CborValue, CborValue>, String> {
    match value {
        CborValue::Map(values) => Ok(values),
        _ => Err(format!("{field} must be a CBOR map")),
    }
}

fn expect_bytes(value: CborValue, field: &str) -> Result<Vec<u8>, String> {
    match value {
        CborValue::Bytes(bytes) => Ok(bytes),
        _ => Err(format!("{field} must be a CBOR byte string")),
    }
}

fn expect_text(value: CborValue, field: &str) -> Result<String, String> {
    match value {
        CborValue::Text(text) => Ok(text),
        _ => Err(format!("{field} must be a CBOR text string")),
    }
}

fn as_i128(value: &CborValue) -> Option<i128> {
    match value {
        CborValue::Integer(integer) => Some(*integer),
        _ => None,
    }
}

fn as_u64(value: &CborValue) -> Option<u64> {
    as_i128(value).and_then(|integer| u64::try_from(integer).ok())
}

#[cfg(test)]
pub fn test_policy() -> ProviderAttestationPolicy {
    ProviderAttestationPolicy {
        version: 1,
        pcrs: BTreeMap::from([
            ("0".to_string(), "11".repeat(48)),
            ("1".to_string(), "22".repeat(48)),
            ("2".to_string(), "33".repeat(48)),
            ("3".to_string(), "44".repeat(48)),
            ("8".to_string(), "55".repeat(48)),
        ]),
        eif_signing_cert_sha256: "66".repeat(32),
        kms_key_arn_sha256: "77".repeat(32),
        protocol: "subly402-provider-v1".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_dev_provider_attestation_roundtrip_verifies() {
        let policy = test_policy();
        let provider_id = "provider-attested";
        let participant_pubkey = Pubkey::new_unique();
        let manifest_hash = "aa".repeat(32);
        let document = build_local_dev_provider_attestation(
            provider_id,
            participant_pubkey,
            &policy,
            Some(&manifest_hash),
        );

        let verified = verify_provider_participant_attestation(
            &ProviderParticipantAttestationRequest {
                document,
                policy,
                max_age_ms: Some(DEFAULT_MAX_ATTESTATION_AGE_MS),
            },
            provider_id,
            &participant_pubkey,
        )
        .unwrap();

        assert_eq!(verified.mode, ProviderAttestationMode::LocalDev);
        assert!(verified.manifest_hash.is_some());
    }

    #[test]
    fn local_dev_provider_attestation_rejects_mismatched_participant() {
        let policy = test_policy();
        let provider_id = "provider-attested";
        let document =
            build_local_dev_provider_attestation(provider_id, Pubkey::new_unique(), &policy, None);

        let error = verify_provider_participant_attestation(
            &ProviderParticipantAttestationRequest {
                document,
                policy,
                max_age_ms: Some(DEFAULT_MAX_ATTESTATION_AGE_MS),
            },
            provider_id,
            &Pubkey::new_unique(),
        )
        .err()
        .unwrap();

        assert!(error.contains("participantPubkey"));
    }
}
