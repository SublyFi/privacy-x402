import {
  createHash,
  verify as verifySignature,
  X509Certificate,
} from "node:crypto";
import { decodeFirstSync, encode, Tagged } from "cbor";

import {
  A402NitroUserDataEnvelope,
  AttestationResponse,
  NitroAttestationConfig,
  NitroAttestationDocument,
  NitroAttestationPolicy,
} from "./types";

const AWS_NITRO_ROOT_G1_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;

const COSE_SIGN1_TAG = 18;
const COSE_ALG_ES256 = -7;
const COSE_ALG_ES384 = -35;
const COSE_ALG_ES512 = -36;
const DEFAULT_MAX_ATTESTATION_AGE_MS = 10 * 60 * 1000;

type ParsedCoseSign1 = {
  protectedHeaderBytes: Buffer;
  protectedHeader: Map<unknown, unknown>;
  payloadBytes: Buffer;
  signatureBytes: Buffer;
  unprotectedHeader: Map<unknown, unknown>;
};

export async function verifyNitroAttestationDocument(
  attestation: AttestationResponse,
  config: NitroAttestationConfig
): Promise<NitroAttestationDocument> {
  const attestationBytes = Buffer.from(
    attestation.attestationDocument,
    "base64"
  );
  const sign1 = parseCoseSign1(attestationBytes);
  const document = parseNitroAttestationPayload(sign1.payloadBytes);
  const leafCertificate = new X509Certificate(document.certificatePem);
  const bundleCertificates = document.cabundlePem.map(
    (pem) => new X509Certificate(pem)
  );
  const trustedRoots = (
    config.rootCertificatesPem?.length
      ? config.rootCertificatesPem
      : [AWS_NITRO_ROOT_G1_PEM]
  ).map((pem) => new X509Certificate(pem));

  verifyCertificateChain(leafCertificate, bundleCertificates, trustedRoots);
  verifyCoseSignature(sign1, leafCertificate);
  verifyAttestationTimestamp(document, config.maxAgeMs);
  verifyExpectedPolicy(document, attestation, config);
  verifyExpectedNonce(document, config.expectedNonce);
  verifyA402UserDataBinding(
    document,
    attestation,
    config.expectedVaultSigner,
    config.requireA402UserData
  );

  if (config.documentValidator) {
    await config.documentValidator(document, attestation);
  }

  return document;
}

export function computeNitroAttestationPolicyHash(
  policy: NitroAttestationPolicy
): string {
  const canonical = canonicalJson(normalizePolicy(policy));
  return sha256hex(Buffer.from(canonical, "utf8"));
}

function parseCoseSign1(input: Buffer): ParsedCoseSign1 {
  const decoded = unwrapTagged(decodeFirstSync(input));
  if (!Array.isArray(decoded) || decoded.length !== 4) {
    throw new Error(
      "Nitro attestation document is not a valid COSE_Sign1 array"
    );
  }

  const [protectedHeaderRaw, unprotectedHeaderRaw, payloadRaw, signatureRaw] =
    decoded;
  const protectedHeaderBytes = expectBuffer(
    protectedHeaderRaw,
    "COSE protected header"
  );
  const protectedHeaderValue = decodeFirstSync(protectedHeaderBytes);
  if (!(protectedHeaderValue instanceof Map)) {
    throw new Error("COSE protected header must decode to a CBOR map");
  }
  const payloadBytes = expectBuffer(payloadRaw, "COSE payload");
  const signatureBytes = expectBuffer(signatureRaw, "COSE signature");
  const unprotectedHeader = mapFromUnknown(unprotectedHeaderRaw);

  return {
    protectedHeaderBytes,
    protectedHeader: protectedHeaderValue,
    payloadBytes,
    signatureBytes,
    unprotectedHeader,
  };
}

function parseNitroAttestationPayload(
  payloadBytes: Buffer
): NitroAttestationDocument {
  const payload = decodeFirstSync(payloadBytes);
  const payloadMap = mapFromUnknown(payload);
  const pcrMap = mapFromUnknown(payloadMap.get("pcrs"));
  const pcrs: Record<string, string> = {};
  for (const [index, value] of pcrMap.entries()) {
    pcrs[String(index)] = expectBuffer(value, `PCR ${String(index)}`).toString(
      "hex"
    );
  }

  const certificateDer = expectBuffer(
    payloadMap.get("certificate"),
    "certificate"
  );
  const cabundle = expectArray(payloadMap.get("cabundle"), "cabundle").map(
    (entry, idx) =>
      derToPem(expectBuffer(entry, `cabundle[${idx}]`), "CERTIFICATE")
  );

  const userDataBuffer = optionalBuffer(payloadMap.get("user_data"));
  const parsedA402UserData = userDataBuffer
    ? parseA402UserDataEnvelope(userDataBuffer)
    : null;

  return {
    moduleId: expectString(payloadMap.get("module_id"), "module_id"),
    timestampMs: expectNumber(payloadMap.get("timestamp"), "timestamp"),
    digest: expectString(payloadMap.get("digest"), "digest"),
    pcrs,
    certificatePem: derToPem(certificateDer, "CERTIFICATE"),
    cabundlePem: cabundle,
    publicKeyDerB64: optionalBuffer(payloadMap.get("public_key"))?.toString(
      "base64"
    ),
    userDataB64: userDataBuffer?.toString("base64"),
    nonceB64: optionalBuffer(payloadMap.get("nonce"))?.toString("base64"),
    parsedA402UserData,
  };
}

function verifyCertificateChain(
  leaf: X509Certificate,
  bundle: X509Certificate[],
  trustedRoots: X509Certificate[]
): void {
  const now = new Date();
  const chain = [leaf, ...bundle];

  for (const certificate of chain) {
    assertCertificateValidAt(certificate, now);
  }
  for (const root of trustedRoots) {
    assertCertificateValidAt(root, now);
  }

  for (let i = 0; i < chain.length - 1; i += 1) {
    const subject = chain[i];
    const issuer = chain[i + 1];
    if (!subject.checkIssued(issuer)) {
      throw new Error(`Attestation certificate chain is broken at depth ${i}`);
    }
    if (!subject.verify(issuer.publicKey)) {
      throw new Error(
        `Attestation certificate signature is invalid at depth ${i}`
      );
    }
  }

  const last = chain[chain.length - 1];
  const trusted = trustedRoots.some((root) => {
    if (last.raw.equals(root.raw)) {
      return true;
    }
    return last.checkIssued(root) && last.verify(root.publicKey);
  });
  if (!trusted) {
    throw new Error(
      "Attestation certificate chain does not terminate at a trusted Nitro root"
    );
  }
}

function verifyCoseSignature(
  sign1: ParsedCoseSign1,
  leafCertificate: X509Certificate
): void {
  const algorithm = sign1.protectedHeader.get(1);
  const hashAlgorithm = coseAlgorithmToHash(algorithm);
  const toBeSigned = Buffer.from(
    encode([
      "Signature1",
      sign1.protectedHeaderBytes,
      Buffer.alloc(0),
      sign1.payloadBytes,
    ])
  );

  const ok = verifySignature(
    hashAlgorithm,
    toBeSigned,
    {
      key: leafCertificate.publicKey,
      dsaEncoding: "ieee-p1363",
    },
    sign1.signatureBytes
  );
  if (!ok) {
    throw new Error("Attestation COSE signature verification failed");
  }
}

function verifyAttestationTimestamp(
  document: NitroAttestationDocument,
  configuredMaxAgeMs?: number
): void {
  const maxAgeMs = configuredMaxAgeMs ?? DEFAULT_MAX_ATTESTATION_AGE_MS;
  const now = Date.now();
  if (document.timestampMs > now + 60_000) {
    throw new Error("Attestation document timestamp is in the future");
  }
  if (now - document.timestampMs > maxAgeMs) {
    throw new Error("Attestation document is older than the allowed maxAgeMs");
  }
  if (document.digest !== "SHA384") {
    throw new Error(`Unsupported Nitro attestation digest ${document.digest}`);
  }
}

function verifyExpectedPolicy(
  document: NitroAttestationDocument,
  attestation: AttestationResponse,
  config: NitroAttestationConfig
): void {
  const expectedPolicyHash = config.policy
    ? computeNitroAttestationPolicyHash(config.policy)
    : normalizeHex(
        config.expectedPolicyHash ?? attestation.attestationPolicyHash
      );
  if (normalizeHex(attestation.attestationPolicyHash) !== expectedPolicyHash) {
    throw new Error(
      "Attestation policy hash does not match the expected value"
    );
  }

  const expectedPcrs = config.policy?.pcrs ?? config.expectedPcrs;
  if (!expectedPcrs) {
    return;
  }

  for (const [index, expected] of Object.entries(expectedPcrs)) {
    const actual = document.pcrs[index];
    if (!actual) {
      throw new Error(`Attestation document is missing expected PCR${index}`);
    }
    if (normalizeHex(actual) !== normalizeHex(expected)) {
      throw new Error(
        `Attestation PCR${index} does not match the expected value`
      );
    }
  }
}

function verifyExpectedNonce(
  document: NitroAttestationDocument,
  expectedNonce?: string | Uint8Array
): void {
  if (expectedNonce === undefined) {
    return;
  }
  if (!document.nonceB64) {
    throw new Error("Attestation document is missing the required nonce");
  }

  const expected =
    typeof expectedNonce === "string"
      ? normalizeNonceString(expectedNonce)
      : Buffer.from(expectedNonce).toString("base64");
  if (document.nonceB64 !== expected) {
    throw new Error(
      "Attestation document nonce does not match the expected value"
    );
  }
}

function verifyA402UserDataBinding(
  document: NitroAttestationDocument,
  attestation: AttestationResponse,
  expectedVaultSigner?: string,
  requireA402UserData?: boolean
): void {
  const parsed = document.parsedA402UserData;
  if (!parsed) {
    if (requireA402UserData || expectedVaultSigner) {
      throw new Error(
        "Attestation document is missing the required A402 user_data envelope"
      );
    }
    return;
  }

  if (parsed.version !== 1) {
    throw new Error("Unsupported A402 Nitro user_data envelope version");
  }
  if (parsed.vaultConfig !== attestation.vaultConfig) {
    throw new Error(
      "A402 user_data vaultConfig does not match attestation response"
    );
  }
  if (parsed.vaultSigner !== attestation.vaultSigner) {
    throw new Error(
      "A402 user_data vaultSigner does not match attestation response"
    );
  }
  if (
    normalizeHex(parsed.attestationPolicyHash) !==
    normalizeHex(attestation.attestationPolicyHash)
  ) {
    throw new Error(
      "A402 user_data attestationPolicyHash does not match attestation response"
    );
  }
  if (expectedVaultSigner && parsed.vaultSigner !== expectedVaultSigner) {
    throw new Error(
      "A402 user_data vaultSigner does not match the expected vault signer"
    );
  }
  if (attestation.snapshotSeqno !== undefined) {
    if (parsed.snapshotSeqno !== attestation.snapshotSeqno) {
      throw new Error(
        "A402 user_data snapshotSeqno does not match attestation response"
      );
    }
  }
  assertMatchingOptionalField(
    parsed.tlsPublicKeySha256,
    attestation.tlsPublicKeySha256,
    "tlsPublicKeySha256"
  );
  assertMatchingOptionalField(
    parsed.manifestHash,
    attestation.manifestHash,
    "manifestHash"
  );
  if (attestation.tlsPublicKeySha256) {
    if (!document.publicKeyDerB64) {
      throw new Error(
        "Attestation document is missing the TLS public key bound to the response"
      );
    }
    const publicKeyHash = sha256hex(
      Buffer.from(document.publicKeyDerB64, "base64")
    );
    if (
      normalizeHex(publicKeyHash) !==
      normalizeHex(attestation.tlsPublicKeySha256)
    ) {
      throw new Error(
        "Attestation document TLS public key does not match attestation response"
      );
    }
  }
}

export function parseA402UserDataEnvelope(
  userData: Uint8Array
): A402NitroUserDataEnvelope | null {
  try {
    const parsed = JSON.parse(
      Buffer.from(userData).toString("utf8")
    ) as Partial<A402NitroUserDataEnvelope>;
    if (
      typeof parsed.version !== "number" ||
      typeof parsed.vaultConfig !== "string" ||
      typeof parsed.vaultSigner !== "string" ||
      typeof parsed.attestationPolicyHash !== "string" ||
      typeof parsed.snapshotSeqno !== "number" ||
      (parsed.tlsPublicKeySha256 !== undefined &&
        typeof parsed.tlsPublicKeySha256 !== "string") ||
      (parsed.manifestHash !== undefined &&
        typeof parsed.manifestHash !== "string")
    ) {
      return null;
    }
    return parsed as A402NitroUserDataEnvelope;
  } catch {
    return null;
  }
}

function assertMatchingOptionalField(
  documentValue: string | undefined,
  responseValue: string | undefined,
  field: string
): void {
  if (documentValue === undefined && responseValue === undefined) {
    return;
  }
  if (documentValue === undefined || responseValue === undefined) {
    throw new Error(
      `Attestation response ${field} is not consistently bound in user_data`
    );
  }
  if (normalizeHex(documentValue) !== normalizeHex(responseValue)) {
    throw new Error(
      `A402 user_data ${field} does not match attestation response`
    );
  }
}

function normalizePolicy(
  policy: NitroAttestationPolicy
): NitroAttestationPolicy {
  const pcrs = Object.fromEntries(
    Object.entries(policy.pcrs)
      .sort(([a], [b]) => Number(a) - Number(b))
      .map(([index, value]) => [String(index), normalizeHex(value)])
  );
  return {
    version: policy.version,
    pcrs,
    eifSigningCertSha256: normalizeHex(policy.eifSigningCertSha256),
    kmsKeyArnSha256: normalizeHex(policy.kmsKeyArnSha256),
    protocol: policy.protocol,
  };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)
    );
    return `{${entries
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256hex(data: Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function normalizeHex(value: string): string {
  return value.toLowerCase().replace(/^0x/, "");
}

function normalizeNonceString(value: string): string {
  const trimmed = value.trim();
  const isBase64 =
    trimmed.length % 4 === 0 && /^[A-Za-z0-9+/=]+$/.test(trimmed);
  return isBase64 ? trimmed : Buffer.from(trimmed, "utf8").toString("base64");
}

function coseAlgorithmToHash(algorithm: unknown): string {
  switch (algorithm) {
    case COSE_ALG_ES256:
      return "sha256";
    case COSE_ALG_ES384:
      return "sha384";
    case COSE_ALG_ES512:
      return "sha512";
    default:
      throw new Error(`Unsupported COSE algorithm ${String(algorithm)}`);
  }
}

function derToPem(der: Buffer, label: string): string {
  const base64 = der.toString("base64");
  const wrapped = base64.match(/.{1,64}/g)?.join("\n") ?? base64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

function assertCertificateValidAt(
  certificate: X509Certificate,
  now: Date
): void {
  const validFrom = certificate.validFromDate;
  const validTo = certificate.validToDate;
  if (now < validFrom || now > validTo) {
    throw new Error(
      `Attestation certificate ${certificate.subject} is not valid at the current time`
    );
  }
}

function unwrapTagged(value: unknown): unknown {
  if (value instanceof Tagged) {
    if (value.tag !== COSE_SIGN1_TAG) {
      throw new Error(
        `Unexpected CBOR tag ${value.tag} in attestation document`
      );
    }
    return value.value;
  }
  return value;
}

function mapFromUnknown(value: unknown): Map<unknown, unknown> {
  const unwrapped = unwrapTagged(value);
  if (!(unwrapped instanceof Map)) {
    throw new Error("Expected a CBOR map in attestation document");
  }
  return unwrapped;
}

function expectArray(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`Attestation field ${field} must be an array`);
  }
  return value;
}

function expectBuffer(value: unknown, field: string): Buffer {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new Error(`Attestation field ${field} must be a byte string`);
  }
  return Buffer.from(value);
}

function optionalBuffer(value: unknown): Buffer | undefined {
  if (value === undefined) {
    return undefined;
  }
  return expectBuffer(value, "optional byte string");
}

function expectString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`Attestation field ${field} must be a string`);
  }
  return value;
}

function expectNumber(value: unknown, field: string): number {
  if (typeof value !== "number") {
    throw new Error(`Attestation field ${field} must be a number`);
  }
  return value;
}
