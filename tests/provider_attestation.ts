import { createHash } from "crypto";

export function buildTestProviderParticipantAttestation(
  providerId: string,
  participantPubkey: string
) {
  const policy = {
    version: 1,
    pcrs: {
      "0": "11".repeat(48),
      "1": "22".repeat(48),
      "2": "33".repeat(48),
      "3": "44".repeat(48),
      "8": "55".repeat(48),
    },
    eifSigningCertSha256: "66".repeat(32),
    kmsKeyArnSha256: "77".repeat(32),
    protocol: "subly402-provider-v1",
  };

  const normalizedPolicy = {
    version: policy.version,
    pcrs: Object.fromEntries(
      Object.entries(policy.pcrs)
        .sort(([a], [b]) => Number(a) - Number(b))
        .map(([index, value]) => [index, normalizeHex(value)])
    ),
    eifSigningCertSha256: normalizeHex(policy.eifSigningCertSha256),
    kmsKeyArnSha256: normalizeHex(policy.kmsKeyArnSha256),
    protocol: policy.protocol,
  };

  const document = {
    version: 1,
    mode: "local-dev-provider",
    providerId,
    participantPubkey,
    attestationPolicyHash: sha256Hex(canonicalJson(normalizedPolicy)),
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
  };

  return {
    document: Buffer.from(JSON.stringify(document), "utf8").toString("base64"),
    policy,
    maxAgeMs: 10 * 60_000,
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

function normalizeHex(value: string): string {
  return value.trim().replace(/^0x/, "").toLowerCase();
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
