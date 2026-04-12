import { expect } from "chai";
import { Keypair, PublicKey } from "@solana/web3.js";

import { A402Client } from "../sdk/src/client";
import {
  computeNitroAttestationPolicyHash,
  parseA402UserDataEnvelope,
} from "../sdk/src/attestation";
import { AttestationResponse, NitroAttestationPolicy } from "../sdk/src/types";

function buildLocalAttestation(
  overrides?: Partial<AttestationResponse>
): AttestationResponse {
  const vaultConfig = Keypair.generate().publicKey.toBase58();
  const vaultSigner = Keypair.generate().publicKey.toBase58();
  const document = {
    version: 1,
    mode: "local-dev",
    vaultConfig,
    vaultSigner,
    attestationPolicyHash: "ab".repeat(32),
    recipientPublicKeyPem:
      "-----BEGIN PUBLIC KEY-----\nZmFrZS1rZXk=\n-----END PUBLIC KEY-----",
    recipientPublicKeySha256: "cd".repeat(32),
    issuedAt: "2026-04-13T00:00:00.000Z",
    expiresAt: "2099-04-13T00:00:00.000Z",
  };

  return {
    vaultConfig,
    vaultSigner,
    attestationPolicyHash: document.attestationPolicyHash,
    attestationDocument: Buffer.from(JSON.stringify(document), "utf8").toString(
      "base64"
    ),
    issuedAt: document.issuedAt,
    expiresAt: document.expiresAt,
    ...overrides,
  };
}

function installFetchResponse(body: unknown): void {
  globalThis.fetch = (async () =>
    ({
      ok: true,
      json: async () => body,
    } as any)) as typeof fetch;
}

describe("attestation_sdk", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("computes the same Nitro policy hash for equivalent canonical policies", () => {
    const policyA: NitroAttestationPolicy = {
      version: 1,
      pcrs: {
        "1": "0xBB",
        "0": "AA",
      },
      eifSigningCertSha256: "0xCC",
      kmsKeyArnSha256: "DD",
      protocol: "a402",
    };
    const policyB: NitroAttestationPolicy = {
      version: 1,
      pcrs: {
        "0": "aa",
        "1": "bb",
      },
      eifSigningCertSha256: "cc",
      kmsKeyArnSha256: "0xdd",
      protocol: "a402",
    };

    expect(computeNitroAttestationPolicyHash(policyA)).to.equal(
      computeNitroAttestationPolicyHash(policyB)
    );
  });

  it("parses the A402 Nitro user_data envelope and rejects invalid JSON", () => {
    const parsed = parseA402UserDataEnvelope(
      Buffer.from(
        JSON.stringify({
          version: 1,
          vaultConfig: "vault-config",
          vaultSigner: "vault-signer",
          attestationPolicyHash: "aa".repeat(32),
          snapshotSeqno: 7,
        }),
        "utf8"
      )
    );

    expect(parsed).to.deep.equal({
      version: 1,
      vaultConfig: "vault-config",
      vaultSigner: "vault-signer",
      attestationPolicyHash: "aa".repeat(32),
      snapshotSeqno: 7,
    });
    expect(parseA402UserDataEnvelope(Buffer.from("not-json", "utf8"))).to.equal(
      null
    );
  });

  it("accepts a local-dev attestation document", async () => {
    const wallet = Keypair.generate();
    const attestation = buildLocalAttestation();

    installFetchResponse(attestation);

    const client = new A402Client({
      walletKeypair: wallet,
      vaultAddress: new PublicKey(attestation.vaultConfig),
      enclaveUrl: "http://localhost:3100",
    });

    const verified = await client.verifyAttestation();
    expect(verified.vaultSigner).to.equal(attestation.vaultSigner);
  });

  it("rejects a non-local attestation document without a verifier", async () => {
    const wallet = Keypair.generate();
    const vaultAddress = Keypair.generate().publicKey;
    const attestation: AttestationResponse = {
      vaultConfig: vaultAddress.toBase58(),
      vaultSigner: Keypair.generate().publicKey.toBase58(),
      attestationPolicyHash: "ab".repeat(32),
      attestationDocument: Buffer.from("nitro-doc", "utf8").toString("base64"),
      issuedAt: "2026-04-13T00:00:00.000Z",
      expiresAt: "2099-04-13T00:00:00.000Z",
    };

    installFetchResponse(attestation);

    const client = new A402Client({
      walletKeypair: wallet,
      vaultAddress,
      enclaveUrl: "http://localhost:3100",
    });

    try {
      await client.verifyAttestation();
      throw new Error("expected verifyAttestation to reject");
    } catch (error) {
      expect((error as Error).message).to.equal(
        "Non-local attestation document requires nitroAttestation or attestationVerifier"
      );
    }
  });

  it("delegates non-local attestation verification to the custom verifier", async () => {
    const wallet = Keypair.generate();
    const vaultAddress = Keypair.generate().publicKey;
    const attestation: AttestationResponse = {
      vaultConfig: vaultAddress.toBase58(),
      vaultSigner: Keypair.generate().publicKey.toBase58(),
      attestationPolicyHash: "ab".repeat(32),
      attestationDocument: Buffer.from("nitro-doc", "utf8").toString("base64"),
      issuedAt: "2026-04-13T00:00:00.000Z",
      expiresAt: "2099-04-13T00:00:00.000Z",
    };
    let verifierCalls = 0;

    installFetchResponse(attestation);

    const client = new A402Client({
      walletKeypair: wallet,
      vaultAddress,
      enclaveUrl: "http://localhost:3100",
      attestationVerifier: async (received) => {
        verifierCalls += 1;
        expect(received.attestationDocument).to.equal(
          attestation.attestationDocument
        );
      },
    });

    await client.verifyAttestation();
    expect(verifierCalls).to.equal(1);
  });
});
