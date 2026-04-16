import { expect } from "chai";
import { createHash, X509Certificate } from "node:crypto";
import { createServer, Server } from "node:https";
import { Keypair, PublicKey } from "@solana/web3.js";

import { A402Client } from "../sdk/src/client";
import {
  computeNitroAttestationPolicyHash,
  parseA402UserDataEnvelope,
} from "../sdk/src/attestation";
import { AttestationResponse, NitroAttestationPolicy } from "../sdk/src/types";

const TLS_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCTvDw3v9WYQril
iwylqMWbPssmSqHe6u9mjA282p3VYSE9lr1uuk+VUMKCkbeULV09/Sz7viIui+Ai
CpiVoGFYYDz5Zc/9NA+rh5lgwUhztf41VyOgrlc1x+hST4OamZXECmoLmdpBFU0z
Iza7Uq8mcHBjZ4BSUyTdM1MtHzofAa0FzHmBJ9O/v0L0ekHc/vWUSmYf5h2Ec4du
mmf4a9KOMcSoe/5g3oKT90wk2SXHEJd49KMxPFG4u9I2CReKkIQv64xLtXR8spMU
r/4HIfjpVc53Ica6CaLAAjf3AaSfn7o4qhnAC8FxZKIeCh9OXRCi2PuhrWaXyb27
it9NiPTRAgMBAAECggEALvuMAwbE/NkrM6pW6VAVF9wOay0M8YGxhOFBdS/pRfTP
x3Bq6g3iRVAbq75/rWYH4zDi32SGJlthejH4eI06qApjGcVhMdseqKRFCNovGm1k
XL5LnEwVfAsJPTQAXGg/ksrlEq9pE42csYifXU9cWFMlytcdnhDHBnnOF+l4aGd6
PQ9WyaeU+RLK1Tw+TlAqBmauoJAazcsQK52JzfIoJA8rlsb3mfVUKtjQc5t30xMU
dYqJfEa1H5ZW6/Wl/gpnKpcteh6uPi420ROKIzMoc1N2CVjbxLzjzosYXZh1xNpC
xoGQCU1Dni5d0SD5lzjFksWXdP2ChknRCVZRpw63iQKBgQDKhqg+I7/6kUb76ITn
2PPULkTjb32fycRejKdjsHsYShItBDiIlYs75rZ8a1fh5pYhVPojjpfy9MeVcXpB
ENl1D2PwqgxZUC1dT0wEJdbs/kKDaacJGcfvZHtvFruwv2G9+aTqls5jXONqywgY
yDFaTMro1y9x+iLrv7QJbt4vAwKBgQC6vhvbWX7Csh7oirRhehnRD7zhpSXmrO3T
09ojgq13JlVlTpiG2yinJPmHt5b8/3giKsVf73tBIq+xTd+o6OUa6Ax7wPSXo10u
HYDsmv6aJe+hqWMxaNQB+ZiiASgc7w4P46429l9hOzh6E19wuDTwcJilar9OdJLO
s8ux6cQqmwKBgQCRXZXlBEQH1b7dkUfUIiThZ1SK6ruAtZH9S3faVhIEnSXuqdjq
MGx/0lmpdGLgAmJACn6AhxkJiii3W3wkt7NeEm3pkCTM9n+ZOhGV6JMcCGQ1buA1
6AtaCQWP9wFBHB1L/qQgvZ3mNAYH4TMuloLWDciW1912MdRe4nqXSryvgQKBgQCX
l5YjhU4KnO/MVDTD4Iuuk7j/78GJtZ3G1HaDVySb0amG+LuG1cf1j2VlD9ro/DW4
fsIE8/I5WQAIza+ffZfmNLNVjri/lCUjN14eNGA0IFGcCVZ1mKRqCgUmlgvLGSBw
M6KMCYo58woQx0M1zMNk3/J6beJovOckFv5nKd5NuwKBgGf5jPsbecbg1Ab3lz8v
KWEJ1wsImYZWlbBnZuPlzIZnixuMKL7MpDw97MzwalmRYd6qJkvyY5J2J8ztkYqd
Q8eTlKSoAfy/hDaOml8YxowhkAd9L8751N8FaXQenRdSRoAhqCimCxVO6u8uMusf
umiyrfajUCuMBfkKpIyikNYL
-----END PRIVATE KEY-----`;

const TLS_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUTTgs1VpwKXf8hxW0ISPwgwNf5XcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDQxNjE4MjI0MFoXDTM2MDQx
MzE4MjI0MFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAk7w8N7/VmEK4pYsMpajFmz7LJkqh3urvZowNvNqd1WEh
PZa9brpPlVDCgpG3lC1dPf0s+74iLovgIgqYlaBhWGA8+WXP/TQPq4eZYMFIc7X+
NVcjoK5XNcfoUk+DmpmVxApqC5naQRVNMyM2u1KvJnBwY2eAUlMk3TNTLR86HwGt
Bcx5gSfTv79C9HpB3P71lEpmH+YdhHOHbppn+GvSjjHEqHv+YN6Ck/dMJNklxxCX
ePSjMTxRuLvSNgkXipCEL+uMS7V0fLKTFK/+ByH46VXOdyHGugmiwAI39wGkn5+6
OKoZwAvBcWSiHgofTl0Qotj7oa1ml8m9u4rfTYj00QIDAQABo1MwUTAdBgNVHQ4E
FgQUaKLlwtp2dIDsJqqMQZAK4KkqQvwwHwYDVR0jBBgwFoAUaKLlwtp2dIDsJqqM
QZAK4KkqQvwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAgV8c
8B0+i+Ik6W4DngGpu2DKslOv5Lakb/Qi1kh1HwozjKdK4MSihNVtiFv9+xQ8Q1wx
JeZcJEhH8qKTJRJrdVYIUZxPD2B8dbnVxsnfs5rcvZ7ogD1meFH7gnoBkiRBV0Th
dJE+KcNG9sV7mbgLUM0aoHfbKW1dYEr8VN/IPplejKLprQkefQVax9N9QGo8YquZ
RwwzZ3b35ZnGhqNwlejZm1Bg2U+VLKwK4HsR01THd81L3f6TRsr1uf9JTDqeuiy4
JNPEN8a2Q/fiL/EXelGrv7I056wNxn/hsGOpJ106bgW+QoCRueNJxFpGxC9Gfv6I
xAL2DZ0k+FNI9/KWhg==
-----END CERTIFICATE-----`;

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
    snapshotSeqno: 0,
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
    snapshotSeqno: document.snapshotSeqno,
    issuedAt: document.issuedAt,
    expiresAt: document.expiresAt,
    ...overrides,
  };
}

function buildLocalAttestationWithDocument(
  documentOverrides?: Record<string, unknown>,
  responseOverrides?: Partial<AttestationResponse>
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
    snapshotSeqno: 0,
    issuedAt: "2026-04-13T00:00:00.000Z",
    expiresAt: "2099-04-13T00:00:00.000Z",
    ...documentOverrides,
  };

  return {
    vaultConfig,
    vaultSigner,
    attestationPolicyHash: document.attestationPolicyHash,
    attestationDocument: Buffer.from(JSON.stringify(document), "utf8").toString(
      "base64"
    ),
    snapshotSeqno: document.snapshotSeqno,
    issuedAt: document.issuedAt,
    expiresAt: document.expiresAt,
    ...responseOverrides,
  };
}

function installFetchResponse(body: unknown): void {
  globalThis.fetch = (async () =>
    ({
      ok: true,
      json: async () => body,
    } as any)) as typeof fetch;
}

function computeTlsPublicKeySha256(certificatePem: string): string {
  const certificate = new X509Certificate(certificatePem);
  const publicKeyDer = certificate.publicKey.export({
    format: "der",
    type: "spki",
  }) as Buffer;
  return createHash("sha256").update(publicKeyDer).digest("hex");
}

async function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("expected server to bind a TCP port"));
        return;
      }
      resolve(address.port);
    });
    server.once("error", reject);
  });
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
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

  it("binds attested tlsPublicKeySha256 to the live HTTPS endpoint certificate", async () => {
    const wallet = Keypair.generate();
    const tlsPublicKeySha256 = computeTlsPublicKeySha256(TLS_CERT_PEM);
    const server = createServer(
      {
        key: TLS_PRIVATE_KEY_PEM,
        cert: TLS_CERT_PEM,
      },
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      }
    );

    const port = await listen(server);
    const attestation = buildLocalAttestationWithDocument(
      { tlsPublicKeySha256 },
      { tlsPublicKeySha256 }
    );

    installFetchResponse(attestation);

    try {
      const client = new A402Client({
        walletKeypair: wallet,
        vaultAddress: new PublicKey(attestation.vaultConfig),
        enclaveUrl: `https://127.0.0.1:${port}`,
      });

      const verified = await client.verifyAttestation();
      expect(verified.tlsPublicKeySha256).to.equal(tlsPublicKeySha256);
    } finally {
      await close(server);
    }
  });

  it("rejects an HTTPS endpoint whose certificate does not match attested tlsPublicKeySha256", async () => {
    const wallet = Keypair.generate();
    const server = createServer(
      {
        key: TLS_PRIVATE_KEY_PEM,
        cert: TLS_CERT_PEM,
      },
      (_req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      }
    );

    const port = await listen(server);
    const attestation = buildLocalAttestationWithDocument(
      { tlsPublicKeySha256: "ef".repeat(32) },
      { tlsPublicKeySha256: "ef".repeat(32) }
    );

    installFetchResponse(attestation);

    try {
      const client = new A402Client({
        walletKeypair: wallet,
        vaultAddress: new PublicKey(attestation.vaultConfig),
        enclaveUrl: `https://127.0.0.1:${port}`,
      });

      try {
        await client.verifyAttestation();
        throw new Error("expected verifyAttestation to reject");
      } catch (error) {
        expect((error as Error).message).to.equal(
          "Enclave TLS endpoint certificate does not match attested tlsPublicKeySha256"
        );
      }
    } finally {
      await close(server);
    }
  });
});
