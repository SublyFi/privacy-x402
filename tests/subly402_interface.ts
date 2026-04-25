import { createServer, Server } from "http";

import { address as solanaAddress, generateKeyPairSigner } from "@solana/kit";
import {
  findAssociatedTokenPda,
  TOKEN_PROGRAM_ADDRESS,
} from "@solana-program/token";
import { expect } from "chai";
import express from "express";

import {
  paymentMiddleware,
  Subly402ExactScheme,
  Subly402FacilitatorClient,
  subly402ResourceServer,
} from "../middleware/src";
import {
  Subly402Client,
  Subly402ExactScheme as BuyerSubly402ExactScheme,
} from "../sdk/src";
import type {
  AttestationResponse,
  PaymentDetails,
  PaymentPayload,
} from "../sdk/src";

function decodeJsonHeader<T>(value: string): T {
  return JSON.parse(Buffer.from(value, "base64").toString("utf8")) as T;
}

async function deriveAta(owner: string, mint: string): Promise<string> {
  const [ata] = await findAssociatedTokenPda({
    owner: solanaAddress(owner),
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
    mint: solanaAddress(mint),
  });
  return ata;
}

function buildLocalAttestation(args: {
  vaultConfig: string;
  vaultSigner: string;
  attestationPolicyHash: string;
}): AttestationResponse {
  const document = {
    version: 1,
    mode: "local-dev",
    vaultConfig: args.vaultConfig,
    vaultSigner: args.vaultSigner,
    attestationPolicyHash: args.attestationPolicyHash,
    snapshotSeqno: 7,
    issuedAt: "2026-04-20T00:00:00.000Z",
    expiresAt: "2099-04-20T00:00:00.000Z",
  };

  return {
    ...args,
    attestationDocument: Buffer.from(JSON.stringify(document), "utf8").toString(
      "base64"
    ),
    snapshotSeqno: document.snapshotSeqno,
    issuedAt: document.issuedAt,
    expiresAt: document.expiresAt,
  };
}

async function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        throw new Error("Failed to bind test server");
      }
      resolve(address.port);
    });
  });
}

async function closeServer(server: Server | undefined): Promise<void> {
  if (!server) {
    return;
  }
  server.closeAllConnections?.();
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

describe("subly402 x402-compatible interface", () => {
  let server: Server | undefined;

  afterEach(async () => {
    await closeServer(server);
    server = undefined;
  });

  it("lets sellers declare x402-like exact routes without exposing subly402 config", async () => {
    const sellerWallet = (await generateKeyPairSigner()).address;
    const assetMint = (await generateKeyPairSigner()).address;
    const payTo = await deriveAta(sellerWallet, assetMint);
    const facilitator = new Subly402FacilitatorClient({
      url: "http://facilitator.example",
      providerApiKey: "provider-secret",
      vaultConfig: "vault-config",
      vaultSigner: "vault-signer",
      attestationPolicyHash: "ab".repeat(32),
      assetMint,
      assetDecimals: 6,
      assetSymbol: "USDC",
    });
    const resourceServer = new subly402ResourceServer(facilitator).register(
      "solana:devnet",
      new Subly402ExactScheme()
    );

    const app = express();
    app.get(
      "/weather",
      paymentMiddleware(
        {
          "GET /weather": {
            accepts: [
              {
                scheme: "exact",
                price: "$0.001",
                network: "solana:devnet",
                providerId: "weather-provider",
                sellerWallet,
              },
            ],
          },
        },
        resourceServer
      ),
      (_req, res) => res.json({ ok: true })
    );

    server = createServer(app);
    const port = await listen(server);

    const response = await fetch(`http://127.0.0.1:${port}/weather`);
    expect(response.status).to.equal(402);

    const header = response.headers.get("payment-required");
    expect(header).to.be.a("string");
    const paymentRequired = decodeJsonHeader<{ accepts: PaymentDetails[] }>(
      header!
    );
    const [details] = paymentRequired.accepts;

    expect(details.scheme).to.equal("subly402-svm-v1");
    expect(details.amount).to.equal("1000");
    expect(details.providerId).to.equal("weather-provider");
    expect(details.payTo).to.equal(payTo);
    expect(details.facilitatorUrl).to.equal("http://facilitator.example");
    expect(details.vault.config).to.equal("vault-config");
  });

  it("lets buyers pay from discovered 402 details with an @solana/kit signer", async () => {
    const signer = await generateKeyPairSigner();
    const attestation = buildLocalAttestation({
      vaultConfig: "vault-config",
      vaultSigner: "vault-signer",
      attestationPolicyHash: "cd".repeat(32),
    });
    const details: PaymentDetails = {
      scheme: "subly402-svm-v1",
      network: "solana:devnet",
      amount: "1000",
      asset: {
        kind: "spl-token",
        mint: "usdc-mint",
        decimals: 6,
        symbol: "USDC",
      },
      payTo: "provider-token-account",
      providerId: "weather-provider",
      facilitatorUrl: "http://facilitator.example",
      vault: {
        config: attestation.vaultConfig,
        signer: attestation.vaultSigner,
        attestationPolicyHash: attestation.attestationPolicyHash,
      },
      paymentDetailsId: "paydet_weather",
      verifyWindowSec: 60,
      maxSettlementDelaySec: 900,
      privacyMode: "vault-batched-v1",
    };

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL) => {
      const url = input.toString();
      if (url === "http://facilitator.example/v1/attestation") {
        return new Response(JSON.stringify(attestation), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected global fetch: ${url}`);
    }) as typeof fetch;

    try {
      let providerRequests = 0;
      let observedPaymentSignature = "";
      const providerFetch = async (
        _input: string | URL,
        init?: RequestInit
      ): Promise<Response> => {
        providerRequests += 1;
        if (providerRequests === 1) {
          return new Response(JSON.stringify({ accepts: [details] }), {
            status: 402,
            headers: {
              "content-type": "application/json",
              "PAYMENT-REQUIRED": Buffer.from(
                JSON.stringify({ accepts: [details] }),
                "utf8"
              ).toString("base64"),
            },
          });
        }

        observedPaymentSignature =
          new Headers(init?.headers).get("PAYMENT-SIGNATURE") || "";
        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      };

      const client = new Subly402Client({
        trustedFacilitators: ["http://facilitator.example"],
        policy: {
          maxPaymentPerRequest: "$0.01",
        },
      }).register("solana:*", new BuyerSubly402ExactScheme(signer));

      const response = await client.fetch(
        "https://seller.example/weather",
        { method: "GET" },
        providerFetch
      );

      expect(response.status).to.equal(200);
      expect(providerRequests).to.equal(2);
      expect(observedPaymentSignature).to.not.equal("");

      const payload = decodeJsonHeader<PaymentPayload>(
        observedPaymentSignature
      );
      expect(payload.scheme).to.equal("subly402-svm-v1");
      expect(payload.providerId).to.equal("weather-provider");
      expect(payload.amount).to.equal("1000");
      expect(payload.client).to.equal(signer.address);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("re-fetches a cached attestation whose details no longer match", async () => {
    // Regression for Codex #2: Subly402Client used to return a cached
    // attestation unconditionally on cache hit, skipping expiry and
    // details-match checks. Long-lived buyer processes would then sign
    // PAYMENT-SIGNATURE against an attestation bound to a different vault
    // signer if the facilitator rotated.
    const signer = await generateKeyPairSigner();
    const attestationV1 = buildLocalAttestation({
      vaultConfig: "vault-config",
      vaultSigner: "vault-signer-v1",
      attestationPolicyHash: "cd".repeat(32),
    });
    const attestationV2 = buildLocalAttestation({
      vaultConfig: "vault-config",
      vaultSigner: "vault-signer-v2",
      attestationPolicyHash: "cd".repeat(32),
    });
    const detailsFor = (version: 1 | 2): PaymentDetails => ({
      scheme: "subly402-svm-v1",
      network: "solana:devnet",
      amount: "1000",
      asset: {
        kind: "spl-token",
        mint: "usdc-mint",
        decimals: 6,
        symbol: "USDC",
      },
      payTo: "provider-token-account",
      providerId: "weather-provider",
      facilitatorUrl: "http://facilitator.example",
      vault: {
        config: "vault-config",
        signer: version === 1 ? "vault-signer-v1" : "vault-signer-v2",
        attestationPolicyHash: "cd".repeat(32),
      },
      paymentDetailsId: "paydet_weather",
      verifyWindowSec: 60,
      maxSettlementDelaySec: 900,
      privacyMode: "vault-batched-v1",
    });

    const originalFetch = globalThis.fetch;
    let attestationCalls = 0;
    globalThis.fetch = (async (input: string | URL) => {
      const url = input.toString();
      if (url === "http://facilitator.example/v1/attestation") {
        attestationCalls += 1;
        const body = attestationCalls === 1 ? attestationV1 : attestationV2;
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected global fetch: ${url}`);
    }) as typeof fetch;

    try {
      const client = new Subly402Client({
        trustedFacilitators: ["http://facilitator.example"],
        policy: { maxPaymentPerRequest: "$0.01" },
      }).register("solana:*", new BuyerSubly402ExactScheme(signer));

      const providerFetchFor =
        (version: 1 | 2) =>
        async (
          _input: string | URL,
          _init?: RequestInit
        ): Promise<Response> => {
          const details = detailsFor(version);
          return new Response(JSON.stringify({ accepts: [details] }), {
            status: 402,
            headers: {
              "content-type": "application/json",
              "PAYMENT-REQUIRED": Buffer.from(
                JSON.stringify({ accepts: [details] }),
                "utf8"
              ).toString("base64"),
            },
          });
        };

      // First attempt primes the cache with v1.
      await client
        .fetch(
          "https://seller.example/weather",
          { method: "GET" },
          providerFetchFor(1) as typeof fetch
        )
        .catch(() => {
          /* payment retry isn't the point of this test */
        });
      expect(attestationCalls).to.equal(1);

      // Second attempt discovers a different vault signer — the cached
      // attestation must be evicted so a fresh fetch runs.
      await client
        .fetch(
          "https://seller.example/weather",
          { method: "GET" },
          providerFetchFor(2) as typeof fetch
        )
        .catch(() => {
          /* noop */
        });
      expect(attestationCalls).to.equal(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("retries attestation fetch after a transient facilitator failure", async () => {
    // Regression for Codex #3: a rejected attestationPromise used to stay
    // cached, so the next /v1/attestation call kept replaying the same failure
    // until process restart.
    const facilitator = new Subly402FacilitatorClient({
      url: "http://facilitator.example",
      assetMint: "usdc-mint",
    });

    const originalFetch = globalThis.fetch;
    let callCount = 0;
    globalThis.fetch = (async () => {
      callCount += 1;
      if (callCount === 1) {
        return {
          ok: false,
          status: 503,
          text: async () => "service unavailable",
        } as any;
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          vaultConfig: "vault-config",
          vaultSigner: "vault-signer",
          attestationPolicyHash: "ab".repeat(32),
        }),
      } as any;
    }) as any;

    try {
      let firstError: unknown;
      try {
        await facilitator.getAttestation();
      } catch (error) {
        firstError = error;
      }
      expect(firstError).to.be.instanceOf(Error);

      // Second call should retry rather than replay the cached rejection.
      const attestation = await facilitator.getAttestation();
      expect(attestation.vaultConfig).to.equal("vault-config");
      expect(callCount).to.equal(2);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("runs on-demand deposit after an insufficient-balance paid retry", async () => {
    const signer = await generateKeyPairSigner();
    const attestation = buildLocalAttestation({
      vaultConfig: "vault-config",
      vaultSigner: "vault-signer",
      attestationPolicyHash: "cd".repeat(32),
    });
    const details: PaymentDetails = {
      scheme: "subly402-svm-v1",
      network: "solana:devnet",
      amount: "1000",
      asset: {
        kind: "spl-token",
        mint: "usdc-mint",
        decimals: 6,
        symbol: "USDC",
      },
      payTo: "provider-token-account",
      providerId: "weather-provider",
      facilitatorUrl: "http://facilitator.example",
      vault: {
        config: attestation.vaultConfig,
        signer: attestation.vaultSigner,
        attestationPolicyHash: attestation.attestationPolicyHash,
      },
      paymentDetailsId: "paydet_weather",
      verifyWindowSec: 60,
      maxSettlementDelaySec: 900,
      privacyMode: "vault-batched-v1",
    };

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: string | URL) => {
      const url = input.toString();
      if (url === "http://facilitator.example/v1/attestation") {
        return new Response(JSON.stringify(attestation), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected global fetch: ${url}`);
    }) as typeof fetch;

    try {
      let providerRequests = 0;
      let depositCalls = 0;
      const observedPaymentIds: string[] = [];
      const providerFetch = async (
        _input: string | URL,
        init?: RequestInit
      ): Promise<Response> => {
        providerRequests += 1;
        if (providerRequests === 1) {
          return new Response(JSON.stringify({ accepts: [details] }), {
            status: 402,
            headers: {
              "content-type": "application/json",
              "PAYMENT-REQUIRED": Buffer.from(
                JSON.stringify({ accepts: [details] }),
                "utf8"
              ).toString("base64"),
            },
          });
        }

        const signature = new Headers(init?.headers).get("PAYMENT-SIGNATURE");
        expect(signature).to.be.a("string").and.not.equal("");
        observedPaymentIds.push(
          decodeJsonHeader<PaymentPayload>(signature!).paymentId
        );

        if (providerRequests === 2) {
          return new Response(
            JSON.stringify({
              accepts: [details],
              error: "payment_verification_failed",
              facilitatorError: "insufficient_balance",
              message: "Insufficient client balance",
            }),
            {
              status: 402,
              headers: { "content-type": "application/json" },
            }
          );
        }

        return new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      };

      const client = new Subly402Client({
        trustedFacilitators: ["http://facilitator.example"],
        policy: { maxPaymentPerRequest: "$0.01" },
        autoDeposit: {
          maxDepositPerRequest: "$0.01",
          deposit: async ({ amount, amountAtomic, details }) => {
            depositCalls += 1;
            expect(amount).to.equal("1000");
            expect(amountAtomic).to.equal(1000n);
            expect(details.providerId).to.equal("weather-provider");
          },
        },
      }).register("solana:*", new BuyerSubly402ExactScheme(signer));

      const response = await client.fetch(
        "https://seller.example/weather",
        { method: "GET" },
        providerFetch
      );

      expect(response.status).to.equal(200);
      expect(providerRequests).to.equal(3);
      expect(depositCalls).to.equal(1);
      expect(observedPaymentIds).to.have.length(2);
      expect(observedPaymentIds[0]).to.not.equal(observedPaymentIds[1]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
