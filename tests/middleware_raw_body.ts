import { createHash } from "crypto";
import { createServer, Server } from "http";

import { address as solanaAddress, generateKeyPairSigner } from "@solana/kit";
import {
  findAssociatedTokenPda,
  TOKEN_PROGRAM_ADDRESS,
} from "@solana-program/token";
import { expect } from "chai";
import express from "express";

import {
  Subly402ExactScheme,
  Subly402FacilitatorClient,
  Subly402ResourceServer,
  captureSubly402RawBody,
  paymentMiddleware,
  subly402Middleware,
} from "../middleware/src";

function sha256hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

function decodeJsonHeader<T>(value: string): T {
  return JSON.parse(Buffer.from(value, "base64").toString("utf8")) as T;
}

function buildExpectedPaymentDetailsId(args: {
  providerId: string;
  payTo: string;
  network: string;
  assetMint: string;
  vaultConfig: string;
  amount: string;
  method: string;
  origin: string;
  pathAndQuery: string;
  bodySha256: string;
}): string {
  const hash = createHash("sha256")
    .update("SUBLY402-SVM-V1-PAYDET\n")
    .update(args.providerId)
    .update("\n")
    .update(args.payTo)
    .update("\n")
    .update(args.network)
    .update("\n")
    .update(args.assetMint)
    .update("\n")
    .update(args.vaultConfig)
    .update("\n")
    .update(args.amount)
    .update("\n")
    .update(args.method)
    .update("\n")
    .update(args.origin)
    .update("\n")
    .update(args.pathAndQuery)
    .update("\n")
    .update(args.bodySha256)
    .update("\n")
    .digest("hex");

  return `paydet_${hash.slice(0, 32)}`;
}

function deriveProviderId(args: {
  network: string;
  assetMint: string;
  payTo: string;
}): string {
  const hash = createHash("sha256")
    .update("SUBLY402-OPEN-PROVIDER-V1\n")
    .update(args.network)
    .update("\n")
    .update(args.assetMint)
    .update("\n")
    .update(args.payTo)
    .update("\n")
    .digest("hex");

  return `payto_${hash.slice(0, 32)}`;
}

async function deriveAta(owner: string, mint: string): Promise<string> {
  const [ata] = await findAssociatedTokenPda({
    owner: solanaAddress(owner),
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
    mint: solanaAddress(mint),
  });
  return ata;
}

describe("middleware_raw_body", () => {
  let server: Server | undefined;
  let facilitatorServer: Server | undefined;
  let baseUrl = "";

  afterEach(async () => {
    const servers = [server, facilitatorServer].filter(Boolean) as Server[];
    for (const current of servers) {
      current.closeAllConnections?.();
    }
    await Promise.all(
      servers.map(
        (current) =>
          new Promise<void>((resolve, reject) => {
            current.close((error) => {
              if (error) {
                reject(error);
                return;
              }
              resolve();
            });
          })
      )
    );
    server = undefined;
    facilitatorServer = undefined;
  });

  it("uses preserved raw body bytes for request binding", async () => {
    const app = express();
    app.use(express.json({ verify: captureSubly402RawBody }));
    app.post(
      "/metered",
      subly402Middleware({
        config: {
          facilitatorUrl: "http://127.0.0.1:3999",
          providerId: "prov_test",
          apiKey: "provider-secret",
          payTo: "payto111111111111111111111111111111111111111",
          network: "solana:localnet",
          assetMint: "mint111111111111111111111111111111111111111",
          assetDecimals: 6,
          assetSymbol: "USDC",
          vaultConfig: "vault11111111111111111111111111111111111111",
          vaultSigner: "signer1111111111111111111111111111111111111",
          attestationPolicyHash: "00".repeat(32),
        },
        pricing: () => "1234",
      }),
      (_req, res) => {
        res.json({ ok: true });
      }
    );

    server = createServer(app);
    await new Promise<void>((resolve) => {
      server?.listen(0, "127.0.0.1", () => resolve());
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to bind test server");
    }
    baseUrl = `http://127.0.0.1:${address.port}`;

    const rawBody = '{"b":1, "a":2}';
    const response = await fetch(`${baseUrl}/metered?x=1`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: rawBody,
    });
    expect(response.status).to.equal(402);
    const paymentRequiredHeader = response.headers.get("payment-required");
    expect(paymentRequiredHeader).to.be.a("string").and.not.equal(null);
    const body = (await response.json()) as {
      accepts: Array<{ paymentDetailsId: string }>;
    };
    const headerBody = decodeJsonHeader<{
      accepts: Array<{ paymentDetailsId: string }>;
    }>(paymentRequiredHeader!);

    const expected = buildExpectedPaymentDetailsId({
      providerId: "prov_test",
      payTo: "payto111111111111111111111111111111111111111",
      network: "solana:localnet",
      assetMint: "mint111111111111111111111111111111111111111",
      vaultConfig: "vault11111111111111111111111111111111111111",
      amount: "1234",
      method: "POST",
      origin: baseUrl,
      pathAndQuery: "/metered?x=1",
      bodySha256: sha256hex(rawBody),
    });
    const normalized = buildExpectedPaymentDetailsId({
      providerId: "prov_test",
      payTo: "payto111111111111111111111111111111111111111",
      network: "solana:localnet",
      assetMint: "mint111111111111111111111111111111111111111",
      vaultConfig: "vault11111111111111111111111111111111111111",
      amount: "1234",
      method: "POST",
      origin: baseUrl,
      pathAndQuery: "/metered?x=1",
      bodySha256: sha256hex(JSON.stringify(JSON.parse(rawBody))),
    });

    expect(body.accepts[0].paymentDetailsId).to.equal(expected);
    expect(body.accepts[0].paymentDetailsId).to.not.equal(normalized);
    expect(headerBody.accepts[0].paymentDetailsId).to.equal(expected);
  });

  it("emits x402-compatible headers for 402 and settled responses", async () => {
    facilitatorServer = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }

      res.setHeader("Content-Type", "application/json");
      if (req.url === "/v1/verify") {
        res.end(
          JSON.stringify({
            ok: true,
            verificationId: "ver_test",
            reservationId: "res_test",
            reservationExpiresAt: "2026-04-18T00:00:00.000Z",
            providerId: "prov_test",
            amount: "1234",
            verificationReceipt: "verification-receipt",
          })
        );
        return;
      }

      if (req.url === "/v1/settle") {
        const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        expect(payload.verificationId).to.equal("ver_test");
        expect(payload.resultHash).to.match(/^[0-9a-f]{64}$/);
        res.end(
          JSON.stringify({
            ok: true,
            settlementId: "set_test",
            offchainSettledAt: "2026-04-18T00:00:01.000Z",
            providerCreditAmount: "1234",
            batchId: null,
            participantReceipt: "participant-receipt",
          })
        );
        return;
      }

      res.statusCode = 404;
      res.end(JSON.stringify({ ok: false }));
    });

    await new Promise<void>((resolve) => {
      facilitatorServer?.listen(0, "127.0.0.1", () => resolve());
    });
    const facilitatorAddress = facilitatorServer.address();
    if (!facilitatorAddress || typeof facilitatorAddress === "string") {
      throw new Error("Failed to bind facilitator stub");
    }
    const facilitatorUrl = `http://127.0.0.1:${facilitatorAddress.port}`;

    const app = express();
    app.get(
      "/metered",
      subly402Middleware({
        config: {
          facilitatorUrl,
          providerId: "prov_test",
          apiKey: "provider-secret",
          payTo: "payto111111111111111111111111111111111111111",
          network: "solana:localnet",
          assetMint: "mint111111111111111111111111111111111111111",
          assetDecimals: 6,
          assetSymbol: "USDC",
          vaultConfig: "vault11111111111111111111111111111111111111",
          vaultSigner: "signer1111111111111111111111111111111111111",
          attestationPolicyHash: "00".repeat(32),
        },
        pricing: () => "1234",
      }),
      (_req, res) => {
        res.json({ ok: true, answer: 42 });
      }
    );

    server = createServer(app);
    await new Promise<void>((resolve) => {
      server?.listen(0, "127.0.0.1", () => resolve());
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to bind test server");
    }
    baseUrl = `http://127.0.0.1:${address.port}`;

    const first = await fetch(`${baseUrl}/metered`);
    expect(first.status).to.equal(402);
    const paymentRequiredHeader = first.headers.get("payment-required");
    expect(paymentRequiredHeader).to.be.a("string").and.not.equal(null);

    const paymentSignature = Buffer.from(
      JSON.stringify({
        paymentId: "pay_test",
        amount: "1234",
        providerId: "prov_test",
      }),
      "utf8"
    ).toString("base64");

    const second = await fetch(`${baseUrl}/metered`, {
      headers: {
        "PAYMENT-SIGNATURE": paymentSignature,
      },
    });
    expect(second.status).to.equal(200);
    expect(await second.json()).to.deep.equal({ ok: true, answer: 42 });

    const paymentResponseHeader = second.headers.get("payment-response");
    expect(paymentResponseHeader).to.be.a("string").and.not.equal(null);
    const paymentResponse = decodeJsonHeader<{
      verificationId: string;
      settlementId: string;
      participantReceipt: string;
    }>(paymentResponseHeader!);

    expect(paymentResponse.verificationId).to.equal("ver_test");
    expect(paymentResponse.settlementId).to.equal("set_test");
    expect(paymentResponse.participantReceipt).to.equal("participant-receipt");
  });

  it("supports seller routes without provider registration or API keys", async () => {
    const sellerWallet = (await generateKeyPairSigner()).address;
    const assetMint = (await generateKeyPairSigner()).address;
    const network = "solana:localnet";
    const payTo = await deriveAta(sellerWallet, assetMint);
    const providerId = deriveProviderId({ network, assetMint, payTo });
    const seenAuthHeaders: Array<{
      authorization?: string;
      providerAuth?: string;
      providerId?: string;
    }> = [];

    facilitatorServer = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      seenAuthHeaders.push({
        authorization: req.headers.authorization as string | undefined,
        providerAuth: req.headers["x-subly402-provider-auth"] as
          | string
          | undefined,
        providerId: req.headers["x-subly402-provider-id"] as string | undefined,
      });

      res.setHeader("Content-Type", "application/json");
      if (req.url === "/v1/verify") {
        res.end(
          JSON.stringify({
            ok: true,
            verificationId: "ver_open",
            reservationId: "res_open",
            reservationExpiresAt: "2026-04-18T00:00:00.000Z",
            providerId,
            amount: "1000",
            verificationReceipt: "verification-receipt",
          })
        );
        return;
      }

      if (req.url === "/v1/settle") {
        res.end(
          JSON.stringify({
            ok: true,
            settlementId: "set_open",
            offchainSettledAt: "2026-04-18T00:00:01.000Z",
            providerCreditAmount: "1000",
            batchId: null,
            participantReceipt: "participant-receipt",
          })
        );
        return;
      }

      res.statusCode = 404;
      res.end(JSON.stringify({ ok: false }));
    });

    await new Promise<void>((resolve) => {
      facilitatorServer?.listen(0, "127.0.0.1", () => resolve());
    });
    const facilitatorAddress = facilitatorServer.address();
    if (!facilitatorAddress || typeof facilitatorAddress === "string") {
      throw new Error("Failed to bind facilitator stub");
    }
    const facilitatorUrl = `http://127.0.0.1:${facilitatorAddress.port}`;

    const facilitator = new Subly402FacilitatorClient({
      url: facilitatorUrl,
      assetMint,
      vaultConfig: "vault11111111111111111111111111111111111111",
      vaultSigner: "signer1111111111111111111111111111111111111",
      attestationPolicyHash: "00".repeat(32),
    });
    const resourceServer = new Subly402ResourceServer(facilitator).register(
      "solana:*",
      new Subly402ExactScheme()
    );

    const app = express();
    app.get(
      "/open",
      paymentMiddleware(
        {
          "GET /open": {
            accepts: [
              {
                scheme: "exact",
                price: "$0.001",
                network,
                sellerWallet,
              },
            ],
          },
        },
        resourceServer
      ),
      (_req, res) => {
        res.json({ ok: true });
      }
    );

    server = createServer(app);
    await new Promise<void>((resolve) => {
      server?.listen(0, "127.0.0.1", () => resolve());
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to bind test server");
    }
    baseUrl = `http://127.0.0.1:${address.port}`;

    const first = await fetch(`${baseUrl}/open`);
    expect(first.status).to.equal(402);
    const paymentRequired = (await first.json()) as {
      accepts: Array<{ providerId: string; amount: string }>;
    };
    expect(paymentRequired.accepts[0].providerId).to.equal(providerId);
    expect(paymentRequired.accepts[0].amount).to.equal("1000");

    const paymentSignature = Buffer.from(
      JSON.stringify({
        paymentId: "pay_open",
        amount: "1000",
        providerId,
      }),
      "utf8"
    ).toString("base64");
    const second = await fetch(`${baseUrl}/open`, {
      headers: {
        "PAYMENT-SIGNATURE": paymentSignature,
      },
    });
    expect(second.status).to.equal(200);
    expect(await second.json()).to.deep.equal({ ok: true });

    expect(seenAuthHeaders).to.have.length(2);
    for (const headers of seenAuthHeaders) {
      expect(headers.providerId).to.equal(providerId);
      expect(headers.authorization).to.equal(undefined);
      expect(headers.providerAuth).to.equal(undefined);
    }
  });
});
