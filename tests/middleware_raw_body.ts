import { createHash } from "crypto";
import { createServer, Server } from "http";

import { expect } from "chai";
import express from "express";

import { subly402Middleware, captureSubly402RawBody } from "../middleware/src";

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
});
