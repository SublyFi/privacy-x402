import { createHash } from "crypto";
import { createServer, Server } from "http";

import { expect } from "chai";
import express from "express";

import {
  a402Middleware,
  captureA402RawBody,
} from "../middleware/src";

function sha256hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
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
    .update("A402-SVM-V1-PAYDET\n")
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
  let baseUrl = "";

  afterEach(async () => {
    if (!server) {
      return;
    }
    await new Promise<void>((resolve, reject) => {
      server?.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
    server = undefined;
  });

  it("uses preserved raw body bytes for request binding", async () => {
    const app = express();
    app.use(express.json({ verify: captureA402RawBody }));
    app.post(
      "/metered",
      a402Middleware({
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
    const body = (await response.json()) as {
      accepts: Array<{ paymentDetailsId: string }>;
    };

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
  });
});
