import { expect } from "chai";
import { createHash, randomUUID } from "crypto";
import nacl from "tweetnacl";
import { Keypair } from "@solana/web3.js";

/**
 * Enclave Facilitator API integration tests.
 *
 * Prerequisites: enclave must be running on localhost:3100
 * Run: cargo run -p a402-enclave &
 * Then: yarn run ts-mocha -p ./tsconfig.json -t 30000 tests/enclave_api.ts
 */

const ENCLAVE_URL = "http://localhost:3100";

type RequestContext = {
  method: string;
  origin: string;
  pathAndQuery: string;
  bodySha256: string;
};

type PaymentPayload = {
  version: number;
  scheme: string;
  paymentId: string;
  client: string;
  vault: string;
  providerId: string;
  payTo: string;
  network: string;
  assetMint: string;
  amount: string;
  requestHash: string;
  paymentDetailsHash: string;
  expiresAt: string;
  nonce: string;
  clientSig: string;
};

function sha256Hex(input: string): string {
  const hash = createHash("sha256");
  hash.update(input);
  return hash.digest("hex");
}

function computeRequestHash(
  ctx: RequestContext,
  paymentDetailsHash: string
): string {
  const hash = createHash("sha256");
  hash.update("A402-SVM-V1-REQ\n");
  hash.update(ctx.method);
  hash.update("\n");
  hash.update(ctx.origin);
  hash.update("\n");
  hash.update(ctx.pathAndQuery);
  hash.update("\n");
  hash.update(ctx.bodySha256);
  hash.update("\n");
  hash.update(paymentDetailsHash);
  hash.update("\n");
  return hash.digest("hex");
}

function signPaymentPayload(
  client: Keypair,
  payload: Omit<PaymentPayload, "clientSig">
): string {
  const message =
    "A402-SVM-V1-AUTH\n" +
    `${payload.version}\n` +
    `${payload.scheme}\n` +
    `${payload.paymentId}\n` +
    `${payload.client}\n` +
    `${payload.vault}\n` +
    `${payload.providerId}\n` +
    `${payload.payTo}\n` +
    `${payload.network}\n` +
    `${payload.assetMint}\n` +
    `${payload.amount}\n` +
    `${payload.requestHash}\n` +
    `${payload.paymentDetailsHash}\n` +
    `${payload.expiresAt}\n` +
    `${payload.nonce}\n`;

  const signature = nacl.sign.detached(
    Buffer.from(message),
    client.secretKey
  );
  return Buffer.from(signature).toString("base64");
}

async function postJson(path: string, body: unknown) {
  return fetch(`${ENCLAVE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("enclave_api", () => {
  let attestation: any;

  it("returns attestation document", async () => {
    const res = await fetch(`${ENCLAVE_URL}/v1/attestation`);
    expect(res.status).to.equal(200);

    attestation = await res.json();
    expect(attestation.vaultConfig).to.be.a("string");
    expect(attestation.vaultSigner).to.be.a("string");
    expect(attestation.attestationPolicyHash).to.be.a("string");
    expect(attestation.issuedAt).to.be.a("string");
    expect(attestation.expiresAt).to.be.a("string");
  });

  it("runs a live verify -> balance -> settle -> withdraw-auth -> receipt flow", async () => {
    const client = Keypair.generate();
    const providerId = `prov_${randomUUID()}`;
    const providerSettlementAccount = Keypair.generate().publicKey;
    const assetMint = Keypair.generate().publicKey;
    const paymentAmount = 600_000;

    const registerRes = await postJson("/v1/provider/register", {
      providerId,
      displayName: "Integration Test Provider",
      settlementTokenAccount: providerSettlementAccount.toBase58(),
      network: "solana:localnet",
      assetMint: assetMint.toBase58(),
      allowedOrigins: ["http://localhost"],
      authMode: "none",
      apiKeyHash: "00".repeat(32),
    });
    expect(registerRes.status).to.equal(200);

    const seedRes = await postJson("/v1/admin/seed-balance", {
      client: client.publicKey.toBase58(),
      free: 2_000_000,
      locked: 0,
      totalDeposited: 2_000_000,
    });
    expect(seedRes.status).to.equal(200);

    const requestContext: RequestContext = {
      method: "POST",
      origin: "http://localhost",
      pathAndQuery: "/demo?x=1",
      bodySha256: sha256Hex(JSON.stringify({ hello: "world" })),
    };
    const paymentDetailsHash = sha256Hex("payment-details");
    const requestHash = computeRequestHash(requestContext, paymentDetailsHash);
    const unsignedPayload: Omit<PaymentPayload, "clientSig"> = {
      version: 1,
      scheme: "a402-svm-v1",
      paymentId: `pay_${randomUUID()}`,
      client: client.publicKey.toBase58(),
      vault: attestation.vaultConfig,
      providerId,
      payTo: providerSettlementAccount.toBase58(),
      network: "solana:localnet",
      assetMint: assetMint.toBase58(),
      amount: paymentAmount.toString(),
      requestHash,
      paymentDetailsHash,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      nonce: "1",
    };
    const paymentPayload: PaymentPayload = {
      ...unsignedPayload,
      clientSig: signPaymentPayload(client, unsignedPayload),
    };

    const verifyRes = await postJson("/v1/verify", {
      paymentPayload,
      requestContext,
    });
    expect(verifyRes.status).to.equal(200);
    const verifyBody = await verifyRes.json();
    expect(verifyBody.ok).to.equal(true);
    expect(verifyBody.providerId).to.equal(providerId);
    expect(verifyBody.amount).to.equal(paymentAmount.toString());

    const balanceAfterVerifyRes = await postJson("/v1/balance", {
      client: client.publicKey.toBase58(),
    });
    expect(balanceAfterVerifyRes.status).to.equal(200);
    const balanceAfterVerify = await balanceAfterVerifyRes.json();
    expect(balanceAfterVerify.free).to.equal(1_400_000);
    expect(balanceAfterVerify.locked).to.equal(paymentAmount);

    const settleRes = await postJson("/v1/settle", {
      verificationId: verifyBody.verificationId,
      resultHash: "ab".repeat(32),
      statusCode: 200,
    });
    expect(settleRes.status).to.equal(200);
    const settleBody = await settleRes.json();
    expect(settleBody.ok).to.equal(true);
    expect(settleBody.settlementId).to.match(/^set_/);
    expect(settleBody.providerCreditAmount).to.equal(paymentAmount.toString());
    expect(settleBody.participantReceipt).to.be.a("string").and.not.equal("");

    const settleRetryRes = await postJson("/v1/settle", {
      verificationId: verifyBody.verificationId,
      resultHash: "ab".repeat(32),
      statusCode: 200,
    });
    expect(settleRetryRes.status).to.equal(200);
    const settleRetryBody = await settleRetryRes.json();
    expect(settleRetryBody.settlementId).to.equal(settleBody.settlementId);

    const balanceAfterSettleRes = await postJson("/v1/balance", {
      client: client.publicKey.toBase58(),
    });
    expect(balanceAfterSettleRes.status).to.equal(200);
    const balanceAfterSettle = await balanceAfterSettleRes.json();
    expect(balanceAfterSettle.free).to.equal(1_400_000);
    expect(balanceAfterSettle.locked).to.equal(0);

    const withdrawAuthRes = await postJson("/v1/withdraw-auth", {
      client: client.publicKey.toBase58(),
      recipientAta: Keypair.generate().publicKey.toBase58(),
      amount: 500_000,
    });
    expect(withdrawAuthRes.status).to.equal(200);
    const withdrawAuthBody = await withdrawAuthRes.json();
    expect(withdrawAuthBody.ok).to.equal(true);
    expect(withdrawAuthBody.signature).to.be.a("string").and.not.equal("");
    expect(withdrawAuthBody.message).to.be.a("string").and.not.equal("");

    const receiptRes = await postJson("/v1/receipt", {
      client: client.publicKey.toBase58(),
      recipientAta: Keypair.generate().publicKey.toBase58(),
    });
    expect(receiptRes.status).to.equal(200);
    const receiptBody = await receiptRes.json();
    expect(receiptBody.ok).to.equal(true);
    expect(receiptBody.participant).to.equal(client.publicKey.toBase58());
    expect(receiptBody.freeBalance).to.equal(1_400_000);
    expect(receiptBody.lockedBalance).to.equal(0);
    expect(receiptBody.signature).to.be.a("string").and.not.equal("");
  });

  it("still rejects invalid and unknown requests", async () => {
    const invalidSchemeRes = await postJson("/v1/verify", {
      paymentPayload: {
        version: 1,
        scheme: "invalid-scheme",
        paymentId: "pay_test",
        client: Keypair.generate().publicKey.toBase58(),
        vault: attestation.vaultConfig,
        providerId: "prov_test",
        payTo: Keypair.generate().publicKey.toBase58(),
        network: "solana:localnet",
        assetMint: Keypair.generate().publicKey.toBase58(),
        amount: "1000000",
        requestHash: "0".repeat(64),
        paymentDetailsHash: "0".repeat(64),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        nonce: "123",
        clientSig: "",
      },
      requestContext: {
        method: "POST",
        origin: "http://localhost",
        pathAndQuery: "/test",
        bodySha256: "0".repeat(64),
      },
    });
    expect(invalidSchemeRes.status).to.equal(400);
    expect((await invalidSchemeRes.json()).error).to.equal("invalid_scheme");

    const unknownProviderRes = await postJson("/v1/verify", {
      paymentPayload: {
        version: 1,
        scheme: "a402-svm-v1",
        paymentId: "pay_unknown",
        client: Keypair.generate().publicKey.toBase58(),
        vault: attestation.vaultConfig,
        providerId: "prov_unknown",
        payTo: Keypair.generate().publicKey.toBase58(),
        network: "solana:localnet",
        assetMint: Keypair.generate().publicKey.toBase58(),
        amount: "1000000",
        requestHash: "0".repeat(64),
        paymentDetailsHash: "0".repeat(64),
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        nonce: "123",
        clientSig: "",
      },
      requestContext: {
        method: "POST",
        origin: "http://localhost",
        pathAndQuery: "/test",
        bodySha256: "0".repeat(64),
      },
    });
    expect(unknownProviderRes.status).to.equal(400);
    expect((await unknownProviderRes.json()).error).to.equal("provider_not_found");

    const settleRes = await postJson("/v1/settle", {
      verificationId: "ver_nonexistent",
      resultHash: "0".repeat(64),
      statusCode: 200,
    });
    expect(settleRes.status).to.equal(404);
    expect((await settleRes.json()).error).to.equal("reservation_not_found");

    const cancelRes = await postJson("/v1/cancel", {
      verificationId: "ver_nonexistent",
      reason: "test",
    });
    expect(cancelRes.status).to.equal(404);
    expect((await cancelRes.json()).error).to.equal("reservation_not_found");

    const withdrawRes = await postJson("/v1/withdraw-auth", {
      client: Keypair.generate().publicKey.toBase58(),
      recipientAta: Keypair.generate().publicKey.toBase58(),
      amount: 1000000,
    });
    expect(withdrawRes.status).to.equal(400);
    expect((await withdrawRes.json()).error).to.equal("client_not_found");
  });
});
