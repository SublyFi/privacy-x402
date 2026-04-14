import { expect } from "chai";
import { createHash, randomUUID } from "crypto";
import nacl from "tweetnacl";
import { Keypair } from "@solana/web3.js";
import {
  computePaymentDetailsHash,
  sha256hex,
} from "../sdk/src/crypto";
import { decodeVerificationReceiptEnvelope } from "../sdk/src/receipt";
import { requestJson, RequestTlsOptions, TestResponse } from "./live_transport";

/**
 * Enclave Facilitator API integration tests.
 *
 * Prerequisites: watchtower must be running on localhost:3200 and enclave must
 * be running on localhost:3100 with A402_WATCHTOWER_URL=http://127.0.0.1:3200
 * Run: cargo run -p a402-watchtower &
 * Then: A402_WATCHTOWER_URL=http://127.0.0.1:3200 cargo run -p a402-enclave &
 * Then: yarn run ts-mocha -p ./tsconfig.json -t 30000 tests/enclave_api.ts
 *
 * Optional HTTPS/mTLS:
 * - set A402_TEST_ENCLAVE_URL=https://127.0.0.1:3100
 * - set A402_TEST_TLS_CA_PATH to trust the enclave certificate
 * - set A402_TEST_MTLS_CERT_PATH / A402_TEST_MTLS_KEY_PATH for provider-authenticated calls
 */

const ENCLAVE_URL =
  process.env.A402_TEST_ENCLAVE_URL || "http://localhost:3100";
const SHARED_TLS: RequestTlsOptions | undefined = process.env.A402_TEST_TLS_CA_PATH
  ? {
      caPath: process.env.A402_TEST_TLS_CA_PATH,
      serverName: process.env.A402_TEST_TLS_SERVER_NAME,
    }
  : undefined;
const PROVIDER_MTLS: RequestTlsOptions | undefined =
  process.env.A402_TEST_MTLS_CERT_PATH && process.env.A402_TEST_MTLS_KEY_PATH
    ? {
        ...SHARED_TLS,
        certPath: process.env.A402_TEST_MTLS_CERT_PATH,
        keyPath: process.env.A402_TEST_MTLS_KEY_PATH,
      }
    : undefined;

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

type AttestationResponse = {
  vaultConfig: string;
  vaultSigner: string;
  attestationPolicyHash: string;
  issuedAt: string;
  expiresAt: string;
};

type VerifyResponse = {
  ok: boolean;
  verificationId: string;
  reservationId: string;
  reservationExpiresAt: string;
  providerId: string;
  amount: string;
  verificationReceipt: string;
};

type BalanceResponse = {
  free: number;
  locked: number;
};

type SettleResponse = {
  ok: boolean;
  settlementId: string;
  providerCreditAmount: string;
  participantReceipt: string;
};

type WithdrawAuthResponse = {
  ok: boolean;
  signature: string;
  message: string;
};

type ReceiptResponse = {
  ok: boolean;
  participant: string;
  participantKind: number;
  recipientAta: string;
  freeBalance: number;
  lockedBalance: number;
  maxLockExpiresAt: number;
  nonce: number;
  vaultConfig: string;
  message: string;
  signature: string;
};

type ErrorResponse = {
  error: string;
  message?: string;
};

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

  const signature = nacl.sign.detached(Buffer.from(message), client.secretKey);
  return Buffer.from(signature).toString("base64");
}

async function postJson(
  path: string,
  body: unknown,
  headers?: Record<string, string>,
  tls?: RequestTlsOptions
): Promise<TestResponse> {
  return requestJson(`${ENCLAVE_URL}${path}`, {
    method: "POST",
    body,
    headers,
    tls: tls ?? SHARED_TLS,
  });
}

async function getJson(path: string, tls?: RequestTlsOptions): Promise<TestResponse> {
  return requestJson(`${ENCLAVE_URL}${path}`, {
    method: "GET",
    tls: tls ?? SHARED_TLS,
  });
}

async function readJson<T>(response: TestResponse): Promise<T> {
  return response.json<T>();
}

describe("enclave_api", () => {
  let attestation: AttestationResponse;

  it("returns attestation document", async () => {
    const res = await getJson("/v1/attestation");
    expect(res.status).to.equal(200);

    attestation = await readJson<AttestationResponse>(res);
    expect(attestation.vaultConfig).to.be.a("string");
    expect(attestation.vaultSigner).to.be.a("string");
    expect(attestation.attestationPolicyHash).to.be.a("string");
    expect(attestation.issuedAt).to.be.a("string");
    expect(attestation.expiresAt).to.be.a("string");
  });

  it("runs a live verify -> balance -> settle -> withdraw-auth -> receipt flow", async () => {
    const client = Keypair.generate();
    const providerId = `prov_${randomUUID()}`;
    const providerApiKey = `provider-secret-${randomUUID()}`;
    const providerParticipant = Keypair.generate();
    const providerSettlementAccount = Keypair.generate().publicKey;
    const assetMint = Keypair.generate().publicKey;
    const paymentAmount = 600_000;

    const registerRes = await postJson("/v1/provider/register", {
      providerId,
      displayName: "Integration Test Provider",
      participantPubkey: providerParticipant.publicKey.toBase58(),
      settlementTokenAccount: providerSettlementAccount.toBase58(),
      network: "solana:localnet",
      assetMint: assetMint.toBase58(),
      allowedOrigins: ["http://localhost"],
      authMode: "bearer",
      apiKeyHash: sha256hex(providerApiKey),
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
      bodySha256: sha256hex(JSON.stringify({ hello: "world" })),
    };
    const paymentDetails = {
      scheme: "a402-svm-v1",
      network: "solana:localnet",
      amount: paymentAmount.toString(),
      asset: {
        kind: "spl-token",
        mint: assetMint.toBase58(),
        decimals: 6,
        symbol: "USDC",
      },
      payTo: providerSettlementAccount.toBase58(),
      providerId,
      facilitatorUrl: ENCLAVE_URL,
      vault: {
        config: attestation.vaultConfig,
        signer: attestation.vaultSigner,
        attestationPolicyHash: attestation.attestationPolicyHash,
      },
      paymentDetailsId: `paydet_test_${providerId}`,
      verifyWindowSec: 60,
      maxSettlementDelaySec: 900,
      privacyMode: "vault-batched-v1",
    } as const;
    const paymentDetailsHash = computePaymentDetailsHash(paymentDetails);
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

    const verifyRes = await postJson(
      "/v1/verify",
      {
        paymentPayload,
        paymentDetails,
        requestContext,
      },
      {
        Authorization: `Bearer ${providerApiKey}`,
        "x-a402-provider-id": providerId,
      },
      PROVIDER_MTLS ?? undefined
    );
    expect(verifyRes.status).to.equal(200);
    const verifyBody = await readJson<VerifyResponse>(verifyRes);
    expect(verifyBody.ok).to.equal(true);
    expect(verifyBody.providerId).to.equal(providerId);
    expect(verifyBody.amount).to.equal(paymentAmount.toString());
    expect(verifyBody.verificationReceipt).to.be.a("string").and.not.equal("");
    const verificationReceipt = decodeVerificationReceiptEnvelope(
      verifyBody.verificationReceipt
    );
    expect(verificationReceipt.verificationId).to.equal(
      verifyBody.verificationId
    );
    expect(verificationReceipt.reservationId).to.equal(verifyBody.reservationId);
    expect(verificationReceipt.paymentId).to.equal(paymentPayload.paymentId);
    expect(verificationReceipt.client).to.equal(client.publicKey.toBase58());
    expect(verificationReceipt.providerId).to.equal(providerId);
    expect(verificationReceipt.amount).to.equal(paymentAmount.toString());
    expect(verificationReceipt.requestHash).to.equal(requestHash);
    expect(verificationReceipt.paymentDetailsHash).to.equal(
      paymentDetailsHash
    );
    expect(verificationReceipt.reservationExpiresAt).to.equal(
      verifyBody.reservationExpiresAt
    );
    expect(verificationReceipt.vaultConfig).to.equal(attestation.vaultConfig);
    expect(verificationReceipt.signature).to.be.a("string").and.not.equal("");
    expect(verificationReceipt.message).to.be.a("string").and.not.equal("");

    const balanceAfterVerifyRes = await postJson("/v1/balance", {
      client: client.publicKey.toBase58(),
    });
    expect(balanceAfterVerifyRes.status).to.equal(200);
    const balanceAfterVerify = await readJson<BalanceResponse>(
      balanceAfterVerifyRes
    );
    expect(balanceAfterVerify.free).to.equal(1_400_000);
    expect(balanceAfterVerify.locked).to.equal(paymentAmount);

    const settleRes = await postJson(
      "/v1/settle",
      {
        verificationId: verifyBody.verificationId,
        resultHash: "ab".repeat(32),
        statusCode: 200,
      },
      {
        Authorization: `Bearer ${providerApiKey}`,
        "x-a402-provider-id": providerId,
      },
      PROVIDER_MTLS ?? undefined
    );
    expect(settleRes.status).to.equal(200);
    const settleBody = await readJson<SettleResponse>(settleRes);
    expect(settleBody.ok).to.equal(true);
    expect(settleBody.settlementId).to.match(/^set_/);
    expect(settleBody.providerCreditAmount).to.equal(paymentAmount.toString());
    expect(settleBody.participantReceipt).to.be.a("string").and.not.equal("");
    const providerReceipt = JSON.parse(
      Buffer.from(settleBody.participantReceipt, "base64").toString("utf-8")
    ) as ReceiptResponse;
    expect(providerReceipt.participant).to.equal(
      providerParticipant.publicKey.toBase58()
    );
    expect(providerReceipt.participantKind).to.equal(1);
    expect(providerReceipt.recipientAta).to.equal(
      providerSettlementAccount.toBase58()
    );
    expect(providerReceipt.freeBalance).to.equal(paymentAmount);
    expect(providerReceipt.lockedBalance).to.equal(0);

    const settleRetryRes = await postJson(
      "/v1/settle",
      {
        verificationId: verifyBody.verificationId,
        resultHash: "ab".repeat(32),
        statusCode: 200,
      },
      {
        Authorization: `Bearer ${providerApiKey}`,
        "x-a402-provider-id": providerId,
      },
      PROVIDER_MTLS ?? undefined
    );
    expect(settleRetryRes.status).to.equal(200);
    const settleRetryBody = await readJson<SettleResponse>(settleRetryRes);
    expect(settleRetryBody.settlementId).to.equal(settleBody.settlementId);

    const balanceAfterSettleRes = await postJson("/v1/balance", {
      client: client.publicKey.toBase58(),
    });
    expect(balanceAfterSettleRes.status).to.equal(200);
    const balanceAfterSettle = await readJson<BalanceResponse>(
      balanceAfterSettleRes
    );
    expect(balanceAfterSettle.free).to.equal(1_400_000);
    expect(balanceAfterSettle.locked).to.equal(0);

    const withdrawAuthRes = await postJson("/v1/withdraw-auth", {
      client: client.publicKey.toBase58(),
      recipientAta: Keypair.generate().publicKey.toBase58(),
      amount: 500_000,
    });
    expect(withdrawAuthRes.status).to.equal(200);
    const withdrawAuthBody = await readJson<WithdrawAuthResponse>(
      withdrawAuthRes
    );
    expect(withdrawAuthBody.ok).to.equal(true);
    expect(withdrawAuthBody.signature).to.be.a("string").and.not.equal("");
    expect(withdrawAuthBody.message).to.be.a("string").and.not.equal("");

    const receiptRes = await postJson("/v1/receipt", {
      client: client.publicKey.toBase58(),
      recipientAta: Keypair.generate().publicKey.toBase58(),
    });
    expect(receiptRes.status).to.equal(200);
    const receiptBody = await readJson<ReceiptResponse>(receiptRes);
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
      paymentDetails: {
        scheme: "invalid-scheme",
      },
      requestContext: {
        method: "POST",
        origin: "http://localhost",
        pathAndQuery: "/test",
        bodySha256: "0".repeat(64),
      },
    });
    expect(invalidSchemeRes.status).to.equal(400);
    expect((await readJson<ErrorResponse>(invalidSchemeRes)).error).to.equal(
      "invalid_scheme"
    );

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
      paymentDetails: {
        scheme: "a402-svm-v1",
      },
      requestContext: {
        method: "POST",
        origin: "http://localhost",
        pathAndQuery: "/test",
        bodySha256: "0".repeat(64),
      },
    });
    expect(unknownProviderRes.status).to.equal(400);
    expect((await readJson<ErrorResponse>(unknownProviderRes)).error).to.equal(
      "provider_not_found"
    );

    const settleRes = await postJson("/v1/settle", {
      verificationId: "ver_nonexistent",
      resultHash: "0".repeat(64),
      statusCode: 200,
    });
    expect(settleRes.status).to.equal(404);
    expect((await readJson<ErrorResponse>(settleRes)).error).to.equal(
      "reservation_not_found"
    );

    const cancelRes = await postJson("/v1/cancel", {
      verificationId: "ver_nonexistent",
      reason: "test",
    });
    expect(cancelRes.status).to.equal(404);
    expect((await readJson<ErrorResponse>(cancelRes)).error).to.equal(
      "reservation_not_found"
    );

    const withdrawRes = await postJson("/v1/withdraw-auth", {
      client: Keypair.generate().publicKey.toBase58(),
      recipientAta: Keypair.generate().publicKey.toBase58(),
      amount: 1000000,
    });
    expect(withdrawRes.status).to.equal(400);
    expect((await readJson<ErrorResponse>(withdrawRes)).error).to.equal(
      "client_not_found"
    );
  });
});
