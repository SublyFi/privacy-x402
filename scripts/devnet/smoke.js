#!/usr/bin/env node

const crypto = require("crypto");
const nacl = require("tweetnacl");

const anchor = require("@coral-xyz/anchor");
const {
  createAccount,
  getAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} = require("@solana/spl-token");
const { Keypair } = require("@solana/web3.js");

const {
  computePaymentDetailsHash,
  computeRequestHash,
  fundAccount,
  getJson,
  loadDefaultEnvFiles,
  loadProgram,
  loadProvider,
  loadState,
  postJson,
  sha256hex,
  signPaymentPayload,
  waitForEndpoint,
} = require("./common");

function signClientTextRequest(client, message) {
  return Buffer.from(
    nacl.sign.detached(Buffer.from(message), client.secretKey)
  ).toString("base64");
}

function buildClientRequestAuth(client, buildMessage) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + 300;
  return {
    issuedAt,
    expiresAt,
    clientSig: signClientTextRequest(client, buildMessage(issuedAt, expiresAt)),
  };
}

async function main() {
  loadDefaultEnvFiles();

  const state = loadState();
  if (!state) {
    throw new Error("data/devnet-state.json is missing. Run bootstrap first.");
  }

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);
  const enclaveUrl =
    process.env.A402_TEST_ENCLAVE_URL || "http://127.0.0.1:3100";
  const requestOrigin = process.env.A402_REQUEST_ORIGIN || "http://127.0.0.1";
  const network = process.env.A402_NETWORK || "solana:devnet";
  const depositAmount = Number(
    process.env.A402_SMOKE_DEPOSIT_AMOUNT || "2000000"
  );
  const paymentAmount = Number(
    process.env.A402_SMOKE_PAYMENT_AMOUNT || "600000"
  );

  const attestationRes = await getJson(enclaveUrl, "/v1/attestation");
  if (!attestationRes.ok) {
    throw new Error(`attestation failed: ${attestationRes.status}`);
  }
  const attestation = await attestationRes.json();

  const client = Keypair.generate();
  const providerOwner = Keypair.generate();
  const providerTokenAccount = await createAccount(
    provider.connection,
    provider.wallet.payer,
    new anchor.web3.PublicKey(state.usdcMint),
    providerOwner.publicKey
  );
  const clientTokenAccount = await createAccount(
    provider.connection,
    provider.wallet.payer,
    new anchor.web3.PublicKey(state.usdcMint),
    client.publicKey
  );

  await fundAccount(provider, client.publicKey, 50_000_000);
  await mintTo(
    provider.connection,
    provider.wallet.payer,
    new anchor.web3.PublicKey(state.usdcMint),
    clientTokenAccount,
    provider.wallet.publicKey,
    depositAmount
  );

  await program.methods
    .deposit(new anchor.BN(depositAmount))
    .accountsPartial({
      client: client.publicKey,
      vaultConfig: new anchor.web3.PublicKey(state.vaultConfig),
      clientTokenAccount,
      vaultTokenAccount: new anchor.web3.PublicKey(state.vaultTokenAccount),
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .signers([client])
    .rpc();

  const balance = await waitForEndpoint(
    "client balance sync",
    async () => {
      const auth = buildClientRequestAuth(
        client,
        (issuedAt, expiresAt) =>
          `A402-CLIENT-BALANCE\n${client.publicKey.toBase58()}\n${issuedAt}\n${expiresAt}\n`
      );
      const response = await postJson(enclaveUrl, "/v1/balance", {
        client: client.publicKey.toBase58(),
        issuedAt: auth.issuedAt,
        expiresAt: auth.expiresAt,
        clientSig: auth.clientSig,
      });
      if (!response.ok) {
        return null;
      }
      const body = await response.json();
      if (body.free === depositAmount) {
        return body;
      }
      return null;
    },
    120,
    1000
  );

  const providerId = `prov_${crypto.randomUUID()}`;
  const providerApiKey = `provider-secret-${crypto.randomUUID()}`;
  const registerRes = await postJson(enclaveUrl, "/v1/provider/register", {
    providerId,
    displayName: "Devnet Smoke Provider",
    participantPubkey: providerOwner.publicKey.toBase58(),
    settlementTokenAccount: providerTokenAccount.toBase58(),
    network,
    assetMint: state.usdcMint,
    allowedOrigins: [requestOrigin],
    authMode: "bearer",
    apiKeyHash: sha256hex(providerApiKey),
  });
  if (!registerRes.ok) {
    throw new Error(
      `provider/register failed: ${
        registerRes.status
      } ${await registerRes.text()} (start enclave with A402_ENABLE_PROVIDER_REGISTRATION_API=1)`
    );
  }

  const requestContext = {
    method: "POST",
    origin: requestOrigin,
    pathAndQuery: "/devnet-smoke",
    bodySha256: sha256hex(JSON.stringify({ ok: true })),
  };
  const paymentDetails = {
    scheme: "a402-svm-v1",
    network,
    amount: paymentAmount.toString(),
    asset: {
      kind: "spl-token",
      mint: state.usdcMint,
      decimals: 6,
      symbol: "USDC",
    },
    payTo: providerTokenAccount.toBase58(),
    providerId,
    facilitatorUrl: enclaveUrl,
    vault: {
      config: state.vaultConfig,
      signer: attestation.vaultSigner,
      attestationPolicyHash: attestation.attestationPolicyHash,
    },
    paymentDetailsId: `paydet_${providerId}`,
    verifyWindowSec: 60,
    maxSettlementDelaySec: 900,
    privacyMode: "vault-batched-v1",
  };
  const paymentDetailsHash = computePaymentDetailsHash(paymentDetails);
  const requestHash = computeRequestHash(requestContext, paymentDetailsHash);
  const unsignedPayload = {
    version: 1,
    scheme: "a402-svm-v1",
    paymentId: `pay_${crypto.randomUUID()}`,
    client: client.publicKey.toBase58(),
    vault: state.vaultConfig,
    providerId,
    payTo: providerTokenAccount.toBase58(),
    network,
    assetMint: state.usdcMint,
    amount: paymentAmount.toString(),
    requestHash,
    paymentDetailsHash,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    nonce: "1",
  };
  const paymentPayload = {
    ...unsignedPayload,
    clientSig: signPaymentPayload(client, unsignedPayload),
  };
  const providerHeaders = {
    Authorization: `Bearer ${providerApiKey}`,
    "x-a402-provider-id": providerId,
  };

  const verifyRes = await postJson(
    enclaveUrl,
    "/v1/verify",
    {
      paymentPayload,
      paymentDetails,
      requestContext,
    },
    providerHeaders
  );
  if (!verifyRes.ok) {
    throw new Error(
      `verify failed: ${verifyRes.status} ${await verifyRes.text()}`
    );
  }
  const verifyBody = await verifyRes.json();

  const settleRes = await postJson(
    enclaveUrl,
    "/v1/settle",
    {
      verificationId: verifyBody.verificationId,
      resultHash: "ab".repeat(32),
      statusCode: 200,
    },
    providerHeaders
  );
  if (!settleRes.ok) {
    throw new Error(
      `settle failed: ${settleRes.status} ${await settleRes.text()}`
    );
  }
  const settleBody = await settleRes.json();

  const fireBatchRes = await postJson(enclaveUrl, "/v1/admin/fire-batch", {});
  if (!fireBatchRes.ok) {
    throw new Error(
      `fire-batch failed: ${
        fireBatchRes.status
      } ${await fireBatchRes.text()} (start enclave with A402_ENABLE_ADMIN_API=1)`
    );
  }
  const fireBatchBody = await fireBatchRes.json();

  const providerToken = await getAccount(
    provider.connection,
    providerTokenAccount
  );
  const finalBalanceAuth = buildClientRequestAuth(
    client,
    (issuedAt, expiresAt) =>
      `A402-CLIENT-BALANCE\n${client.publicKey.toBase58()}\n${issuedAt}\n${expiresAt}\n`
  );
  const finalBalanceRes = await postJson(enclaveUrl, "/v1/balance", {
    client: client.publicKey.toBase58(),
    issuedAt: finalBalanceAuth.issuedAt,
    expiresAt: finalBalanceAuth.expiresAt,
    clientSig: finalBalanceAuth.clientSig,
  });
  const finalBalance = finalBalanceRes.ok ? await finalBalanceRes.json() : null;

  console.log(
    JSON.stringify(
      {
        ok: true,
        deposited: balance,
        verify: verifyBody,
        settle: settleBody,
        fireBatch: fireBatchBody,
        providerTokenAmount: Number(providerToken.amount),
        finalBalance,
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
