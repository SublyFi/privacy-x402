#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nacl = require("tweetnacl");

const anchor = require("@coral-xyz/anchor");
const {
  createAccount,
  getAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} = require("@solana/spl-token");
const { Keypair, PublicKey } = require("@solana/web3.js");

const {
  computePaymentDetailsHash,
  computeRequestHash,
  fundAccount,
  loadProgram,
  loadProvider,
  postJson,
  sha256hex,
  signPaymentPayload,
  waitForEndpoint,
} = require("../devnet/common");

const ROOT = path.resolve(__dirname, "..", "..");

function expandEnv(value) {
  return value.replace(
    /\$([A-Z_][A-Z0-9_]*)/g,
    (_match, name) => process.env[name] || ""
  );
}

function parseEnvAssignment(rawValue) {
  const value = rawValue.trim();
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    const quote = value[0];
    const unquoted = value.slice(1, -1);
    return quote === '"' ? expandEnv(unquoted) : unquoted;
  }
  return expandEnv(value);
}

function loadEnvFile(filePath, { required = false } = {}) {
  if (!fs.existsSync(filePath)) {
    if (required) {
      throw new Error(`env file is missing: ${filePath}`);
    }
    return false;
  }
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^export\s+([A-Z0-9_]+)=(.*)$/);
    if (!match) {
      continue;
    }
    const [, key, rawValue] = match;
    process.env[key] = parseEnvAssignment(rawValue);
  }
  return true;
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

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

function loadNitroEnv() {
  loadEnvFile(path.join(ROOT, ".env.devnet.local"));

  const clientEnv =
    process.env.A402_NITRO_CLIENT_ENV ||
    path.join(ROOT, "infra", "nitro", "generated", "client.env");
  loadEnvFile(clientEnv, { required: true });

  const providerEnv =
    process.env.A402_DEMO_PROVIDERS_ENV || "/root/a402-demo-providers.env";
  loadEnvFile(providerEnv, { required: true });
}

function loadDemoProviders() {
  const providers = [1, 2].map((index) => ({
    index,
    id: process.env[`A402_DEMO_PROVIDER_${index}_ID`],
    tokenAccount: process.env[`A402_DEMO_PROVIDER_${index}_TOKEN_ACCOUNT`],
    apiKey: process.env[`A402_DEMO_PROVIDER_${index}_API_KEY`],
  }));

  for (const provider of providers) {
    if (!provider.id || !provider.tokenAccount || !provider.apiKey) {
      throw new Error(
        `A402_DEMO_PROVIDER_${provider.index}_{ID,TOKEN_ACCOUNT,API_KEY} are required`
      );
    }
  }
  return providers;
}

async function fetchJson(baseUrl, route) {
  const response = await fetch(`${baseUrl}${route}`);
  if (!response.ok) {
    throw new Error(
      `${route} failed: ${response.status} ${await response.text()}`
    );
  }
  return response.json();
}

async function assertFinalRoutes(enclaveUrl) {
  const registerRes = await fetch(`${enclaveUrl}/v1/provider/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  if (registerRes.status !== 404) {
    throw new Error(
      `expected final EIF to return 404 for /v1/provider/register, got ${registerRes.status}`
    );
  }

  const adminRes = await fetch(`${enclaveUrl}/v1/admin/fire-batch`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  if (adminRes.status !== 404) {
    throw new Error(
      `expected final EIF to return 404 for /v1/admin/fire-batch, got ${adminRes.status}`
    );
  }
}

async function postOrThrow(enclaveUrl, route, body, headers) {
  const response = await postJson(enclaveUrl, route, body, headers);
  if (!response.ok) {
    throw new Error(
      `${route} failed: ${response.status} ${await response.text()}`
    );
  }
  return response.json();
}

function buildPayment({
  attestation,
  client,
  enclaveUrl,
  provider,
  requestOrigin,
  network,
  usdcMint,
  vaultConfig,
  paymentAmount,
  nonce,
}) {
  const requestContext = {
    method: "POST",
    origin: requestOrigin,
    pathAndQuery: `/nitro-e2e/provider-${provider.index}`,
    bodySha256: sha256hex(JSON.stringify({ provider: provider.index })),
  };
  const paymentDetails = {
    scheme: "a402-svm-v1",
    network,
    amount: paymentAmount.toString(),
    asset: {
      kind: "spl-token",
      mint: usdcMint,
      decimals: 6,
      symbol: "USDC",
    },
    payTo: provider.tokenAccount,
    providerId: provider.id,
    facilitatorUrl: enclaveUrl,
    vault: {
      config: vaultConfig,
      signer: attestation.vaultSigner,
      attestationPolicyHash: attestation.attestationPolicyHash,
    },
    paymentDetailsId: `paydet_${provider.id}_${crypto.randomUUID()}`,
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
    vault: vaultConfig,
    providerId: provider.id,
    payTo: provider.tokenAccount,
    network,
    assetMint: usdcMint,
    amount: paymentAmount.toString(),
    requestHash,
    paymentDetailsHash,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    nonce: nonce.toString(),
  };

  return {
    requestContext,
    paymentDetails,
    paymentPayload: {
      ...unsignedPayload,
      clientSig: signPaymentPayload(client, unsignedPayload),
    },
  };
}

async function main() {
  loadNitroEnv();

  if (process.env.A402_NITRO_ALLOW_SELF_SIGNED_TLS !== "0") {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

  const enclaveUrl = requireEnv("A402_PUBLIC_ENCLAVE_URL").replace(/\/$/, "");
  const vaultConfig = requireEnv("A402_VAULT_CONFIG");
  const vaultTokenAccount = requireEnv("A402_VAULT_TOKEN_ACCOUNT");
  const usdcMint = requireEnv("A402_USDC_MINT");
  const expectedPolicyHash = requireEnv("A402_ATTESTATION_POLICY_HASH_HEX");
  const requestOrigin =
    process.env.A402_REQUEST_ORIGIN || "http://localhost:3000";
  const network = process.env.A402_NETWORK || "solana:devnet";
  const depositAmount = Number(
    process.env.A402_NITRO_E2E_DEPOSIT_AMOUNT || "3000000"
  );
  const paymentAmount = Number(
    process.env.A402_NITRO_E2E_PAYMENT_AMOUNT || "1100000"
  );
  const providerSolLamports = Number(
    process.env.A402_NITRO_E2E_CLIENT_SOL_LAMPORTS || "50000000"
  );
  const providers = loadDemoProviders();

  if (depositAmount < paymentAmount * providers.length) {
    throw new Error("deposit amount must cover all provider payment amounts");
  }

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);

  const plan = {
    cluster: process.env.ANCHOR_PROVIDER_URL || process.env.A402_SOLANA_RPC_URL,
    feePayer: provider.wallet.publicKey.toBase58(),
    enclaveUrl,
    vaultConfig,
    vaultTokenAccount,
    usdcMint,
    expectedPolicyHash,
    depositAmount,
    paymentAmountPerProvider: paymentAmount,
    providers: providers.map(({ id, tokenAccount }) => ({ id, tokenAccount })),
  };

  if (process.env.A402_NITRO_E2E_CONFIRM !== "1") {
    console.log(
      JSON.stringify(
        {
          ok: false,
          dryRun: true,
          message: "Set A402_NITRO_E2E_CONFIRM=1 to send devnet transactions.",
          plan,
        },
        null,
        2
      )
    );
    return;
  }

  const attestation = await fetchJson(enclaveUrl, "/v1/attestation");
  if (attestation.vaultConfig !== vaultConfig) {
    throw new Error("attestation vaultConfig mismatch");
  }
  if (
    attestation.attestationPolicyHash.toLowerCase() !==
    expectedPolicyHash.toLowerCase()
  ) {
    throw new Error("attestation policy hash mismatch");
  }

  await assertFinalRoutes(enclaveUrl);

  const providerTokenBefore = [];
  for (const demoProvider of providers) {
    const account = await getAccount(
      provider.connection,
      new PublicKey(demoProvider.tokenAccount)
    );
    providerTokenBefore.push(BigInt(account.amount.toString()));
  }

  const client = Keypair.generate();
  const clientTokenAccount = await createAccount(
    provider.connection,
    provider.wallet.payer,
    new PublicKey(usdcMint),
    client.publicKey
  );

  await fundAccount(provider, client.publicKey, providerSolLamports);
  await mintTo(
    provider.connection,
    provider.wallet.payer,
    new PublicKey(usdcMint),
    clientTokenAccount,
    provider.wallet.publicKey,
    depositAmount
  );

  const depositSig = await program.methods
    .deposit(new anchor.BN(depositAmount))
    .accountsPartial({
      client: client.publicKey,
      vaultConfig: new PublicKey(vaultConfig),
      clientTokenAccount,
      vaultTokenAccount: new PublicKey(vaultTokenAccount),
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .signers([client])
    .rpc();

  const depositedBalance = await waitForEndpoint(
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
      return body.free === depositAmount ? body : null;
    },
    120,
    1000
  );

  const settlements = [];
  for (let index = 0; index < providers.length; index += 1) {
    const demoProvider = providers[index];
    const built = buildPayment({
      attestation,
      client,
      enclaveUrl,
      provider: demoProvider,
      requestOrigin,
      network,
      usdcMint,
      vaultConfig,
      paymentAmount,
      nonce: index + 1,
    });
    const providerHeaders = {
      Authorization: `Bearer ${demoProvider.apiKey}`,
      "x-a402-provider-id": demoProvider.id,
    };

    const verifyBody = await postOrThrow(
      enclaveUrl,
      "/v1/verify",
      {
        paymentPayload: built.paymentPayload,
        paymentDetails: built.paymentDetails,
        requestContext: built.requestContext,
      },
      providerHeaders
    );
    const settleBody = await postOrThrow(
      enclaveUrl,
      "/v1/settle",
      {
        verificationId: verifyBody.verificationId,
        resultHash: sha256hex(`nitro-e2e-${demoProvider.id}`),
        statusCode: 200,
      },
      providerHeaders
    );
    settlements.push({ providerId: demoProvider.id, verifyBody, settleBody });
  }

  const providerTokenAfter = await waitForEndpoint(
    "automatic batch settlement",
    async () => {
      const balances = [];
      for (let index = 0; index < providers.length; index += 1) {
        const account = await getAccount(
          provider.connection,
          new PublicKey(providers[index].tokenAccount)
        );
        balances.push(BigInt(account.amount.toString()));
      }
      const allSettled = balances.every((balance, index) => {
        return balance >= providerTokenBefore[index] + BigInt(paymentAmount);
      });
      return allSettled ? balances : null;
    },
    18,
    5000
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
        plan,
        attestation: {
          vaultConfig: attestation.vaultConfig,
          vaultSigner: attestation.vaultSigner,
          attestationPolicyHash: attestation.attestationPolicyHash,
          snapshotSeqno: attestation.snapshotSeqno,
        },
        client: client.publicKey.toBase58(),
        clientTokenAccount: clientTokenAccount.toBase58(),
        depositSig,
        depositedBalance,
        settlements,
        providerTokenBefore: providerTokenBefore.map((value) =>
          value.toString()
        ),
        providerTokenAfter: providerTokenAfter.map((value) => value.toString()),
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
