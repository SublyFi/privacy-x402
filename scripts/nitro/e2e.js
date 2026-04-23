#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nacl = require("tweetnacl");

const anchor = require("@coral-xyz/anchor");
const {
  createAccount,
  getAccount,
  getMint,
  mintTo,
  TOKEN_PROGRAM_ID,
  transfer,
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

function readPositiveIntEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

function loadKeypairFromFile(filePath) {
  const secretKey = Uint8Array.from(
    JSON.parse(fs.readFileSync(filePath, "utf8"))
  );
  return Keypair.fromSecretKey(secretKey);
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
    process.env.SUBLY402_NITRO_CLIENT_ENV ||
    path.join(ROOT, "infra", "nitro", "generated", "client.env");
  loadEnvFile(clientEnv, { required: true });

  const providerEnv =
    process.env.SUBLY402_DEMO_PROVIDERS_ENV ||
    "/root/subly402-demo-providers.env";
  loadEnvFile(providerEnv, { required: true });
}

function loadDemoProviders() {
  const providers = [1, 2].map((index) => ({
    index,
    id: process.env[`SUBLY402_DEMO_PROVIDER_${index}_ID`],
    tokenAccount: process.env[`SUBLY402_DEMO_PROVIDER_${index}_TOKEN_ACCOUNT`],
    apiKey: process.env[`SUBLY402_DEMO_PROVIDER_${index}_API_KEY`],
  }));

  for (const provider of providers) {
    if (!provider.id || !provider.tokenAccount || !provider.apiKey) {
      throw new Error(
        `SUBLY402_DEMO_PROVIDER_${provider.index}_{ID,TOKEN_ACCOUNT,API_KEY} are required`
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
    scheme: "subly402-svm-v1",
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
    scheme: "subly402-svm-v1",
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

function loadMintAuthority(provider, mintAuthority) {
  if (mintAuthority === null) {
    return null;
  }
  const walletPath = process.env.SUBLY402_USDC_MINT_AUTHORITY_WALLET;
  if (walletPath) {
    return loadKeypairFromFile(walletPath);
  }
  if (mintAuthority.equals(provider.wallet.publicKey)) {
    return provider.wallet.payer;
  }
  return null;
}

async function main() {
  loadNitroEnv();

  if (process.env.SUBLY402_NITRO_ALLOW_SELF_SIGNED_TLS !== "0") {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

  const enclaveUrl = requireEnv("SUBLY402_PUBLIC_ENCLAVE_URL").replace(
    /\/$/,
    ""
  );
  const vaultConfig = requireEnv("SUBLY402_VAULT_CONFIG");
  const vaultTokenAccount = requireEnv("SUBLY402_VAULT_TOKEN_ACCOUNT");
  const usdcMint = requireEnv("SUBLY402_USDC_MINT");
  const expectedPolicyHash = requireEnv("SUBLY402_ATTESTATION_POLICY_HASH_HEX");
  const requestOrigin =
    process.env.SUBLY402_REQUEST_ORIGIN || "http://localhost:3000";
  const network = process.env.SUBLY402_NETWORK || "solana:devnet";
  const depositAmount = Number(
    process.env.SUBLY402_NITRO_E2E_DEPOSIT_AMOUNT || "3000000"
  );
  const paymentAmount = Number(
    process.env.SUBLY402_NITRO_E2E_PAYMENT_AMOUNT || "1100000"
  );
  const providerSolLamports = Number(
    process.env.SUBLY402_NITRO_E2E_CLIENT_SOL_LAMPORTS || "50000000"
  );
  const batchWaitAttempts = readPositiveIntEnv(
    "SUBLY402_NITRO_E2E_BATCH_WAIT_ATTEMPTS",
    48
  );
  const batchWaitDelayMs = readPositiveIntEnv(
    "SUBLY402_NITRO_E2E_BATCH_WAIT_DELAY_MS",
    5000
  );
  const providers = loadDemoProviders();

  if (depositAmount < paymentAmount * providers.length) {
    throw new Error("deposit amount must cover all provider payment amounts");
  }

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);
  const mint = await getMint(provider.connection, new PublicKey(usdcMint));
  const mintAuthority = loadMintAuthority(provider, mint.mintAuthority);

  const plan = {
    cluster:
      process.env.ANCHOR_PROVIDER_URL || process.env.SUBLY402_SOLANA_RPC_URL,
    feePayer: provider.wallet.publicKey.toBase58(),
    enclaveUrl,
    vaultConfig,
    vaultTokenAccount,
    usdcMint,
    expectedPolicyHash,
    depositAmount,
    paymentAmountPerProvider: paymentAmount,
    providers: providers.map(({ id, tokenAccount }) => ({ id, tokenAccount })),
    mintAuthority: mint.mintAuthority?.toBase58() ?? "disabled",
    mintAuthorityWallet:
      process.env.SUBLY402_USDC_MINT_AUTHORITY_WALLET || null,
    sourceTokenAccount:
      process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT || null,
    batchWaitAttempts,
    batchWaitDelayMs,
  };

  if (process.env.SUBLY402_NITRO_E2E_CONFIRM !== "1") {
    console.log(
      JSON.stringify(
        {
          ok: false,
          dryRun: true,
          message:
            "Set SUBLY402_NITRO_E2E_CONFIRM=1 to send devnet transactions.",
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
  if (mintAuthority) {
    await mintTo(
      provider.connection,
      provider.wallet.payer,
      new PublicKey(usdcMint),
      clientTokenAccount,
      mintAuthority,
      depositAmount
    );
  } else if (process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT) {
    const sourceOwner = process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_OWNER_WALLET
      ? loadKeypairFromFile(
          process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_OWNER_WALLET
        )
      : provider.wallet.payer;
    await transfer(
      provider.connection,
      provider.wallet.payer,
      new PublicKey(process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT),
      clientTokenAccount,
      sourceOwner,
      depositAmount
    );
  } else {
    throw new Error(
      `USDC mint authority is ${
        mint.mintAuthority?.toBase58() ?? "disabled"
      }, not fee payer ${provider.wallet.publicKey.toBase58()}. Set SUBLY402_USDC_MINT_AUTHORITY_WALLET to the mint authority keypair, or set SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT to a funded token account.`
    );
  }

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
          `SUBLY402-CLIENT-BALANCE\n${client.publicKey.toBase58()}\n${issuedAt}\n${expiresAt}\n`
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
      "x-subly402-provider-id": demoProvider.id,
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

  let providerTokenAfter;
  try {
    providerTokenAfter = await waitForEndpoint(
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
      batchWaitAttempts,
      batchWaitDelayMs
    );
  } catch (error) {
    const providerTokenCurrent = [];
    for (let index = 0; index < providers.length; index += 1) {
      const account = await getAccount(
        provider.connection,
        new PublicKey(providers[index].tokenAccount)
      );
      providerTokenCurrent.push(account.amount.toString());
    }

    const settlementStatuses = [];
    for (const settlement of settlements) {
      const demoProvider = providers.find(
        (item) => item.id === settlement.providerId
      );
      const response = await postJson(
        enclaveUrl,
        "/v1/settlement/status",
        {
          settlementId: settlement.settleBody.settlementId,
        },
        {
          Authorization: `Bearer ${demoProvider.apiKey}`,
          "x-subly402-provider-id": demoProvider.id,
        }
      );
      settlementStatuses.push({
        providerId: settlement.providerId,
        settlementId: settlement.settleBody.settlementId,
        httpStatus: response.status,
        body: await response.text(),
      });
    }

    throw new Error(
      `Timed out waiting for automatic batch settlement: ${JSON.stringify(
        {
          message: error.message,
          providerTokenBefore: providerTokenBefore.map((value) =>
            value.toString()
          ),
          providerTokenCurrent,
          settlementStatuses,
        },
        null,
        2
      )}`
    );
  }

  const finalBalanceAuth = buildClientRequestAuth(
    client,
    (issuedAt, expiresAt) =>
      `SUBLY402-CLIENT-BALANCE\n${client.publicKey.toBase58()}\n${issuedAt}\n${expiresAt}\n`
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
