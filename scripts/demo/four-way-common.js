const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { AccountRole, address, signBytes } = require("@solana/kit");
const {
  findAssociatedTokenPda,
  TOKEN_PROGRAM_ADDRESS,
} = require("@solana-program/token");

const {
  createAssociatedTokenAccount,
  createDemoRpc,
  createDemoSigner,
  fetchTokenAmount,
  fundAddressWithSol,
  loadFeePayerSigner,
  loadMintAuthoritySigner,
  loadSignerFromFile,
  mintTokens,
  rpcUrlFromEnv,
  sendKitInstructions,
  transferTokens,
} = require("./solana-kit");

const ROOT = path.resolve(__dirname, "..", "..");
const DEFAULT_X402_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const DEFAULT_X402_FACILITATOR_URL = "https://x402.org/facilitator";
const DEFAULT_SUBLY_NETWORK = "solana:devnet";
const DEMO_ROUTE_PATH = "/weather";
const DEMO_METHOD = "GET";
const DEMO_DESCRIPTION = "Weather data";
const DEMO_MIME_TYPE = "application/json";

const DEPOSIT_DISCRIMINATOR = crypto
  .createHash("sha256")
  .update("global:deposit")
  .digest()
  .subarray(0, 8);

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

function loadEnvFile(
  filePath,
  protectedKeys = new Set(Object.keys(process.env))
) {
  if (!fs.existsSync(filePath)) {
    return false;
  }
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^(?:export\s+)?([A-Z0-9_]+)=(.*)$/);
    if (!match) {
      continue;
    }
    const [, key, rawValue] = match;
    if (!protectedKeys.has(key)) {
      process.env[key] = parseEnvAssignment(rawValue);
    }
  }
  return true;
}

function aliasEnv(from, to) {
  if (!process.env[to] && process.env[from]) {
    process.env[to] = process.env[from];
  }
}

function loadFourWayDemoEnv() {
  const protectedKeys = new Set(Object.keys(process.env));
  loadEnvFile(path.join(ROOT, ".env.devnet.local"), protectedKeys);
  loadEnvFile(path.join(ROOT, ".env.devnet.generated"), protectedKeys);
  loadEnvFile(
    path.join(ROOT, "infra", "nitro", "generated", "client.env"),
    protectedKeys
  );

  aliasEnv("A402_PROGRAM_ID", "SUBLY402_PROGRAM_ID");
  aliasEnv("A402_VAULT_CONFIG", "SUBLY402_VAULT_CONFIG");
  aliasEnv("A402_VAULT_TOKEN_ACCOUNT", "SUBLY402_VAULT_TOKEN_ACCOUNT");
  aliasEnv("A402_USDC_MINT", "SUBLY402_USDC_MINT");
  aliasEnv(
    "A402_ATTESTATION_POLICY_HASH_HEX",
    "SUBLY402_ATTESTATION_POLICY_HASH_HEX"
  );
  aliasEnv("A402_PUBLIC_ENCLAVE_URL", "SUBLY402_PUBLIC_ENCLAVE_URL");

  if (
    process.env.SUBLY402_NITRO_ALLOW_SELF_SIGNED_TLS === "1" ||
    process.env.SUBLY402_ALLOW_SELF_SIGNED_TLS === "1"
  ) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }
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

function demoPaymentAmount() {
  return readPositiveIntEnv(
    "SUBLY402_DEMO_PAYMENT_AMOUNT",
    readPositiveIntEnv("SUBLY402_NITRO_E2E_PAYMENT_AMOUNT", 1100000)
  );
}

function demoDepositAmount() {
  return readPositiveIntEnv(
    "SUBLY402_DEMO_DEPOSIT_AMOUNT",
    readPositiveIntEnv("SUBLY402_NITRO_E2E_DEPOSIT_AMOUNT", demoPaymentAmount())
  );
}

function demoClientSolLamports() {
  return readPositiveIntEnv(
    "SUBLY402_DEMO_CLIENT_SOL_LAMPORTS",
    readPositiveIntEnv("SUBLY402_NITRO_E2E_CLIENT_SOL_LAMPORTS", 50000000)
  );
}

function formatUsdcAtomic(value) {
  const atomic = BigInt(value.toString());
  const whole = atomic / 1000000n;
  const fraction = (atomic % 1000000n).toString().padStart(6, "0");
  return `${whole}.${fraction} USDC`;
}

function shortKey(value) {
  const text = String(value || "");
  if (text.length <= 12) {
    return text || "n/a";
  }
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
}

function printHeader(title) {
  console.log("");
  console.log("=".repeat(72));
  console.log(title);
  console.log("=".repeat(72));
}

function logKV(label, value) {
  console.log(`    ${label}: ${value}`);
}

function encodeJsonHeader(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

function decodeJsonHeader(value) {
  return JSON.parse(Buffer.from(value, "base64").toString("utf8"));
}

function paymentResponseFromHeaders(headers) {
  const raw =
    headers.get("PAYMENT-RESPONSE") || headers.get("payment-response") || "";
  return raw ? decodeJsonHeader(raw) : null;
}

function paymentRequiredFromResponse(response) {
  const raw =
    response.headers.get("PAYMENT-REQUIRED") ||
    response.headers.get("payment-required") ||
    "";
  return raw ? decodeJsonHeader(raw) : null;
}

function demoWeatherResponse({ mode, providerId }) {
  return {
    ok: true,
    report: {
      weather: "sunny",
      temperature: 70,
    },
    providerId,
    settlementMode: mode,
  };
}

async function deriveTokenAccount(owner, mint) {
  const [ata] = await findAssociatedTokenPda({
    mint: address(mint),
    owner: address(owner),
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
  });
  return ata.toString();
}

async function ensureAssociatedTokenAccount(rpc, feePayer, owner, mint) {
  return (
    await createAssociatedTokenAccount(rpc, feePayer, owner, mint)
  ).toString();
}

async function fetchTokenAmountOrNull(rpc, tokenAccount) {
  try {
    return await fetchTokenAmount(rpc, tokenAccount);
  } catch {
    return null;
  }
}

async function fetchPublicSellerMetadata(routeUrl) {
  const parsed = new URL(routeUrl);
  const response = await fetch(`${parsed.origin}/.well-known/subly402.json`, {
    cache: "no-store",
  }).catch(() => null);
  if (!response?.ok) {
    return null;
  }
  return response.json();
}

async function resolveDemoSeller({ createAta = true } = {}) {
  const usdcMint = requireEnv("SUBLY402_USDC_MINT");
  let rpc = null;
  let feePayer = null;

  if (
    createAta ||
    (!process.env.SUBLY402_DEMO_SELLER_WALLET && !process.env.SELLER_WALLET)
  ) {
    rpc = createDemoRpc();
    ({ signer: feePayer } = await loadFeePayerSigner());
  }

  const sellerWallet =
    process.env.SUBLY402_DEMO_SELLER_WALLET ||
    process.env.SELLER_WALLET ||
    feePayer?.address ||
    null;
  if (!sellerWallet) {
    throw new Error(
      "Set SUBLY402_DEMO_SELLER_WALLET or SELLER_WALLET to the seller wallet owner address"
    );
  }

  let associatedTokenAccount = await deriveTokenAccount(sellerWallet, usdcMint);
  if (createAta) {
    associatedTokenAccount = (
      await createAssociatedTokenAccount(rpc, feePayer, sellerWallet, usdcMint)
    ).toString();
  }

  return {
    rpc,
    feePayer,
    sellerWallet,
    associatedTokenAccount,
  };
}

async function fundBuyerTokenAccount({ amount }) {
  const rpc = createDemoRpc();
  const usdcMint = requireEnv("SUBLY402_USDC_MINT");
  const { signer: feePayer } = await loadFeePayerSigner();
  const mintAuthority = await loadMintAuthoritySigner(rpc, usdcMint, feePayer);
  const { signer: buyer, secretKeyBytes } = await createDemoSigner();
  const buyerTokenAccount = await createAssociatedTokenAccount(
    rpc,
    feePayer,
    buyer.address,
    usdcMint
  );
  await fundAddressWithSol(
    rpc,
    feePayer,
    buyer.address,
    demoClientSolLamports()
  );

  let fundingTx;
  if (mintAuthority) {
    fundingTx = await mintTokens(
      rpc,
      feePayer,
      usdcMint,
      buyerTokenAccount,
      mintAuthority,
      amount
    );
  } else if (process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT) {
    const sourceOwner = process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_OWNER_WALLET
      ? (
          await loadSignerFromFile(
            process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_OWNER_WALLET
          )
        ).signer
      : feePayer;
    fundingTx = await transferTokens(
      rpc,
      feePayer,
      process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT,
      buyerTokenAccount,
      sourceOwner,
      amount
    );
  } else {
    throw new Error(
      "Demo needs test USDC funding. Set SUBLY402_USDC_MINT_AUTHORITY_WALLET or SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT."
    );
  }

  return {
    rpc,
    feePayer,
    buyer,
    secretKeyBytes,
    buyerTokenAccount: buyerTokenAccount.toString(),
    fundingTx,
  };
}

function u64Le(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(value));
  return buffer;
}

function buildDepositInstruction({
  programId,
  client,
  vaultConfig,
  clientTokenAccount,
  vaultTokenAccount,
  amount,
}) {
  return {
    programAddress: address(programId),
    accounts: [
      {
        address: client.address,
        role: AccountRole.WRITABLE_SIGNER,
        signer: client,
      },
      { address: address(vaultConfig), role: AccountRole.WRITABLE },
      { address: address(clientTokenAccount), role: AccountRole.WRITABLE },
      { address: address(vaultTokenAccount), role: AccountRole.WRITABLE },
      { address: TOKEN_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    ],
    data: Buffer.concat([DEPOSIT_DISCRIMINATOR, u64Le(amount)]),
  };
}

async function signTextRequest(signer, message) {
  const signature = await signBytes(
    signer.keyPair.privateKey,
    Buffer.from(message)
  );
  return Buffer.from(signature).toString("base64");
}

async function buildClientBalanceAuth(signer) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + 300;
  return {
    issuedAt,
    expiresAt,
    clientSig: await signTextRequest(
      signer,
      `SUBLY402-CLIENT-BALANCE\n${signer.address}\n${issuedAt}\n${expiresAt}\n`
    ),
  };
}

async function postJson(baseUrl, route, body, headers) {
  return fetch(`${baseUrl}${route}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(headers || {}),
    },
    body: JSON.stringify(body),
  });
}

async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForEndpoint(label, fn, attempts, delayMs) {
  let lastError = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const value = await fn();
      if (value) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(delayMs);
  }
  const suffix = lastError ? `: ${lastError.message}` : "";
  throw new Error(`Timed out waiting for ${label}${suffix}`);
}

async function fetchSublyBalance(facilitatorUrl, signer) {
  const auth = await buildClientBalanceAuth(signer);
  const response = await postJson(facilitatorUrl, "/v1/balance", {
    client: signer.address,
    issuedAt: auth.issuedAt,
    expiresAt: auth.expiresAt,
    clientSig: auth.clientSig,
  });
  if (!response.ok) {
    throw new Error(
      `/v1/balance failed: ${response.status} ${await response.text()}`
    );
  }
  return response.json();
}

async function waitForSublyBalance(facilitatorUrl, signer, minimumAtomic) {
  return waitForEndpoint(
    "Subly vault balance sync",
    async () => {
      const body = await fetchSublyBalance(facilitatorUrl, signer);
      return BigInt(body.free.toString()) >= BigInt(minimumAtomic)
        ? body
        : null;
    },
    readPositiveIntEnv("SUBLY402_DEMO_BALANCE_WAIT_ATTEMPTS", 120),
    readPositiveIntEnv("SUBLY402_DEMO_BALANCE_WAIT_DELAY_MS", 1000)
  );
}

async function depositIntoSublyVault({
  rpc,
  feePayer,
  client,
  clientTokenAccount,
  amount,
}) {
  const programId = requireEnv("SUBLY402_PROGRAM_ID");
  const vaultConfig = requireEnv("SUBLY402_VAULT_CONFIG");
  const vaultTokenAccount = requireEnv("SUBLY402_VAULT_TOKEN_ACCOUNT");

  return sendKitInstructions(rpc, feePayer, [
    buildDepositInstruction({
      programId,
      client,
      vaultConfig,
      clientTokenAccount,
      vaultTokenAccount,
      amount,
    }),
  ]);
}

function buildSublyClientAttestationOptions() {
  const pcrs = {};
  for (const index of ["0", "1", "2", "3", "8"]) {
    const value = process.env[`SUBLY402_PCR${index}`];
    if (value) {
      pcrs[index] = value;
    }
  }
  const hasPcrPolicy =
    Object.keys(pcrs).length > 0 &&
    process.env.SUBLY402_EIF_CERT_SHA256 &&
    process.env.SUBLY402_KMS_KEY_ARN_SHA256;

  if (hasPcrPolicy) {
    return {
      nitroAttestation: {
        policy: {
          version: 1,
          pcrs,
          eifSigningCertSha256: process.env.SUBLY402_EIF_CERT_SHA256,
          kmsKeyArnSha256: process.env.SUBLY402_KMS_KEY_ARN_SHA256,
          protocol: "subly402-svm-v1",
        },
      },
    };
  }

  return {
    attestationVerifier: async (attestation) => {
      if (attestation.vaultConfig !== requireEnv("SUBLY402_VAULT_CONFIG")) {
        throw new Error("Subly402 attestation vaultConfig mismatch");
      }
      if (
        attestation.attestationPolicyHash.toLowerCase() !==
        requireEnv("SUBLY402_ATTESTATION_POLICY_HASH_HEX").toLowerCase()
      ) {
        throw new Error("Subly402 attestation policy hash mismatch");
      }
      if (
        attestation.expiresAt &&
        Date.parse(attestation.expiresAt) <= Date.now()
      ) {
        throw new Error("Subly402 attestation is expired");
      }
    },
  };
}

async function getSettlementStatus(facilitatorUrl, settlementId, providerId) {
  const headers = {
    "x-subly402-provider-id": providerId,
  };
  const response = await postJson(
    facilitatorUrl,
    "/v1/settlement/status",
    { settlementId },
    headers
  );
  if (!response.ok) {
    throw new Error(
      `/v1/settlement/status failed: ${
        response.status
      } ${await response.text()}`
    );
  }
  return response.json();
}

function explorerTx(signature) {
  return `https://explorer.solana.com/tx/${signature}?cluster=devnet`;
}

function explorerAddress(value) {
  return `https://explorer.solana.com/address/${value}?cluster=devnet`;
}

module.exports = {
  DEFAULT_SUBLY_NETWORK,
  DEFAULT_X402_FACILITATOR_URL,
  DEFAULT_X402_NETWORK,
  DEMO_DESCRIPTION,
  DEMO_METHOD,
  DEMO_MIME_TYPE,
  DEMO_ROUTE_PATH,
  buildSublyClientAttestationOptions,
  decodeJsonHeader,
  demoDepositAmount,
  demoPaymentAmount,
  demoWeatherResponse,
  encodeJsonHeader,
  deriveTokenAccount,
  ensureAssociatedTokenAccount,
  explorerAddress,
  explorerTx,
  fetchSublyBalance,
  fetchTokenAmount,
  fetchTokenAmountOrNull,
  fetchPublicSellerMetadata,
  formatUsdcAtomic,
  getSettlementStatus,
  loadFourWayDemoEnv,
  logKV,
  paymentRequiredFromResponse,
  paymentResponseFromHeaders,
  printHeader,
  readPositiveIntEnv,
  requireEnv,
  resolveDemoSeller,
  rpcUrlFromEnv,
  shortKey,
  waitForEndpoint,
  waitForSublyBalance,
  fundBuyerTokenAccount,
  depositIntoSublyVault,
};
