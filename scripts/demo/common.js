const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const nacl = require("tweetnacl");

const { Keypair } = require("@solana/web3.js");

const {
  computePaymentDetailsHash,
  computeRequestHash,
  postJson,
  requireEnv,
  sha256hex,
  signPaymentPayload,
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

function loadMintAuthority(provider, mintAuthority) {
  if (mintAuthority === null) {
    return null;
  }
  const walletPath = process.env.A402_USDC_MINT_AUTHORITY_WALLET;
  if (walletPath) {
    return loadKeypairFromFile(walletPath);
  }
  if (mintAuthority.equals(provider.wallet.publicKey)) {
    return provider.wallet.payer;
  }
  return null;
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

async function fetchJson(baseUrl, route) {
  const response = await fetch(`${baseUrl}${route}`);
  if (!response.ok) {
    throw new Error(
      `${route} failed: ${response.status} ${await response.text()}`
    );
  }
  return response.json();
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
    pathAndQuery: `/demo/agent/provider-${provider.index}`,
    bodySha256: sha256hex(
      JSON.stringify({
        agentTask: "summarize private market data",
        provider: provider.index,
      })
    ),
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
    paymentDetailsId: `paydet_demo_${provider.id}_${crypto.randomUUID()}`,
    verifyWindowSec: 60,
    maxSettlementDelaySec: 900,
    privacyMode: "vault-batched-v1",
  };
  const paymentDetailsHash = computePaymentDetailsHash(paymentDetails);
  const requestHash = computeRequestHash(requestContext, paymentDetailsHash);
  const unsignedPayload = {
    version: 1,
    scheme: "a402-svm-v1",
    paymentId: `pay_demo_${crypto.randomUUID()}`,
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

function formatUsdcAtomic(value) {
  const atomic = BigInt(value.toString());
  const whole = atomic / 1_000_000n;
  const fraction = (atomic % 1_000_000n).toString().padStart(6, "0");
  return `${whole}.${fraction} USDC`;
}

function shortKey(value) {
  const text = value.toString();
  if (text.length <= 12) {
    return text;
  }
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
}

function printHeader(title) {
  console.log("");
  console.log("=".repeat(72));
  console.log(title);
  console.log("=".repeat(72));
}

function logStep(index, message) {
  console.log(`[${index}] ${message}`);
}

function logKV(label, value) {
  console.log(`    ${label}: ${value}`);
}

function requireDemoConfirmation(plan) {
  if (process.env.A402_DEMO_CONFIRM === "1") {
    return;
  }
  console.log(JSON.stringify({ ok: false, dryRun: true, plan }, null, 2));
  console.log("");
  console.log("Set A402_DEMO_CONFIRM=1 to send devnet transactions.");
  process.exit(0);
}

module.exports = {
  ROOT,
  assertFinalRoutes,
  buildClientRequestAuth,
  buildPayment,
  fetchJson,
  formatUsdcAtomic,
  loadDemoProviders,
  loadKeypairFromFile,
  loadMintAuthority,
  loadNitroEnv,
  logKV,
  logStep,
  postOrThrow,
  printHeader,
  readPositiveIntEnv,
  requireDemoConfirmation,
  requireEnv,
  shortKey,
};
