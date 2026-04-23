const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { signBytes } = require("@solana/kit");

const ROOT = path.resolve(__dirname, "..", "..");

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

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
  { required = false, protectedKeys = new Set() } = {}
) {
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
    if (protectedKeys.has(key)) {
      continue;
    }
    process.env[key] = parseEnvAssignment(rawValue);
  }
  return true;
}

function loadNitroEnv() {
  const shellEnvKeys = new Set(Object.keys(process.env));

  loadEnvFile(path.join(ROOT, ".env.devnet.local"), {
    protectedKeys: shellEnvKeys,
  });

  const clientEnv =
    process.env.SUBLY402_NITRO_CLIENT_ENV ||
    path.join(ROOT, "infra", "nitro", "generated", "client.env");
  loadEnvFile(clientEnv, { required: true, protectedKeys: shellEnvKeys });

  const providerEnv =
    process.env.SUBLY402_DEMO_PROVIDERS_ENV ||
    "/root/subly402-demo-providers.env";
  const hasProviderShellEnv = [1, 2].every((index) => {
    return (
      process.env[`SUBLY402_DEMO_PROVIDER_${index}_ID`] &&
      process.env[`SUBLY402_DEMO_PROVIDER_${index}_TOKEN_ACCOUNT`] &&
      process.env[`SUBLY402_DEMO_PROVIDER_${index}_API_KEY`]
    );
  });
  loadEnvFile(providerEnv, {
    required: !hasProviderShellEnv,
    protectedKeys: shellEnvKeys,
  });
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

function selectDemoProviders(providers) {
  if (process.env.SUBLY402_DEMO_ALL_PROVIDERS === "1") {
    return providers;
  }

  const providerIndex = readPositiveIntEnv("SUBLY402_DEMO_PROVIDER_INDEX", 1);
  const provider = providers.find((item) => item.index === providerIndex);
  if (!provider) {
    throw new Error(
      `SUBLY402_DEMO_PROVIDER_INDEX=${providerIndex} is not configured`
    );
  }
  return [provider];
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

async function signTextRequest(signer, message) {
  const signature = await signBytes(
    signer.keyPair.privateKey,
    Buffer.from(message)
  );
  return Buffer.from(signature).toString("base64");
}

async function buildClientRequestAuth(clientSigner, buildMessage) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + 300;
  return {
    issuedAt,
    expiresAt,
    clientSig: await signTextRequest(
      clientSigner,
      buildMessage(issuedAt, expiresAt)
    ),
  };
}

function sha256hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value).sort(([left], [right]) =>
      left < right ? -1 : left > right ? 1 : 0
    );
    return `{${entries
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function computePaymentDetailsHash(details) {
  return sha256hex(canonicalJson(details));
}

function computeRequestHash(
  { method, origin, pathAndQuery, bodySha256 },
  paymentDetailsHash
) {
  const preimage =
    `SUBLY402-SVM-V1-REQ\n` +
    `${method}\n` +
    `${origin}\n` +
    `${pathAndQuery}\n` +
    `${bodySha256}\n` +
    `${paymentDetailsHash}\n`;
  return sha256hex(preimage);
}

async function signPaymentPayload(signer, fields) {
  const message =
    `SUBLY402-SVM-V1-AUTH\n` +
    `${fields.version}\n` +
    `${fields.scheme}\n` +
    `${fields.paymentId}\n` +
    `${fields.client}\n` +
    `${fields.vault}\n` +
    `${fields.providerId}\n` +
    `${fields.payTo}\n` +
    `${fields.network}\n` +
    `${fields.assetMint}\n` +
    `${fields.amount}\n` +
    `${fields.requestHash}\n` +
    `${fields.paymentDetailsHash}\n` +
    `${fields.expiresAt}\n` +
    `${fields.nonce}\n`;
  return signTextRequest(signer, message);
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

async function postOrThrow(enclaveUrl, route, body, headers) {
  const response = await postJson(enclaveUrl, route, body, headers);
  if (!response.ok) {
    throw new Error(
      `${route} failed: ${response.status} ${await response.text()}`
    );
  }
  return response.json();
}

async function assertRouteAbsent(enclaveUrl, route) {
  const response = await fetch(`${enclaveUrl}${route}`, { method: "GET" });
  if (response.status !== 404) {
    throw new Error(
      `expected final EIF to have ${route} disabled; safe GET returned ${response.status}`
    );
  }
}

async function assertFinalRoutes(enclaveUrl) {
  await assertRouteAbsent(enclaveUrl, "/v1/provider/register");
  await assertRouteAbsent(enclaveUrl, "/v1/admin/fire-batch");
}

async function buildPayment({
  attestation,
  clientSigner,
  enclaveUrl,
  provider,
  requestOrigin,
  network,
  usdcMint,
  vaultConfig,
  paymentAmount,
  nonce,
  requestMethod = "GET",
  routePath = "/weather",
  requestBody = null,
}) {
  const requestContext = {
    method: requestMethod,
    origin: requestOrigin,
    pathAndQuery: routePath,
    bodySha256: sha256hex(
      requestBody == null ? "" : JSON.stringify(requestBody)
    ),
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
    paymentDetailsId: `paydet_demo_${provider.id}_${crypto.randomUUID()}`,
    verifyWindowSec: 60,
    maxSettlementDelaySec: 900,
    privacyMode: "vault-batched-v1",
  };
  const paymentDetailsHash = computePaymentDetailsHash(paymentDetails);
  const requestHash = computeRequestHash(requestContext, paymentDetailsHash);
  const unsignedPayload = {
    version: 1,
    scheme: "subly402-svm-v1",
    paymentId: `pay_demo_${crypto.randomUUID()}`,
    client: clientSigner.address,
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
      clientSig: await signPaymentPayload(clientSigner, unsignedPayload),
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
  if (process.env.SUBLY402_DEMO_CONFIRM === "1") {
    return;
  }
  console.log(JSON.stringify({ ok: false, dryRun: true, plan }, null, 2));
  console.log("");
  console.log("Set SUBLY402_DEMO_CONFIRM=1 to send devnet transactions.");
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
  loadNitroEnv,
  logKV,
  logStep,
  postJson,
  postOrThrow,
  printHeader,
  readPositiveIntEnv,
  requireDemoConfirmation,
  requireEnv,
  selectDemoProviders,
  sha256hex,
  shortKey,
  waitForEndpoint,
};
