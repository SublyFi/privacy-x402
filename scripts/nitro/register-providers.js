#!/usr/bin/env node

const path = require("path");

const {
  ROOT,
  loadDefaultEnvFiles,
  loadEnvFile,
  postJson,
  requireEnv,
  sha256hex,
} = require("../devnet/common");

function loadNitroEnv() {
  loadDefaultEnvFiles();
  loadEnvFile(
    process.env.SUBLY402_NITRO_CLIENT_ENV ||
      path.join(ROOT, "infra", "nitro", "generated", "client.env")
  );
  loadEnvFile(
    process.env.SUBLY402_DEMO_PROVIDERS_ENV ||
      "/root/subly402-demo-providers.env"
  );
}

function loadProvider(index) {
  const id = process.env[`SUBLY402_DEMO_PROVIDER_${index}_ID`];
  const tokenAccount =
    process.env[`SUBLY402_DEMO_PROVIDER_${index}_TOKEN_ACCOUNT`];
  const apiKey = process.env[`SUBLY402_DEMO_PROVIDER_${index}_API_KEY`];
  if (!id || !tokenAccount || !apiKey) {
    throw new Error(
      `SUBLY402_DEMO_PROVIDER_${index}_{ID,TOKEN_ACCOUNT,API_KEY} are required`
    );
  }
  return { index, id, tokenAccount, apiKey };
}

async function assertRegistrationRoute(enclaveUrl) {
  const response = await postJson(enclaveUrl, "/v1/provider/register", {});
  if (response.status === 404) {
    throw new Error(
      "/v1/provider/register is 404. Start the provider-bootstrap EIF before registering providers."
    );
  }
}

async function registerProvider(
  enclaveUrl,
  provider,
  network,
  assetMint,
  origin
) {
  const response = await postJson(enclaveUrl, "/v1/provider/register", {
    providerId: provider.id,
    displayName: `Subly402 Demo Provider ${provider.index}`,
    settlementTokenAccount: provider.tokenAccount,
    network,
    assetMint,
    allowedOrigins: [origin],
    authMode: "bearer",
    apiKeyHash: sha256hex(provider.apiKey),
  });
  const text = await response.text();

  if (response.ok) {
    return {
      providerId: provider.id,
      status: "registered",
      response: JSON.parse(text),
    };
  }

  if (response.status === 409 && text.includes("provider_already_registered")) {
    return { providerId: provider.id, status: "already_registered" };
  }

  throw new Error(
    `/v1/provider/register failed for ${provider.id}: ${response.status} ${text}`
  );
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
  const network = process.env.SUBLY402_NETWORK || "solana:devnet";
  const assetMint = requireEnv("SUBLY402_USDC_MINT");
  const origin = process.env.SUBLY402_REQUEST_ORIGIN || "http://localhost:3000";
  const providers = [loadProvider(1), loadProvider(2)];

  await assertRegistrationRoute(enclaveUrl);

  const results = [];
  for (const provider of providers) {
    results.push(
      await registerProvider(enclaveUrl, provider, network, assetMint, origin)
    );
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        enclaveUrl,
        vaultConfig: process.env.SUBLY402_VAULT_CONFIG,
        results,
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
