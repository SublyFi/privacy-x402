#!/usr/bin/env node

const { getJson, loadDefaultEnvFiles, waitForEndpoint } = require("./common");

async function fetchStatus() {
  const enclaveUrl =
    process.env.A402_TEST_ENCLAVE_URL || "http://127.0.0.1:3100";
  const watchtowerUrl =
    process.env.A402_WATCHTOWER_URL || "http://127.0.0.1:3200";

  const watchtowerRes = await getJson(watchtowerUrl, "/v1/status");
  if (!watchtowerRes.ok) {
    throw new Error(`watchtower status failed: ${watchtowerRes.status}`);
  }
  const watchtower = await watchtowerRes.json();

  const attestationRes = await getJson(enclaveUrl, "/v1/attestation");
  if (!attestationRes.ok) {
    throw new Error(`enclave attestation failed: ${attestationRes.status}`);
  }
  const attestation = await attestationRes.json();

  return {
    ok: true,
    watchtower,
    attestation,
  };
}

async function main() {
  loadDefaultEnvFiles();

  if (process.argv.includes("--wait")) {
    const status = await waitForEndpoint(
      "devnet stack",
      fetchStatus,
      120,
      1000
    );
    console.log(JSON.stringify(status, null, 2));
    return;
  }

  const status = await fetchStatus();
  console.log(JSON.stringify(status, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
