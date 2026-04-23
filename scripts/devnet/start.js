#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawn, spawnSync } = require("child_process");

const {
  ROOT,
  getJson,
  loadDefaultEnvFiles,
  waitForEndpoint,
} = require("./common");

const WATCHTOWER_BIN = path.join(
  ROOT,
  "target",
  "debug",
  "subly402-watchtower"
);
const ENCLAVE_BIN = path.join(ROOT, "target", "debug", "subly402-enclave");
const WATCHTOWER_PID = path.join(ROOT, "data", "watchtower-devnet.pid");
const ENCLAVE_PID = path.join(ROOT, "data", "enclave-devnet.pid");
const WATCHTOWER_LOG = path.join(ROOT, "data", "logs", "watchtower-devnet.log");
const ENCLAVE_LOG = path.join(ROOT, "data", "logs", "enclave-devnet.log");

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function readPid(pidFile) {
  if (!fs.existsSync(pidFile)) {
    return null;
  }
  return Number(fs.readFileSync(pidFile, "utf8").trim());
}

function isRunning(pid) {
  if (!pid) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function ensureBuilt() {
  if (fs.existsSync(WATCHTOWER_BIN) && fs.existsSync(ENCLAVE_BIN)) {
    return;
  }
  const result = spawnSync(
    "cargo",
    ["build", "-p", "subly402-watchtower", "-p", "subly402-enclave"],
    {
      cwd: ROOT,
      env: {
        ...process.env,
        NO_DNA: "1",
      },
      stdio: "inherit",
    }
  );
  if (result.status !== 0) {
    process.exit(result.status || 1);
  }
}

function spawnDetached(binPath, logPath, pidFile) {
  ensureDir(path.dirname(logPath));
  const logFd = fs.openSync(logPath, "a");
  const child = spawn(binPath, [], {
    cwd: ROOT,
    env: {
      ...process.env,
      NO_DNA: "1",
    },
    detached: true,
    stdio: ["ignore", logFd, logFd],
  });
  child.unref();
  fs.writeFileSync(pidFile, `${child.pid}\n`);
}

async function fetchStatus() {
  const enclaveUrl =
    process.env.SUBLY402_TEST_ENCLAVE_URL || "http://127.0.0.1:3100";
  const watchtowerUrl =
    process.env.SUBLY402_WATCHTOWER_URL || "http://127.0.0.1:3200";

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

  return { ok: true, watchtower, attestation };
}

async function main() {
  loadDefaultEnvFiles();
  ensureBuilt();
  ensureDir(path.join(ROOT, "data", "logs"));

  const watchtowerPid = readPid(WATCHTOWER_PID);
  if (!isRunning(watchtowerPid)) {
    fs.rmSync(WATCHTOWER_PID, { force: true });
    spawnDetached(WATCHTOWER_BIN, WATCHTOWER_LOG, WATCHTOWER_PID);
  }

  const enclavePid = readPid(ENCLAVE_PID);
  if (!isRunning(enclavePid)) {
    fs.rmSync(ENCLAVE_PID, { force: true });
    spawnDetached(ENCLAVE_BIN, ENCLAVE_LOG, ENCLAVE_PID);
  }

  const status = await waitForEndpoint("devnet stack", fetchStatus, 120, 1000);
  console.log(JSON.stringify(status, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
