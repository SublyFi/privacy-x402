const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const anchor = require("@coral-xyz/anchor");
const { createMint } = require("@solana/spl-token");
const { Keypair, PublicKey } = require("@solana/web3.js");

const {
  ROOT,
  decodeHex32,
  deriveVaultAddresses,
  fundAccount,
  keypairFromSeedBase64,
  loadDefaultEnvFiles,
  loadProgram,
  loadProvider,
  randomSeedBase64,
} = require("../devnet/common");

const GENERATED_DIR = path.join(ROOT, "infra", "nitro", "generated");
const PLAN_PATH = path.join(GENERATED_DIR, "nitro-plan.json");

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\"'\"'`)}'`;
}

function writeEnvFile(filePath, vars) {
  ensureDir(path.dirname(filePath));
  const lines = Object.entries(vars)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `export ${key}=${shellQuote(value)}`);
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`);
}

function saveJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      continue;
    }
    const name = token.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith("--")) {
      args[name] = true;
      continue;
    }
    args[name] = next;
    i += 1;
  }
  return args;
}

function requireValue(name, value) {
  if (value === undefined || value === null || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

function normalizeHex(value, label = "hex value") {
  const normalized = String(value).trim().replace(/^0x/i, "").toLowerCase();
  if (!normalized) {
    throw new Error(`${label} must not be empty`);
  }
  if (!/^[0-9a-f]+$/.test(normalized)) {
    throw new Error(`${label} must contain only hex characters`);
  }
  return normalized;
}

function sha256hex(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function sha384hex(data) {
  return crypto.createHash("sha384").update(data).digest("hex");
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

function computeAttestationPolicy({
  measurements,
  eifSigningCertSha256,
  kmsKeyArnSha256,
  parentRolePcr3,
  protocol = "subly402-svm-v1",
}) {
  const normalizedMeasurements = normalizeMeasurements(measurements);
  const pcr8 = normalizedMeasurements.PCR8;
  if (!pcr8) {
    throw new Error(
      "measurements file is missing PCR8; build a signed EIF with --private-key and --signing-certificate"
    );
  }
  const policy = {
    version: 1,
    pcrs: {
      0: normalizedMeasurements.PCR0,
      1: normalizedMeasurements.PCR1,
      2: normalizedMeasurements.PCR2,
      3: normalizeHex(requireValue("parent role PCR3", parentRolePcr3), "PCR3"),
      8: pcr8,
    },
    eifSigningCertSha256: normalizeHex(
      eifSigningCertSha256,
      "EIF signing certificate SHA256"
    ),
    kmsKeyArnSha256: normalizeHex(kmsKeyArnSha256, "KMS key ARN SHA256"),
    protocol,
  };
  return {
    policy,
    hashHex: sha256hex(Buffer.from(canonicalJson(policy), "utf8")),
  };
}

function normalizeMeasurements(raw) {
  const measurements = raw.Measurements || raw.measurements || raw;
  const out = {};
  for (const key of ["PCR0", "PCR1", "PCR2"]) {
    const value = measurements[key];
    if (!value) {
      throw new Error(`measurements file is missing ${key}`);
    }
    out[key] = normalizeHex(value, key);
  }
  if (measurements.PCR8) {
    out.PCR8 = normalizeHex(measurements.PCR8, "PCR8");
  }
  return out;
}

function loadMeasurements(filePath) {
  return normalizeMeasurements(readJson(filePath));
}

function resolveKmsKeyArnSha256(args) {
  const explicitHash =
    args.kmsKeyArnSha256 || process.env.SUBLY402_KMS_KEY_ARN_SHA256;
  if (explicitHash) {
    return normalizeHex(explicitHash, "SUBLY402_KMS_KEY_ARN_SHA256");
  }
  const keyArn = args.kmsKeyArn || process.env.SUBLY402_KMS_KEY_ARN;
  if (!keyArn) {
    throw new Error(
      "SUBLY402_KMS_KEY_ARN or SUBLY402_KMS_KEY_ARN_SHA256 must be provided"
    );
  }
  return sha256hex(Buffer.from(keyArn, "utf8"));
}

function resolveEifSigningCertSha256(args) {
  const explicitHash =
    args.eifSigningCertSha256 || process.env.SUBLY402_EIF_SIGNING_CERT_SHA256;
  if (explicitHash) {
    return normalizeHex(explicitHash, "SUBLY402_EIF_SIGNING_CERT_SHA256");
  }
  const certPath =
    args.eifSigningCertPath || process.env.SUBLY402_EIF_SIGNING_CERT_PATH;
  if (!certPath) {
    throw new Error(
      "SUBLY402_EIF_SIGNING_CERT_PATH or SUBLY402_EIF_SIGNING_CERT_SHA256 must be provided"
    );
  }
  return fileSha256(certPath);
}

function fileSha256(filePath) {
  return sha256hex(fs.readFileSync(filePath));
}

function resolveNitroProjectName(args = {}) {
  return (
    args.projectName ||
    process.env.SUBLY402_NITRO_PROJECT_NAME ||
    "subly402-devnet"
  );
}

function resolveAwsCallerIdentity(args = {}) {
  const accountId =
    args.awsAccountId ||
    process.env.SUBLY402_AWS_ACCOUNT_ID ||
    process.env.AWS_ACCOUNT_ID;
  const partition = args.awsPartition || process.env.SUBLY402_AWS_PARTITION;
  if (accountId) {
    return {
      accountId: String(accountId).trim(),
      partition: partition || "aws",
    };
  }

  try {
    const output = execFileSync(
      "aws",
      ["sts", "get-caller-identity", "--output", "json"],
      {
        cwd: ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    const identity = JSON.parse(output);
    const arn = requireValue("caller identity ARN", identity.Arn);
    return {
      accountId: requireValue("caller identity Account", identity.Account),
      partition: arn.split(":")[1] || "aws",
    };
  } catch (error) {
    const stderr =
      error && typeof error.stderr === "string" ? error.stderr.trim() : "";
    throw new Error(
      stderr
        ? `failed to resolve AWS caller identity: ${stderr}`
        : `failed to resolve AWS caller identity: ${error.message}`
    );
  }
}

function resolveParentRoleArn(args = {}) {
  const explicitArn =
    args.parentRoleArn ||
    process.env.SUBLY402_PARENT_ROLE_ARN ||
    process.env.SUBLY402_NITRO_PARENT_ROLE_ARN;
  if (explicitArn) {
    return explicitArn.trim();
  }

  const { accountId, partition } = resolveAwsCallerIdentity(args);
  const projectName = resolveNitroProjectName(args);
  return `arn:${partition}:iam::${accountId}:role/${projectName}-parent`;
}

function computeParentRolePcr3(parentRoleArn) {
  const roleArn = requireValue("parent role ARN", parentRoleArn);
  const padded = Buffer.concat([
    Buffer.alloc(48, 0),
    Buffer.from(roleArn, "utf8"),
  ]);
  return sha384hex(padded);
}

function awsKmsEncryptBase64({ keyId, plaintext, encryptionContext, region }) {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "subly402-kms-"));
  const plaintextPath = path.join(tempDir, "plaintext.bin");
  fs.writeFileSync(plaintextPath, plaintext);
  try {
    const args = [
      "kms",
      "encrypt",
      "--key-id",
      requireValue("kms key id", keyId),
      "--plaintext",
      `fileb://${plaintextPath}`,
      "--output",
      "json",
    ];
    if (region) {
      args.push("--region", region);
    }
    if (encryptionContext && Object.keys(encryptionContext).length > 0) {
      args.push(
        "--encryption-context",
        Object.entries(encryptionContext)
          .map(([key, value]) => `${key}=${value}`)
          .join(",")
      );
    }
    const output = execFileSync("aws", args, {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const parsed = JSON.parse(output);
    return requireValue("CiphertextBlob", parsed.CiphertextBlob);
  } catch (error) {
    const stderr =
      error && typeof error.stderr === "string" ? error.stderr.trim() : "";
    throw new Error(
      stderr
        ? `aws kms encrypt failed: ${stderr}`
        : `aws kms encrypt failed: ${error.message}`
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function keypairToBase64(keypair) {
  return Buffer.from(keypair.secretKey).toString("base64");
}

function keypairFromBase64(encoded, label) {
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.length !== 64) {
    throw new Error(`${label} must decode to 64 bytes`);
  }
  return Keypair.fromSecretKey(new Uint8Array(bytes));
}

async function ensureFunded(provider, publicKey, minLamports) {
  const balance = await provider.connection.getBalance(publicKey);
  if (balance < minLamports) {
    await fundAccount(provider, publicKey, minLamports - balance);
  }
}

async function planVault({
  provider,
  program,
  desiredVaultId,
  vaultSignerPubkey,
  usdcMintBase58,
  reuseExistingVault,
}) {
  let vaultId = BigInt(desiredVaultId);
  let resolvedUsdcMint = usdcMintBase58 || null;

  while (true) {
    const { vaultConfigPda, vaultTokenAccountPda, vaultIdBn } =
      deriveVaultAddresses(
        provider.wallet.publicKey,
        vaultId,
        program.programId
      );
    const vaultConfigInfo = await provider.connection.getAccountInfo(
      vaultConfigPda
    );
    const existingVaultConfig = vaultConfigInfo
      ? await program.account.vaultConfig.fetch(vaultConfigPda)
      : null;

    if (!vaultConfigInfo) {
      if (!resolvedUsdcMint) {
        const mint = await createMint(
          provider.connection,
          provider.wallet.payer,
          provider.wallet.publicKey,
          null,
          6
        );
        resolvedUsdcMint = mint.toBase58();
      }

      return {
        vaultId,
        vaultIdBn,
        vaultConfigPda,
        vaultTokenAccountPda,
        vaultConfigInfo,
        existingVaultConfig,
        usdcMintBase58: resolvedUsdcMint,
      };
    }

    if (!resolvedUsdcMint) {
      resolvedUsdcMint = existingVaultConfig.usdcMint.toBase58();
    }

    if (
      reuseExistingVault ||
      existingVaultConfig.vaultSignerPubkey.toBase58() ===
        vaultSignerPubkey.toBase58()
    ) {
      return {
        vaultId,
        vaultIdBn,
        vaultConfigPda,
        vaultTokenAccountPda,
        vaultConfigInfo,
        existingVaultConfig,
        usdcMintBase58: resolvedUsdcMint,
      };
    }

    vaultId += 1n;
  }
}

function buildSignerEncryptionContext(vaultConfig) {
  return {
    "subly402:component": "vault-signer",
    "subly402:vaultConfig": vaultConfig,
  };
}

function buildStorageMetadataKey(vaultConfig) {
  return `meta/${vaultConfig}/snapshot-data-key.ciphertext`;
}

function loadOrCreateWatchtowerKeypair() {
  const encoded = process.env.SUBLY402_WATCHTOWER_KEYPAIR_B64;
  if (encoded) {
    return keypairFromBase64(encoded, "SUBLY402_WATCHTOWER_KEYPAIR_B64");
  }
  return Keypair.generate();
}

module.exports = {
  GENERATED_DIR,
  PLAN_PATH,
  ROOT,
  anchor,
  awsKmsEncryptBase64,
  buildSignerEncryptionContext,
  buildStorageMetadataKey,
  canonicalJson,
  computeParentRolePcr3,
  computeAttestationPolicy,
  decodeHex32,
  ensureDir,
  ensureFunded,
  keypairFromBase64,
  keypairFromSeedBase64,
  keypairToBase64,
  loadDefaultEnvFiles,
  loadMeasurements,
  loadOrCreateWatchtowerKeypair,
  loadProgram,
  loadProvider,
  normalizeHex,
  parseArgs,
  planVault,
  randomSeedBase64,
  readJson,
  resolveAwsCallerIdentity,
  resolveEifSigningCertSha256,
  resolveKmsKeyArnSha256,
  resolveNitroProjectName,
  resolveParentRoleArn,
  saveJson,
  sha256hex,
  sha384hex,
  writeEnvFile,
};
