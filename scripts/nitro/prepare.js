#!/usr/bin/env node

const path = require("path");

const {
  GENERATED_DIR,
  PLAN_PATH,
  anchor,
  awsKmsEncryptBase64,
  buildSignerEncryptionContext,
  buildStorageMetadataKey,
  computeParentRolePcr3,
  ensureFunded,
  keypairFromSeedBase64,
  keypairToBase64,
  loadDefaultEnvFiles,
  loadOrCreateWatchtowerKeypair,
  loadProgram,
  loadProvider,
  parseArgs,
  planVault,
  randomSeedBase64,
  resolveEifSigningCertSha256,
  resolveKmsKeyArnSha256,
  resolveNitroProjectName,
  resolveParentRoleArn,
  saveJson,
  sha256hex,
  writeEnvFile,
} = require("./common");

function isEnvEnabled(value) {
  return ["1", "true", "TRUE", "yes", "YES"].includes(value || "");
}

function resolveAdminAuthTokenSha256() {
  if (process.env.SUBLY402_ADMIN_AUTH_TOKEN_SHA256) {
    return process.env.SUBLY402_ADMIN_AUTH_TOKEN_SHA256;
  }
  if (process.env.SUBLY402_ADMIN_AUTH_TOKEN) {
    return sha256hex(process.env.SUBLY402_ADMIN_AUTH_TOKEN);
  }
  return undefined;
}

function firstEnvValue(...names) {
  for (const name of names) {
    const value = process.env[name];
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return undefined;
}

async function main() {
  loadDefaultEnvFiles();
  const args = parseArgs(process.argv.slice(2));

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);

  const desiredVaultId =
    args.vaultId ||
    process.env.SUBLY402_VAULT_ID ||
    process.env.SUBLY402_NITRO_VAULT_ID ||
    "1";
  const localSignerSeedBase64 =
    args.localSignerSeedBase64 ||
    process.env.SUBLY402_LOCAL_VAULT_SIGNER_SECRET_KEY_B64 ||
    randomSeedBase64();
  const localSigner = keypairFromSeedBase64(localSignerSeedBase64);
  const reuseExistingVault = process.env.SUBLY402_REUSE_EXISTING_VAULT === "1";
  const projectName = resolveNitroProjectName(args);
  const parentRoleArn = resolveParentRoleArn({ ...args, projectName });
  const kmsKeyId =
    args.kmsKeyId ||
    process.env.SUBLY402_KMS_KEY_ID ||
    process.env.SUBLY402_KMS_KEY_ARN ||
    process.env.SUBLY402_SNAPSHOT_DATA_KEY_ID;
  if (!kmsKeyId) {
    throw new Error(
      "SUBLY402_KMS_KEY_ID (or SUBLY402_KMS_KEY_ARN / SUBLY402_SNAPSHOT_DATA_KEY_ID) is required"
    );
  }

  const planned = await planVault({
    provider,
    program,
    desiredVaultId,
    vaultSignerPubkey: localSigner.publicKey,
    usdcMintBase58: process.env.SUBLY402_USDC_MINT || null,
    reuseExistingVault,
  });

  const vaultConfig = planned.vaultConfigPda.toBase58();
  const vaultTokenAccount = planned.vaultTokenAccountPda.toBase58();
  const signerMinLamports = Number(
    process.env.SUBLY402_VAULT_SIGNER_MIN_LAMPORTS || "50000000"
  );
  const watchtowerMinLamports = Number(
    process.env.SUBLY402_WATCHTOWER_MIN_LAMPORTS || "50000000"
  );
  const watchtowerKeypair = loadOrCreateWatchtowerKeypair();

  await ensureFunded(provider, localSigner.publicKey, signerMinLamports);
  await ensureFunded(
    provider,
    watchtowerKeypair.publicKey,
    watchtowerMinLamports
  );

  const kmsKeyArnSha256 = resolveKmsKeyArnSha256(args);
  const eifSigningCertSha256 = resolveEifSigningCertSha256(args);
  const awsRegion =
    args.awsRegion ||
    process.env.AWS_REGION ||
    process.env.SUBLY402_KMS_REGION ||
    "us-east-1";
  const protocol =
    args.protocol ||
    process.env.SUBLY402_ATTESTATION_PROTOCOL ||
    "subly402-svm-v1";
  const snapshotDataKeyId =
    args.snapshotDataKeyId ||
    process.env.SUBLY402_SNAPSHOT_DATA_KEY_ID ||
    kmsKeyId;
  const enableProviderRegistrationApi =
    process.env.SUBLY402_ENABLE_PROVIDER_REGISTRATION_API || "0";
  const enableAdminApi = process.env.SUBLY402_ENABLE_ADMIN_API || "0";
  const adminAuthTokenSha256 = resolveAdminAuthTokenSha256();
  if (
    (isEnvEnabled(enableProviderRegistrationApi) ||
      isEnvEnabled(enableAdminApi)) &&
    !adminAuthTokenSha256
  ) {
    throw new Error(
      [
        "SUBLY402_ADMIN_AUTH_TOKEN or SUBLY402_ADMIN_AUTH_TOKEN_SHA256",
        "is required when control-plane APIs are enabled",
      ].join(" ")
    );
  }
  const ciphertextB64 = awsKmsEncryptBase64({
    keyId: kmsKeyId,
    plaintext: Buffer.from(localSigner.secretKey.slice(0, 32)),
    encryptionContext: buildSignerEncryptionContext(vaultConfig),
    region: awsRegion,
  });

  const enclaveEnv = {
    RUST_LOG: process.env.RUST_LOG || "info",
    SUBLY402_ENCLAVE_INTERCONNECT_MODE: "vsock",
    SUBLY402_PARENT_CID: process.env.SUBLY402_PARENT_CID || "3",
    SUBLY402_ENCLAVE_INGRESS_PORT:
      process.env.SUBLY402_ENCLAVE_INGRESS_PORT || "5000",
    SUBLY402_ENCLAVE_EGRESS_PORT:
      process.env.SUBLY402_ENCLAVE_EGRESS_PORT || "5001",
    SUBLY402_ENCLAVE_KMS_PORT: process.env.SUBLY402_ENCLAVE_KMS_PORT || "5002",
    SUBLY402_ENCLAVE_SNAPSHOT_PORT:
      process.env.SUBLY402_ENCLAVE_SNAPSHOT_PORT || "5003",
    SUBLY402_PROGRAM_ID: program.programId.toBase58(),
    SUBLY402_VAULT_CONFIG: vaultConfig,
    SUBLY402_VAULT_TOKEN_ACCOUNT: vaultTokenAccount,
    SUBLY402_USDC_MINT: planned.usdcMintBase58,
    SUBLY402_SOLANA_RPC_URL: process.env.SUBLY402_SOLANA_RPC_URL,
    SUBLY402_SOLANA_WS_URL: process.env.SUBLY402_SOLANA_WS_URL,
    SUBLY402_WAL_PATH:
      process.env.SUBLY402_WAL_PATH || "/var/lib/subly402/wal-devnet.jsonl",
    SUBLY402_WAL_PREFIX:
      process.env.SUBLY402_WAL_PREFIX || `wal/${vaultConfig}`,
    SUBLY402_WATCHTOWER_URL:
      process.env.SUBLY402_WATCHTOWER_URL || "http://127.0.0.1:3200",
    SUBLY402_VAULT_SIGNER_SEED_CIPHERTEXT_B64: ciphertextB64,
    SUBLY402_SNAPSHOT_DATA_KEY_ID: snapshotDataKeyId,
    SUBLY402_STORAGE_KEY_METADATA_KEY:
      process.env.SUBLY402_STORAGE_KEY_METADATA_KEY ||
      buildStorageMetadataKey(vaultConfig),
    SUBLY402_KMS_KEY_ARN_SHA256: kmsKeyArnSha256,
    SUBLY402_EIF_SIGNING_CERT_SHA256: eifSigningCertSha256,
    SUBLY402_ATTESTATION_PROTOCOL: protocol,
    SUBLY402_ENCLAVE_TLS_CERT_PATH:
      process.env.SUBLY402_ENCLAVE_TLS_CERT_PATH ||
      "/etc/subly402/tls/server.crt",
    SUBLY402_ENCLAVE_TLS_KEY_PATH:
      process.env.SUBLY402_ENCLAVE_TLS_KEY_PATH ||
      "/etc/subly402/tls/server.key",
    SUBLY402_ENABLE_PROVIDER_REGISTRATION_API: enableProviderRegistrationApi,
    SUBLY402_ENABLE_ADMIN_API: enableAdminApi,
    SUBLY402_ADMIN_AUTH_TOKEN_SHA256: adminAuthTokenSha256,
    SUBLY402_BATCH_WINDOW_SEC:
      firstEnvValue("SUBLY402_BATCH_WINDOW_SEC", "BATCH_WINDOW_SEC") || "120",
    SUBLY402_MIN_BATCH_PROVIDERS:
      firstEnvValue("SUBLY402_MIN_BATCH_PROVIDERS", "MIN_BATCH_PROVIDERS") ||
      "2",
    SUBLY402_MIN_ANONYMITY_WINDOW_SEC:
      firstEnvValue(
        "SUBLY402_MIN_ANONYMITY_WINDOW_SEC",
        "MIN_ANONYMITY_WINDOW_SEC"
      ) || "300",
    SUBLY402_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC:
      process.env.SUBLY402_AUTO_BATCH_MIN_PROVIDER_PAYOUT_ATOMIC || "1000000",
    SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH:
      process.env.SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH || "0",
    SUBLY402_MANIFEST_HASH_HEX: process.env.SUBLY402_MANIFEST_HASH_HEX,
  };

  const watchtowerEnv = {
    RUST_LOG: process.env.RUST_LOG || "info",
    SUBLY402_WATCHTOWER_LISTEN:
      process.env.SUBLY402_WATCHTOWER_LISTEN || "127.0.0.1:3200",
    SUBLY402_WATCHTOWER_STORE_PATH:
      process.env.SUBLY402_WATCHTOWER_STORE_PATH ||
      "/var/lib/subly402/watchtower/receipts.json",
    SUBLY402_WATCHTOWER_POLL_SEC:
      process.env.SUBLY402_WATCHTOWER_POLL_SEC || "10",
    SUBLY402_PROGRAM_ID: program.programId.toBase58(),
    SUBLY402_VAULT_CONFIG: vaultConfig,
    SUBLY402_SOLANA_RPC_URL: process.env.SUBLY402_SOLANA_RPC_URL,
    SUBLY402_WATCHTOWER_KEYPAIR_B64: keypairToBase64(watchtowerKeypair),
  };

  const parentEnv = {
    RUST_LOG: process.env.RUST_LOG || "info",
    SUBLY402_PARENT_INGRESS_LISTEN:
      process.env.SUBLY402_PARENT_INGRESS_LISTEN || "0.0.0.0:443",
    SUBLY402_PARENT_INTERCONNECT_MODE: "vsock",
    SUBLY402_ENCLAVE_CID: process.env.SUBLY402_ENCLAVE_CID || "16",
    SUBLY402_ENCLAVE_INGRESS_PORT: enclaveEnv.SUBLY402_ENCLAVE_INGRESS_PORT,
    SUBLY402_ENCLAVE_EGRESS_PORT: enclaveEnv.SUBLY402_ENCLAVE_EGRESS_PORT,
    SUBLY402_ENCLAVE_KMS_PORT: enclaveEnv.SUBLY402_ENCLAVE_KMS_PORT,
    SUBLY402_ENCLAVE_SNAPSHOT_PORT: enclaveEnv.SUBLY402_ENCLAVE_SNAPSHOT_PORT,
    SUBLY402_SNAPSHOT_DIR:
      process.env.SUBLY402_SNAPSHOT_DIR || "/var/lib/subly402/snapshots",
    SUBLY402_KMS_REGION: awsRegion,
    SUBLY402_EGRESS_ALLOWLIST: process.env.SUBLY402_EGRESS_ALLOWLIST,
  };

  const runEnclaveConfig = {
    enclave_name:
      process.env.SUBLY402_NITRO_ENCLAVE_NAME || "subly402-devnet-enclave",
    cpu_count: Number(process.env.SUBLY402_NITRO_CPU_COUNT || "2"),
    memory_mib: Number(process.env.SUBLY402_NITRO_MEMORY_MIB || "2048"),
    eif_path:
      process.env.SUBLY402_NITRO_EIF_PATH ||
      "/opt/subly402/enclave/subly402-enclave.eif",
    enclave_cid: Number(parentEnv.SUBLY402_ENCLAVE_CID),
    debug_mode: process.env.SUBLY402_NITRO_DEBUG_MODE === "1",
  };

  const auditorMasterPubkeyHex = (
    process.env.SUBLY402_AUDITOR_MASTER_PUBKEY_HEX || "00".repeat(32)
  ).toLowerCase();
  const plan = {
    createdAt: new Date().toISOString(),
    vaultId: planned.vaultId.toString(),
    governance: provider.wallet.publicKey.toBase58(),
    programId: program.programId.toBase58(),
    vaultConfig,
    vaultTokenAccount,
    usdcMint: planned.usdcMintBase58,
    vaultSignerPubkey: localSigner.publicKey.toBase58(),
    vaultSignerSeedCiphertextB64: ciphertextB64,
    watchtowerPubkey: watchtowerKeypair.publicKey.toBase58(),
    watchtowerKeypairB64: watchtowerEnv.SUBLY402_WATCHTOWER_KEYPAIR_B64,
    kmsKeyId,
    kmsKeyArnSha256,
    eifSigningCertSha256,
    snapshotDataKeyId,
    storageKeyMetadataKey: enclaveEnv.SUBLY402_STORAGE_KEY_METADATA_KEY,
    signerMinLamports,
    watchtowerMinLamports,
    auditorMasterPubkeyHex,
    protocol,
    awsRegion,
    projectName,
    parentRoleArn,
    parentRolePcr3: computeParentRolePcr3(parentRoleArn),
    existingVault: Boolean(planned.vaultConfigInfo),
    generatedFiles: {
      enclaveEnv: path.join(GENERATED_DIR, "enclave.env"),
      watchtowerEnv: path.join(GENERATED_DIR, "watchtower.env"),
      parentEnv: path.join(GENERATED_DIR, "parent.env"),
      runEnclaveConfig: path.join(GENERATED_DIR, "run-enclave.json"),
      plan: PLAN_PATH,
    },
  };

  writeEnvFile(path.join(GENERATED_DIR, "enclave.env"), enclaveEnv);
  writeEnvFile(path.join(GENERATED_DIR, "watchtower.env"), watchtowerEnv);
  writeEnvFile(path.join(GENERATED_DIR, "parent.env"), parentEnv);
  saveJson(path.join(GENERATED_DIR, "run-enclave.json"), runEnclaveConfig);
  saveJson(PLAN_PATH, plan);

  console.log(
    JSON.stringify(
      {
        ok: true,
        stage: "prepare",
        summary: {
          vaultId: plan.vaultId,
          vaultConfig: plan.vaultConfig,
          vaultTokenAccount: plan.vaultTokenAccount,
          usdcMint: plan.usdcMint,
          vaultSignerPubkey: plan.vaultSignerPubkey,
          watchtowerPubkey: plan.watchtowerPubkey,
          generatedDir: GENERATED_DIR,
        },
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
