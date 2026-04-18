#!/usr/bin/env node

const path = require("path");

const {
  GENERATED_DIR,
  PLAN_PATH,
  anchor,
  awsKmsEncryptBase64,
  buildSignerEncryptionContext,
  buildStorageMetadataKey,
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
  saveJson,
  writeEnvFile,
} = require("./common");

async function main() {
  loadDefaultEnvFiles();
  const args = parseArgs(process.argv.slice(2));

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);

  const desiredVaultId =
    args.vaultId ||
    process.env.A402_VAULT_ID ||
    process.env.A402_NITRO_VAULT_ID ||
    "1";
  const localSignerSeedBase64 =
    args.localSignerSeedBase64 ||
    process.env.A402_LOCAL_VAULT_SIGNER_SECRET_KEY_B64 ||
    randomSeedBase64();
  const localSigner = keypairFromSeedBase64(localSignerSeedBase64);
  const reuseExistingVault = process.env.A402_REUSE_EXISTING_VAULT === "1";
  const kmsKeyId =
    args.kmsKeyId ||
    process.env.A402_KMS_KEY_ID ||
    process.env.A402_KMS_KEY_ARN ||
    process.env.A402_SNAPSHOT_DATA_KEY_ID;
  if (!kmsKeyId) {
    throw new Error(
      "A402_KMS_KEY_ID (or A402_KMS_KEY_ARN / A402_SNAPSHOT_DATA_KEY_ID) is required"
    );
  }

  const planned = await planVault({
    provider,
    program,
    desiredVaultId,
    vaultSignerPubkey: localSigner.publicKey,
    usdcMintBase58: process.env.A402_USDC_MINT || null,
    reuseExistingVault,
  });

  const vaultConfig = planned.vaultConfigPda.toBase58();
  const vaultTokenAccount = planned.vaultTokenAccountPda.toBase58();
  const signerMinLamports = Number(
    process.env.A402_VAULT_SIGNER_MIN_LAMPORTS || "50000000"
  );
  const watchtowerMinLamports = Number(
    process.env.A402_WATCHTOWER_MIN_LAMPORTS || "50000000"
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
    process.env.A402_KMS_REGION ||
    "us-east-1";
  const protocol =
    args.protocol || process.env.A402_ATTESTATION_PROTOCOL || "a402-svm-v1";
  const snapshotDataKeyId =
    args.snapshotDataKeyId || process.env.A402_SNAPSHOT_DATA_KEY_ID || kmsKeyId;
  const ciphertextB64 = awsKmsEncryptBase64({
    keyId: kmsKeyId,
    plaintext: Buffer.from(localSigner.secretKey.slice(0, 32)),
    encryptionContext: buildSignerEncryptionContext(vaultConfig),
    region: awsRegion,
  });

  const enclaveEnv = {
    RUST_LOG: process.env.RUST_LOG || "info",
    A402_ENCLAVE_INTERCONNECT_MODE: "vsock",
    A402_PARENT_CID: process.env.A402_PARENT_CID || "3",
    A402_ENCLAVE_INGRESS_PORT: process.env.A402_ENCLAVE_INGRESS_PORT || "5000",
    A402_ENCLAVE_EGRESS_PORT: process.env.A402_ENCLAVE_EGRESS_PORT || "5001",
    A402_ENCLAVE_KMS_PORT: process.env.A402_ENCLAVE_KMS_PORT || "5002",
    A402_ENCLAVE_SNAPSHOT_PORT:
      process.env.A402_ENCLAVE_SNAPSHOT_PORT || "5003",
    A402_PROGRAM_ID: program.programId.toBase58(),
    A402_VAULT_CONFIG: vaultConfig,
    A402_VAULT_TOKEN_ACCOUNT: vaultTokenAccount,
    A402_USDC_MINT: planned.usdcMintBase58,
    A402_SOLANA_RPC_URL: process.env.A402_SOLANA_RPC_URL,
    A402_SOLANA_WS_URL: process.env.A402_SOLANA_WS_URL,
    A402_WAL_PATH:
      process.env.A402_WAL_PATH || "/var/lib/a402/wal-devnet.jsonl",
    A402_WAL_PREFIX: process.env.A402_WAL_PREFIX || `wal/${vaultConfig}`,
    A402_WATCHTOWER_URL:
      process.env.A402_WATCHTOWER_URL || "http://127.0.0.1:3200",
    A402_VAULT_SIGNER_SEED_CIPHERTEXT_B64: ciphertextB64,
    A402_SNAPSHOT_DATA_KEY_ID: snapshotDataKeyId,
    A402_STORAGE_KEY_METADATA_KEY:
      process.env.A402_STORAGE_KEY_METADATA_KEY ||
      buildStorageMetadataKey(vaultConfig),
    A402_KMS_KEY_ARN_SHA256: kmsKeyArnSha256,
    A402_EIF_SIGNING_CERT_SHA256: eifSigningCertSha256,
    A402_ATTESTATION_PROTOCOL: protocol,
    A402_ENCLAVE_TLS_CERT_PATH:
      process.env.A402_ENCLAVE_TLS_CERT_PATH || "/etc/a402/tls/server.crt",
    A402_ENCLAVE_TLS_KEY_PATH:
      process.env.A402_ENCLAVE_TLS_KEY_PATH || "/etc/a402/tls/server.key",
    A402_ENABLE_PROVIDER_REGISTRATION_API:
      process.env.A402_ENABLE_PROVIDER_REGISTRATION_API || "0",
    A402_ENABLE_ADMIN_API: process.env.A402_ENABLE_ADMIN_API || "0",
    A402_MANIFEST_HASH_HEX: process.env.A402_MANIFEST_HASH_HEX,
  };

  const watchtowerEnv = {
    RUST_LOG: process.env.RUST_LOG || "info",
    A402_WATCHTOWER_LISTEN:
      process.env.A402_WATCHTOWER_LISTEN || "127.0.0.1:3200",
    A402_WATCHTOWER_STORE_PATH:
      process.env.A402_WATCHTOWER_STORE_PATH ||
      "/var/lib/a402/watchtower/receipts.json",
    A402_WATCHTOWER_POLL_SEC: process.env.A402_WATCHTOWER_POLL_SEC || "10",
    A402_PROGRAM_ID: program.programId.toBase58(),
    A402_VAULT_CONFIG: vaultConfig,
    A402_SOLANA_RPC_URL: process.env.A402_SOLANA_RPC_URL,
    A402_WATCHTOWER_KEYPAIR_B64: keypairToBase64(watchtowerKeypair),
  };

  const parentEnv = {
    RUST_LOG: process.env.RUST_LOG || "info",
    A402_PARENT_INGRESS_LISTEN:
      process.env.A402_PARENT_INGRESS_LISTEN || "0.0.0.0:443",
    A402_PARENT_INTERCONNECT_MODE: "vsock",
    A402_ENCLAVE_CID: process.env.A402_ENCLAVE_CID || "16",
    A402_ENCLAVE_INGRESS_PORT: enclaveEnv.A402_ENCLAVE_INGRESS_PORT,
    A402_ENCLAVE_EGRESS_PORT: enclaveEnv.A402_ENCLAVE_EGRESS_PORT,
    A402_ENCLAVE_KMS_PORT: enclaveEnv.A402_ENCLAVE_KMS_PORT,
    A402_ENCLAVE_SNAPSHOT_PORT: enclaveEnv.A402_ENCLAVE_SNAPSHOT_PORT,
    A402_SNAPSHOT_DIR:
      process.env.A402_SNAPSHOT_DIR || "/var/lib/a402/snapshots",
    A402_KMS_REGION: awsRegion,
    A402_EGRESS_ALLOWLIST: process.env.A402_EGRESS_ALLOWLIST,
  };

  const runEnclaveConfig = {
    enclave_name: process.env.A402_NITRO_ENCLAVE_NAME || "a402-devnet-enclave",
    cpu_count: Number(process.env.A402_NITRO_CPU_COUNT || "2"),
    memory_mib: Number(process.env.A402_NITRO_MEMORY_MIB || "2048"),
    eif_path:
      process.env.A402_NITRO_EIF_PATH || "/opt/a402/enclave/a402-enclave.eif",
    enclave_cid: Number(parentEnv.A402_ENCLAVE_CID),
    debug_mode: process.env.A402_NITRO_DEBUG_MODE === "1",
  };

  const auditorMasterPubkeyHex = (
    process.env.A402_AUDITOR_MASTER_PUBKEY_HEX || "00".repeat(32)
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
    watchtowerKeypairB64: watchtowerEnv.A402_WATCHTOWER_KEYPAIR_B64,
    kmsKeyId,
    kmsKeyArnSha256,
    eifSigningCertSha256,
    snapshotDataKeyId,
    storageKeyMetadataKey: enclaveEnv.A402_STORAGE_KEY_METADATA_KEY,
    signerMinLamports,
    watchtowerMinLamports,
    auditorMasterPubkeyHex,
    protocol,
    awsRegion,
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
