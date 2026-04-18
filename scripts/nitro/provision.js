#!/usr/bin/env node

const path = require("path");

const {
  GENERATED_DIR,
  PLAN_PATH,
  anchor,
  computeAttestationPolicy,
  decodeHex32,
  ensureFunded,
  loadDefaultEnvFiles,
  loadMeasurements,
  loadProgram,
  loadProvider,
  parseArgs,
  readJson,
  saveJson,
  writeEnvFile,
} = require("./common");

function bytes32ToHex(value) {
  return Buffer.from(value).toString("hex");
}

async function main() {
  loadDefaultEnvFiles();
  const args = parseArgs(process.argv.slice(2));
  const planPath = args.plan || process.env.A402_NITRO_PLAN_PATH || PLAN_PATH;
  const measurementsPath =
    args.measurements ||
    process.env.A402_EIF_MEASUREMENTS_FILE ||
    path.join(GENERATED_DIR, "eif-measurements.json");
  const plan = readJson(planPath);
  const measurements = loadMeasurements(measurementsPath);
  const { policy, hashHex } = computeAttestationPolicy({
    measurements,
    eifSigningCertSha256: plan.eifSigningCertSha256,
    kmsKeyArnSha256: plan.kmsKeyArnSha256,
    protocol: plan.protocol,
  });

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);
  if (program.programId.toBase58() !== plan.programId) {
    throw new Error(
      `program id mismatch: plan=${
        plan.programId
      } current=${program.programId.toBase58()}`
    );
  }

  const vaultConfig = new anchor.web3.PublicKey(plan.vaultConfig);
  const vaultTokenAccount = new anchor.web3.PublicKey(plan.vaultTokenAccount);
  const vaultSignerPubkey = new anchor.web3.PublicKey(plan.vaultSignerPubkey);
  const usdcMint = new anchor.web3.PublicKey(plan.usdcMint);
  const accountInfo = await provider.connection.getAccountInfo(vaultConfig);
  let initialized = false;

  if (!accountInfo) {
    await program.methods
      .initializeVault(
        new anchor.BN(plan.vaultId),
        vaultSignerPubkey,
        decodeHex32(
          "A402_AUDITOR_MASTER_PUBKEY_HEX",
          plan.auditorMasterPubkeyHex
        ),
        decodeHex32("A402_ATTESTATION_POLICY_HASH_HEX", hashHex)
      )
      .accountsPartial({
        governance: provider.wallet.publicKey,
        vaultConfig,
        usdcMint,
        vaultTokenAccount,
        systemProgram: anchor.web3.SystemProgram.programId,
        tokenProgram: require("@solana/spl-token").TOKEN_PROGRAM_ID,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .rpc();
    initialized = true;
  }

  const onchainVault = await program.account.vaultConfig.fetch(vaultConfig);
  if (onchainVault.vaultSignerPubkey.toBase58() !== plan.vaultSignerPubkey) {
    throw new Error(
      `on-chain vault signer mismatch: expected ${
        plan.vaultSignerPubkey
      }, got ${onchainVault.vaultSignerPubkey.toBase58()}`
    );
  }
  if (onchainVault.usdcMint.toBase58() !== plan.usdcMint) {
    throw new Error(
      `on-chain USDC mint mismatch: expected ${
        plan.usdcMint
      }, got ${onchainVault.usdcMint.toBase58()}`
    );
  }
  const onchainPolicyHex = bytes32ToHex(onchainVault.attestationPolicyHash);
  if (onchainPolicyHex !== hashHex) {
    throw new Error(
      `on-chain attestation policy hash mismatch: expected ${hashHex}, got ${onchainPolicyHex}`
    );
  }

  await ensureFunded(
    provider,
    vaultSignerPubkey,
    Number(plan.signerMinLamports || 50000000)
  );
  await ensureFunded(
    provider,
    new anchor.web3.PublicKey(plan.watchtowerPubkey),
    Number(plan.watchtowerMinLamports || 50000000)
  );

  const policyPath = path.join(GENERATED_DIR, "attestation-policy.json");
  const policyHashPath = path.join(GENERATED_DIR, "attestation-policy.hash");
  const tfvarsPath = path.join(
    GENERATED_DIR,
    "terraform.attestation.auto.tfvars.json"
  );
  const statePath = path.join(GENERATED_DIR, "nitro-state.json");
  const clientEnvPath = path.join(GENERATED_DIR, "client.env");

  saveJson(policyPath, policy);
  saveJson(tfvarsPath, {
    aws_region: plan.awsRegion,
    kms_attestation_pcrs: policy.pcrs,
    kms_eif_signing_cert_sha256: plan.eifSigningCertSha256,
    kms_attestation_image_sha384: policy.pcrs["0"],
    kms_provisioner_principal_arns: process.env
      .A402_KMS_PROVISIONER_PRINCIPAL_ARN
      ? process.env.A402_KMS_PROVISIONER_PRINCIPAL_ARN.split(",").map((item) =>
          item.trim()
        )
      : [],
  });
  require("fs").writeFileSync(policyHashPath, `${hashHex}\n`);
  saveJson(statePath, {
    ...plan,
    attestationPolicyHashHex: hashHex,
    measurements,
    initialized,
    provisionedAt: new Date().toISOString(),
  });
  writeEnvFile(clientEnvPath, {
    A402_PROGRAM_ID: plan.programId,
    A402_VAULT_CONFIG: plan.vaultConfig,
    A402_VAULT_TOKEN_ACCOUNT: plan.vaultTokenAccount,
    A402_USDC_MINT: plan.usdcMint,
    A402_ATTESTATION_POLICY_HASH_HEX: hashHex,
    A402_PUBLIC_ENCLAVE_URL:
      process.env.A402_PUBLIC_ENCLAVE_URL || "https://replace-with-your-nlb",
  });

  console.log(
    JSON.stringify(
      {
        ok: true,
        stage: "provision",
        initialized,
        summary: {
          vaultConfig: plan.vaultConfig,
          vaultTokenAccount: plan.vaultTokenAccount,
          usdcMint: plan.usdcMint,
          attestationPolicyHashHex: hashHex,
          policyPath,
          tfvarsPath,
          clientEnvPath,
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
