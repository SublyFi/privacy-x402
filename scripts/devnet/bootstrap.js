#!/usr/bin/env node

const anchor = require("@coral-xyz/anchor");
const { createMint, TOKEN_PROGRAM_ID } = require("@solana/spl-token");

const {
  decodeHex32,
  deriveVaultAddresses,
  fundAccount,
  keypairFromSeedBase64,
  loadDefaultEnvFiles,
  loadProgram,
  loadProvider,
  loadState,
  randomSeedBase64,
  saveState,
  writeGeneratedEnv,
} = require("./common");

async function main() {
  loadDefaultEnvFiles();

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);

  const existingState = loadState() || {};
  let vaultId = BigInt(
    process.env.SUBLY402_VAULT_ID || existingState.vaultId || "1"
  );
  const enclaveSignerSeedBase64 =
    process.env.SUBLY402_VAULT_SIGNER_SECRET_KEY_B64 ||
    existingState.enclaveSignerSeedBase64 ||
    randomSeedBase64();
  const enclaveSigner = keypairFromSeedBase64(enclaveSignerSeedBase64);
  const auditorMasterPubkeyHex =
    process.env.SUBLY402_AUDITOR_MASTER_PUBKEY_HEX ||
    existingState.auditorMasterPubkeyHex ||
    "00".repeat(32);
  const attestationPolicyHashHex =
    process.env.SUBLY402_ATTESTATION_POLICY_HASH_HEX ||
    existingState.attestationPolicyHashHex ||
    "00".repeat(32);
  let usdcMintBase58 =
    process.env.SUBLY402_USDC_MINT || existingState.usdcMint || null;
  let { vaultConfigPda, vaultTokenAccountPda, vaultIdBn } =
    deriveVaultAddresses(provider.wallet.publicKey, vaultId, program.programId);
  let vaultConfigInfo = await provider.connection.getAccountInfo(
    vaultConfigPda
  );
  let existingVaultConfig = vaultConfigInfo
    ? await program.account.vaultConfig.fetch(vaultConfigPda)
    : null;

  while (
    existingVaultConfig &&
    existingVaultConfig.vaultSignerPubkey.toBase58() !==
      enclaveSigner.publicKey.toBase58() &&
    process.env.SUBLY402_REUSE_EXISTING_VAULT !== "1"
  ) {
    usdcMintBase58 = usdcMintBase58 || existingVaultConfig.usdcMint.toBase58();
    vaultId += 1n;
    ({ vaultConfigPda, vaultTokenAccountPda, vaultIdBn } = deriveVaultAddresses(
      provider.wallet.publicKey,
      vaultId,
      program.programId
    ));
    vaultConfigInfo = await provider.connection.getAccountInfo(vaultConfigPda);
    existingVaultConfig = vaultConfigInfo
      ? await program.account.vaultConfig.fetch(vaultConfigPda)
      : null;
  }

  if (!vaultConfigInfo && !usdcMintBase58) {
    const mint = await createMint(
      provider.connection,
      provider.wallet.payer,
      provider.wallet.publicKey,
      null,
      6
    );
    usdcMintBase58 = mint.toBase58();
  }

  if (vaultConfigInfo && !usdcMintBase58) {
    usdcMintBase58 = existingVaultConfig.usdcMint.toBase58();
  }

  if (!usdcMintBase58) {
    throw new Error("SUBLY402_USDC_MINT could not be resolved");
  }

  let initialized = false;
  if (!vaultConfigInfo) {
    await program.methods
      .initializeVault(
        vaultIdBn,
        enclaveSigner.publicKey,
        decodeHex32(
          "SUBLY402_AUDITOR_MASTER_PUBKEY_HEX",
          auditorMasterPubkeyHex
        ),
        decodeHex32(
          "SUBLY402_ATTESTATION_POLICY_HASH_HEX",
          attestationPolicyHashHex
        )
      )
      .accountsPartial({
        governance: provider.wallet.publicKey,
        vaultConfig: vaultConfigPda,
        usdcMint: new anchor.web3.PublicKey(usdcMintBase58),
        vaultTokenAccount: vaultTokenAccountPda,
        systemProgram: anchor.web3.SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .rpc();
    initialized = true;
  }

  const vaultConfig = await program.account.vaultConfig.fetch(vaultConfigPda);
  const signerMinLamports = Number(
    process.env.SUBLY402_VAULT_SIGNER_MIN_LAMPORTS || "50000000"
  );
  const signerBalance = await provider.connection.getBalance(
    enclaveSigner.publicKey
  );
  if (signerBalance < signerMinLamports) {
    await fundAccount(
      provider,
      enclaveSigner.publicKey,
      signerMinLamports - signerBalance
    );
  }

  const state = {
    vaultId: vaultId.toString(),
    programId: program.programId.toBase58(),
    governance: provider.wallet.publicKey.toBase58(),
    rpcUrl: provider.connection.rpcEndpoint,
    wsUrl: process.env.SUBLY402_SOLANA_WS_URL || existingState.wsUrl || "",
    usdcMint: vaultConfig.usdcMint.toBase58(),
    vaultConfig: vaultConfigPda.toBase58(),
    vaultTokenAccount: vaultConfig.vaultTokenAccount.toBase58(),
    vaultSignerPubkey: vaultConfig.vaultSignerPubkey.toBase58(),
    enclaveSignerSeedBase64,
    auditorMasterPubkeyHex: auditorMasterPubkeyHex.toLowerCase(),
    attestationPolicyHashHex: attestationPolicyHashHex.toLowerCase(),
  };
  saveState(state);
  writeGeneratedEnv({
    SUBLY402_PROGRAM_ID: state.programId,
    SUBLY402_VAULT_CONFIG: state.vaultConfig,
    SUBLY402_VAULT_TOKEN_ACCOUNT: state.vaultTokenAccount,
    SUBLY402_USDC_MINT: state.usdcMint,
    SUBLY402_ATTESTATION_POLICY_HASH_HEX: state.attestationPolicyHashHex,
    SUBLY402_VAULT_SIGNER_SECRET_KEY_B64: state.enclaveSignerSeedBase64,
    SUBLY402_WAL_PATH: "data/wal-devnet.jsonl",
    SUBLY402_WATCHTOWER_URL: "http://127.0.0.1:3200",
    SUBLY402_TEST_ENCLAVE_URL: "http://127.0.0.1:3100",
  });

  console.log(
    JSON.stringify(
      {
        ok: true,
        initialized,
        stateFile: "data/devnet-state.json",
        envFile: ".env.devnet.generated",
        summary: {
          programId: state.programId,
          vaultConfig: state.vaultConfig,
          vaultTokenAccount: state.vaultTokenAccount,
          usdcMint: state.usdcMint,
          vaultSignerPubkey: state.vaultSignerPubkey,
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
