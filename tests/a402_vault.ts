import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { A402Vault } from "../target/types/a402_vault";
import {
  createMint,
  createAccount,
  mintTo,
  getAccount,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { Keypair, PublicKey, SystemProgram, SYSVAR_INSTRUCTIONS_PUBKEY } from "@solana/web3.js";
import { expect } from "chai";
import BN from "bn.js";

describe("a402_vault", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.a402Vault as Program<A402Vault>;
  const governance = provider.wallet as anchor.Wallet;

  let usdcMint: PublicKey;
  let vaultConfigPda: PublicKey;
  let vaultConfigBump: number;
  let vaultTokenAccountPda: PublicKey;
  const vaultId = new BN(1);
  const vaultSignerKeypair = Keypair.generate();

  const auditorMasterPubkey = new Array(32).fill(0);
  const attestationPolicyHash = new Array(32).fill(1);

  before(async () => {
    // Create USDC mint
    usdcMint = await createMint(
      provider.connection,
      (governance as any).payer,
      governance.publicKey,
      null,
      6
    );

    // Derive PDAs
    [vaultConfigPda, vaultConfigBump] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("vault_config"),
        governance.publicKey.toBuffer(),
        vaultId.toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    [vaultTokenAccountPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault_token"), vaultConfigPda.toBuffer()],
      program.programId
    );
  });

  describe("initialize_vault", () => {
    it("initializes vault correctly", async () => {
      await program.methods
        .initializeVault(
          vaultId,
          vaultSignerKeypair.publicKey,
          auditorMasterPubkey,
          attestationPolicyHash
        )
        .accounts({
          governance: governance.publicKey,
          vaultConfig: vaultConfigPda,
          usdcMint: usdcMint,
          vaultTokenAccount: vaultTokenAccountPda,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();

      const vault = await program.account.vaultConfig.fetch(vaultConfigPda);
      expect(vault.vaultId.toNumber()).to.equal(1);
      expect(vault.governance.toBase58()).to.equal(governance.publicKey.toBase58());
      expect(vault.status).to.equal(0); // Active
      expect(vault.vaultSignerPubkey.toBase58()).to.equal(
        vaultSignerKeypair.publicKey.toBase58()
      );
      expect(vault.usdcMint.toBase58()).to.equal(usdcMint.toBase58());
      expect(vault.auditorEpoch).to.equal(0);
      expect(vault.lifetimeDeposited.toNumber()).to.equal(0);
      expect(vault.lifetimeWithdrawn.toNumber()).to.equal(0);
      expect(vault.lifetimeSettled.toNumber()).to.equal(0);
    });
  });

  describe("deposit", () => {
    let clientKeypair: Keypair;
    let clientTokenAccount: PublicKey;
    const depositAmount = 1_000_000; // 1 USDC

    before(async () => {
      clientKeypair = Keypair.generate();

      // Airdrop SOL to client
      const sig = await provider.connection.requestAirdrop(
        clientKeypair.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);

      // Create client token account
      clientTokenAccount = await createAccount(
        provider.connection,
        clientKeypair,
        usdcMint,
        clientKeypair.publicKey
      );

      // Mint USDC to client
      await mintTo(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        clientTokenAccount,
        governance.publicKey,
        depositAmount * 10
      );
    });

    it("deposits USDC into vault", async () => {
      await program.methods
        .deposit(new BN(depositAmount))
        .accounts({
          client: clientKeypair.publicKey,
          vaultConfig: vaultConfigPda,
          clientTokenAccount: clientTokenAccount,
          vaultTokenAccount: vaultTokenAccountPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([clientKeypair])
        .rpc();

      const vaultToken = await getAccount(provider.connection, vaultTokenAccountPda);
      expect(Number(vaultToken.amount)).to.equal(depositAmount);

      const vault = await program.account.vaultConfig.fetch(vaultConfigPda);
      expect(vault.lifetimeDeposited.toNumber()).to.equal(depositAmount);
    });

    it("rejects zero deposit", async () => {
      try {
        await program.methods
          .deposit(new BN(0))
          .accounts({
            client: clientKeypair.publicKey,
            vaultConfig: vaultConfigPda,
            clientTokenAccount: clientTokenAccount,
            vaultTokenAccount: vaultTokenAccountPda,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([clientKeypair])
          .rpc();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.error.errorCode.code).to.equal("InvalidAmount");
      }
    });
  });

  describe("settle_vault", () => {
    let providerKeypair: Keypair;
    let providerTokenAccount: PublicKey;
    let clientKeypair: Keypair;
    let clientTokenAccount: PublicKey;
    const settleAmount = 100_000; // 0.1 USDC

    before(async () => {
      // Create provider
      providerKeypair = Keypair.generate();
      const sig = await provider.connection.requestAirdrop(
        providerKeypair.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);

      providerTokenAccount = await createAccount(
        provider.connection,
        providerKeypair,
        usdcMint,
        providerKeypair.publicKey
      );

      // Deposit more funds to vault
      clientKeypair = Keypair.generate();
      const sig2 = await provider.connection.requestAirdrop(
        clientKeypair.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig2);

      clientTokenAccount = await createAccount(
        provider.connection,
        clientKeypair,
        usdcMint,
        clientKeypair.publicKey
      );

      await mintTo(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        clientTokenAccount,
        governance.publicKey,
        5_000_000
      );

      await program.methods
        .deposit(new BN(5_000_000))
        .accounts({
          client: clientKeypair.publicKey,
          vaultConfig: vaultConfigPda,
          clientTokenAccount: clientTokenAccount,
          vaultTokenAccount: vaultTokenAccountPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([clientKeypair])
        .rpc();
    });

    it("settles vault with vault signer", async () => {
      const batchId = new BN(1);
      const batchChunkHash = new Array(32).fill(0);

      await program.methods
        .settleVault(batchId, batchChunkHash, [
          {
            providerTokenAccount: providerTokenAccount,
            amount: new BN(settleAmount),
          },
        ])
        .accounts({
          vaultSigner: vaultSignerKeypair.publicKey,
          vaultConfig: vaultConfigPda,
          vaultTokenAccount: vaultTokenAccountPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .remainingAccounts([
          {
            pubkey: providerTokenAccount,
            isWritable: true,
            isSigner: false,
          },
        ])
        .signers([vaultSignerKeypair])
        .rpc();

      const providerToken = await getAccount(
        provider.connection,
        providerTokenAccount
      );
      expect(Number(providerToken.amount)).to.equal(settleAmount);

      const vault = await program.account.vaultConfig.fetch(vaultConfigPda);
      expect(vault.lifetimeSettled.toNumber()).to.equal(settleAmount);
    });

    it("rejects settlement from non-vault-signer", async () => {
      const fakeSigner = Keypair.generate();
      const sig = await provider.connection.requestAirdrop(
        fakeSigner.publicKey,
        anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);

      try {
        await program.methods
          .settleVault(new BN(2), new Array(32).fill(0), [
            {
              providerTokenAccount: providerTokenAccount,
              amount: new BN(1000),
            },
          ])
          .accounts({
            vaultSigner: fakeSigner.publicKey,
            vaultConfig: vaultConfigPda,
            vaultTokenAccount: vaultTokenAccountPda,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .remainingAccounts([
            {
              pubkey: providerTokenAccount,
              isWritable: true,
              isSigner: false,
            },
          ])
          .signers([fakeSigner])
          .rpc();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.error.errorCode.code).to.equal("InvalidVaultSigner");
      }
    });
  });

  describe("pause_vault", () => {
    // Use a separate vault for pause tests
    let pauseVaultConfigPda: PublicKey;
    let pauseVaultTokenPda: PublicKey;
    const pauseVaultId = new BN(100);

    before(async () => {
      [pauseVaultConfigPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("vault_config"),
          governance.publicKey.toBuffer(),
          pauseVaultId.toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );
      [pauseVaultTokenPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault_token"), pauseVaultConfigPda.toBuffer()],
        program.programId
      );

      await program.methods
        .initializeVault(
          pauseVaultId,
          vaultSignerKeypair.publicKey,
          auditorMasterPubkey,
          attestationPolicyHash
        )
        .accounts({
          governance: governance.publicKey,
          vaultConfig: pauseVaultConfigPda,
          usdcMint: usdcMint,
          vaultTokenAccount: pauseVaultTokenPda,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();
    });

    it("pauses an active vault", async () => {
      await program.methods
        .pauseVault()
        .accounts({
          governance: governance.publicKey,
          vaultConfig: pauseVaultConfigPda,
        })
        .rpc();

      const vault = await program.account.vaultConfig.fetch(pauseVaultConfigPda);
      expect(vault.status).to.equal(1); // Paused
    });

    it("rejects deposit on paused vault", async () => {
      const clientKeypair = Keypair.generate();
      const sig = await provider.connection.requestAirdrop(
        clientKeypair.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);

      const clientTokenAccount = await createAccount(
        provider.connection,
        clientKeypair,
        usdcMint,
        clientKeypair.publicKey
      );

      await mintTo(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        clientTokenAccount,
        governance.publicKey,
        1_000_000
      );

      try {
        await program.methods
          .deposit(new BN(1_000_000))
          .accounts({
            client: clientKeypair.publicKey,
            vaultConfig: pauseVaultConfigPda,
            clientTokenAccount: clientTokenAccount,
            vaultTokenAccount: pauseVaultTokenPda,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .signers([clientKeypair])
          .rpc();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.error.errorCode.code).to.equal("VaultInactive");
      }
    });
  });

  describe("announce_migration", () => {
    let migrateVaultConfigPda: PublicKey;
    let migrateVaultTokenPda: PublicKey;
    const migrateVaultId = new BN(200);
    const successorVault = Keypair.generate().publicKey;

    before(async () => {
      [migrateVaultConfigPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("vault_config"),
          governance.publicKey.toBuffer(),
          migrateVaultId.toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );
      [migrateVaultTokenPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault_token"), migrateVaultConfigPda.toBuffer()],
        program.programId
      );

      await program.methods
        .initializeVault(
          migrateVaultId,
          vaultSignerKeypair.publicKey,
          auditorMasterPubkey,
          attestationPolicyHash
        )
        .accounts({
          governance: governance.publicKey,
          vaultConfig: migrateVaultConfigPda,
          usdcMint: usdcMint,
          vaultTokenAccount: migrateVaultTokenPda,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();
    });

    it("announces migration", async () => {
      const clock = await provider.connection.getSlot();
      const blockTime = await provider.connection.getBlockTime(clock);
      const exitDeadline = new BN(blockTime! + 3600); // 1 hour from now

      await program.methods
        .announceMigration(successorVault, exitDeadline)
        .accounts({
          governance: governance.publicKey,
          vaultConfig: migrateVaultConfigPda,
        })
        .rpc();

      const vault = await program.account.vaultConfig.fetch(migrateVaultConfigPda);
      expect(vault.status).to.equal(2); // Migrating
      expect(vault.successorVault.toBase58()).to.equal(successorVault.toBase58());
    });
  });

  describe("rotate_auditor", () => {
    it("rotates auditor key", async () => {
      const newAuditorPubkey = new Array(32).fill(42);

      await program.methods
        .rotateAuditor(newAuditorPubkey)
        .accounts({
          governance: governance.publicKey,
          vaultConfig: vaultConfigPda,
        })
        .rpc();

      const vault = await program.account.vaultConfig.fetch(vaultConfigPda);
      expect(vault.auditorEpoch).to.equal(1);
      expect(vault.auditorMasterPubkey).to.deep.equal(newAuditorPubkey);
    });
  });

  describe("retire_vault", () => {
    let retireVaultConfigPda: PublicKey;
    let retireVaultTokenPda: PublicKey;
    const retireVaultId = new BN(300);

    before(async () => {
      [retireVaultConfigPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("vault_config"),
          governance.publicKey.toBuffer(),
          retireVaultId.toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );
      [retireVaultTokenPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault_token"), retireVaultConfigPda.toBuffer()],
        program.programId
      );

      await program.methods
        .initializeVault(
          retireVaultId,
          vaultSignerKeypair.publicKey,
          auditorMasterPubkey,
          attestationPolicyHash
        )
        .accounts({
          governance: governance.publicKey,
          vaultConfig: retireVaultConfigPda,
          usdcMint: usdcMint,
          vaultTokenAccount: retireVaultTokenPda,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();
    });

    it("retires a paused vault", async () => {
      // First pause
      await program.methods
        .pauseVault()
        .accounts({
          governance: governance.publicKey,
          vaultConfig: retireVaultConfigPda,
        })
        .rpc();

      // Then retire
      await program.methods
        .retireVault()
        .accounts({
          governance: governance.publicKey,
          vaultConfig: retireVaultConfigPda,
        })
        .rpc();

      const vault = await program.account.vaultConfig.fetch(retireVaultConfigPda);
      expect(vault.status).to.equal(3); // Retired
    });

    it("rejects retire on active vault", async () => {
      // Create another vault
      const activeVaultId = new BN(301);
      const [activeVaultPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("vault_config"),
          governance.publicKey.toBuffer(),
          activeVaultId.toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );
      const [activeVaultTokenPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault_token"), activeVaultPda.toBuffer()],
        program.programId
      );

      await program.methods
        .initializeVault(
          activeVaultId,
          vaultSignerKeypair.publicKey,
          auditorMasterPubkey,
          attestationPolicyHash
        )
        .accounts({
          governance: governance.publicKey,
          vaultConfig: activeVaultPda,
          usdcMint: usdcMint,
          vaultTokenAccount: activeVaultTokenPda,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();

      try {
        await program.methods
          .retireVault()
          .accounts({
            governance: governance.publicKey,
            vaultConfig: activeVaultPda,
          })
          .rpc();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.error.errorCode.code).to.equal("InvalidStatusTransition");
      }
    });
  });
});
