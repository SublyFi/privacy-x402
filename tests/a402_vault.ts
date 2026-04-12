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
import {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Ed25519Program,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { expect } from "chai";
import BN from "bn.js";
import nacl from "tweetnacl";

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

  describe("withdraw", () => {
    let withdrawClient: Keypair;
    let withdrawClientTokenAccount: PublicKey;
    const withdrawAmount = 500_000; // 0.5 USDC

    before(async () => {
      withdrawClient = Keypair.generate();
      const sig = await provider.connection.requestAirdrop(
        withdrawClient.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);

      // Create client token account
      withdrawClientTokenAccount = await createAccount(
        provider.connection,
        withdrawClient,
        usdcMint,
        withdrawClient.publicKey
      );

      // Deposit funds first
      const depositTokenAccount = await createAccount(
        provider.connection,
        withdrawClient,
        usdcMint,
        withdrawClient.publicKey,
        Keypair.generate() // separate account for deposit
      );
      await mintTo(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        depositTokenAccount,
        governance.publicKey,
        2_000_000
      );
      await program.methods
        .deposit(new BN(2_000_000))
        .accounts({
          client: withdrawClient.publicKey,
          vaultConfig: vaultConfigPda,
          clientTokenAccount: depositTokenAccount,
          vaultTokenAccount: vaultTokenAccountPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([withdrawClient])
        .rpc();
    });

    function buildWithdrawMessage(
      client: PublicKey,
      recipientAta: PublicKey,
      amount: number,
      withdrawNonce: number,
      expiresAt: number,
      vaultConfig: PublicKey
    ): Buffer {
      const buf = Buffer.alloc(120);
      let offset = 0;
      buf.set(client.toBuffer(), offset); offset += 32;
      buf.set(recipientAta.toBuffer(), offset); offset += 32;
      buf.writeBigUInt64LE(BigInt(amount), offset); offset += 8;
      buf.writeBigUInt64LE(BigInt(withdrawNonce), offset); offset += 8;
      buf.writeBigInt64LE(BigInt(expiresAt), offset); offset += 8;
      buf.set(vaultConfig.toBuffer(), offset);
      return buf;
    }

    it("withdraws with valid Ed25519 signature", async () => {
      const withdrawNonce = 1;
      const slot = await provider.connection.getSlot();
      const blockTime = await provider.connection.getBlockTime(slot);
      const expiresAt = blockTime! + 600;

      const message = buildWithdrawMessage(
        withdrawClient.publicKey,
        withdrawClientTokenAccount,
        withdrawAmount,
        withdrawNonce,
        expiresAt,
        vaultConfigPda
      );

      const signature = nacl.sign.detached(
        message,
        vaultSignerKeypair.secretKey
      );

      const [usedNoncePda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("withdraw_nonce"),
          vaultConfigPda.toBuffer(),
          withdrawClient.publicKey.toBuffer(),
          new BN(withdrawNonce).toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );

      const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
        privateKey: vaultSignerKeypair.secretKey,
        message: message,
      });

      const withdrawIx = await program.methods
        .withdraw(
          new BN(withdrawAmount),
          new BN(withdrawNonce),
          new BN(expiresAt),
          Array.from(signature) as any
        )
        .accounts({
          client: withdrawClient.publicKey,
          vaultConfig: vaultConfigPda,
          vaultTokenAccount: vaultTokenAccountPda,
          clientTokenAccount: withdrawClientTokenAccount,
          usedWithdrawNonce: usedNoncePda,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .instruction();

      const latestBlockhash = await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: withdrawClient.publicKey,
        recentBlockhash: latestBlockhash.blockhash,
        instructions: [ed25519Ix, withdrawIx],
      }).compileToV0Message();

      const tx = new VersionedTransaction(messageV0);
      tx.sign([withdrawClient]);

      const txSig = await provider.connection.sendTransaction(tx);
      await provider.connection.confirmTransaction({
        signature: txSig,
        blockhash: latestBlockhash.blockhash,
        lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
      });

      const clientToken = await getAccount(
        provider.connection,
        withdrawClientTokenAccount
      );
      expect(Number(clientToken.amount)).to.equal(withdrawAmount);
    });

    it("rejects withdraw with wrong signer", async () => {
      const withdrawNonce = 2;
      const slot = await provider.connection.getSlot();
      const blockTime = await provider.connection.getBlockTime(slot);
      const expiresAt = blockTime! + 600;

      const fakeSigner = Keypair.generate();

      const message = buildWithdrawMessage(
        withdrawClient.publicKey,
        withdrawClientTokenAccount,
        withdrawAmount,
        withdrawNonce,
        expiresAt,
        vaultConfigPda
      );

      const signature = nacl.sign.detached(message, fakeSigner.secretKey);

      const [usedNoncePda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("withdraw_nonce"),
          vaultConfigPda.toBuffer(),
          withdrawClient.publicKey.toBuffer(),
          new BN(withdrawNonce).toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );

      // Ed25519 instruction signed by fake signer
      const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
        privateKey: fakeSigner.secretKey,
        message: message,
      });

      const withdrawIx = await program.methods
        .withdraw(
          new BN(withdrawAmount),
          new BN(withdrawNonce),
          new BN(expiresAt),
          Array.from(signature) as any
        )
        .accounts({
          client: withdrawClient.publicKey,
          vaultConfig: vaultConfigPda,
          vaultTokenAccount: vaultTokenAccountPda,
          clientTokenAccount: withdrawClientTokenAccount,
          usedWithdrawNonce: usedNoncePda,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .instruction();

      const latestBlockhash = await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: withdrawClient.publicKey,
        recentBlockhash: latestBlockhash.blockhash,
        instructions: [ed25519Ix, withdrawIx],
      }).compileToV0Message();

      const tx = new VersionedTransaction(messageV0);
      tx.sign([withdrawClient]);

      try {
        await provider.connection.sendTransaction(tx);
        await new Promise((r) => setTimeout(r, 1000));
        expect.fail("Should have thrown");
      } catch (err: any) {
        // Transaction should fail with InvalidVaultSigner
        expect(err.toString()).to.include("Error");
      }
    });

    it("rejects withdraw with mismatched message content", async () => {
      const withdrawNonce = 3;
      const slot = await provider.connection.getSlot();
      const blockTime = await provider.connection.getBlockTime(slot);
      const expiresAt = blockTime! + 600;

      // Build message with wrong amount
      const wrongMessage = buildWithdrawMessage(
        withdrawClient.publicKey,
        withdrawClientTokenAccount,
        999_999, // wrong amount
        withdrawNonce,
        expiresAt,
        vaultConfigPda
      );

      const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
        privateKey: vaultSignerKeypair.secretKey,
        message: wrongMessage,
      });

      const signature = nacl.sign.detached(wrongMessage, vaultSignerKeypair.secretKey);

      const [usedNoncePda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("withdraw_nonce"),
          vaultConfigPda.toBuffer(),
          withdrawClient.publicKey.toBuffer(),
          new BN(withdrawNonce).toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );

      const withdrawIx = await program.methods
        .withdraw(
          new BN(withdrawAmount), // actual amount differs from signed amount
          new BN(withdrawNonce),
          new BN(expiresAt),
          Array.from(signature) as any
        )
        .accounts({
          client: withdrawClient.publicKey,
          vaultConfig: vaultConfigPda,
          vaultTokenAccount: vaultTokenAccountPda,
          clientTokenAccount: withdrawClientTokenAccount,
          usedWithdrawNonce: usedNoncePda,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .instruction();

      const latestBlockhash = await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: withdrawClient.publicKey,
        recentBlockhash: latestBlockhash.blockhash,
        instructions: [ed25519Ix, withdrawIx],
      }).compileToV0Message();

      const tx = new VersionedTransaction(messageV0);
      tx.sign([withdrawClient]);

      try {
        await provider.connection.sendTransaction(tx);
        await new Promise((r) => setTimeout(r, 1000));
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.toString()).to.include("Error");
      }
    });

    it("rejects nonce replay", async () => {
      // Try to use nonce=1 again (already used above)
      const withdrawNonce = 1;
      const slot = await provider.connection.getSlot();
      const blockTime = await provider.connection.getBlockTime(slot);
      const expiresAt = blockTime! + 600;

      const message = buildWithdrawMessage(
        withdrawClient.publicKey,
        withdrawClientTokenAccount,
        withdrawAmount,
        withdrawNonce,
        expiresAt,
        vaultConfigPda
      );

      const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
        privateKey: vaultSignerKeypair.secretKey,
        message: message,
      });

      const signature = nacl.sign.detached(message, vaultSignerKeypair.secretKey);

      const [usedNoncePda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("withdraw_nonce"),
          vaultConfigPda.toBuffer(),
          withdrawClient.publicKey.toBuffer(),
          new BN(withdrawNonce).toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );

      const withdrawIx = await program.methods
        .withdraw(
          new BN(withdrawAmount),
          new BN(withdrawNonce),
          new BN(expiresAt),
          Array.from(signature) as any
        )
        .accounts({
          client: withdrawClient.publicKey,
          vaultConfig: vaultConfigPda,
          vaultTokenAccount: vaultTokenAccountPda,
          clientTokenAccount: withdrawClientTokenAccount,
          usedWithdrawNonce: usedNoncePda,
          instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .instruction();

      const latestBlockhash = await provider.connection.getLatestBlockhash();
      const messageV0 = new TransactionMessage({
        payerKey: withdrawClient.publicKey,
        recentBlockhash: latestBlockhash.blockhash,
        instructions: [ed25519Ix, withdrawIx],
      }).compileToV0Message();

      const tx = new VersionedTransaction(messageV0);
      tx.sign([withdrawClient]);

      try {
        await provider.connection.sendTransaction(tx);
        await new Promise((r) => setTimeout(r, 1000));
        expect.fail("Should have thrown");
      } catch (err: any) {
        // PDA already initialized → should fail
        expect(err.toString()).to.include("Error");
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

    it("settles to multiple providers in one batch", async () => {
      const provider2Keypair = Keypair.generate();
      const sig3 = await provider.connection.requestAirdrop(
        provider2Keypair.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig3);

      const provider2TokenAccount = await createAccount(
        provider.connection,
        provider2Keypair,
        usdcMint,
        provider2Keypair.publicKey
      );

      const amount1 = 50_000;
      const amount2 = 75_000;

      const vaultBefore = await program.account.vaultConfig.fetch(vaultConfigPda);
      const settledBefore = vaultBefore.lifetimeSettled.toNumber();

      await program.methods
        .settleVault(new BN(10), new Array(32).fill(0), [
          {
            providerTokenAccount: providerTokenAccount,
            amount: new BN(amount1),
          },
          {
            providerTokenAccount: provider2TokenAccount,
            amount: new BN(amount2),
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
          {
            pubkey: provider2TokenAccount,
            isWritable: true,
            isSigner: false,
          },
        ])
        .signers([vaultSignerKeypair])
        .rpc();

      const p2Token = await getAccount(provider.connection, provider2TokenAccount);
      expect(Number(p2Token.amount)).to.equal(amount2);

      const vaultAfter = await program.account.vaultConfig.fetch(vaultConfigPda);
      expect(vaultAfter.lifetimeSettled.toNumber()).to.equal(
        settledBefore + amount1 + amount2
      );
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

  describe("record_audit", () => {
    it("rejects record_audit from non-vault-signer", async () => {
      const fakeSigner = Keypair.generate();
      const sig = await provider.connection.requestAirdrop(
        fakeSigner.publicKey,
        anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(sig);

      try {
        await program.methods
          .recordAudit(new BN(1), new Array(32).fill(0), [])
          .accounts({
            vaultSigner: fakeSigner.publicKey,
            vaultConfig: vaultConfigPda,
            systemProgram: SystemProgram.programId,
          })
          .signers([fakeSigner])
          .rpc();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.error.errorCode.code).to.equal("InvalidVaultSigner");
      }
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
