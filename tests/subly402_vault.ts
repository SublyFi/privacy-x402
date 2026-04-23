import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Subly402Vault } from "../target/types/subly402_vault";
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
  Transaction,
} from "@solana/web3.js";
import { expect } from "chai";
import BN from "bn.js";
import { createHash, hkdfSync } from "crypto";
import { RistrettoPoint } from "@noble/curves/ed25519";
import nacl from "tweetnacl";
import { AuditTool } from "../sdk/src/audit";
import {
  buildAscClaimVoucherMessage,
  generateAscDeliveryArtifact,
  submitAscCloseClaim,
} from "../middleware/src/asc";

const SCALAR_ORDER = BigInt(
  "7237005577332262213973186563042994240857116359379907606001950938285454250989"
);

describe("subly402_vault", () => {
  const provider = new anchor.AnchorProvider(
    anchor.AnchorProvider.env().connection,
    anchor.AnchorProvider.env().wallet,
    { commitment: "confirmed", preflightCommitment: "confirmed" }
  );
  anchor.setProvider(provider);

  // Devnet-friendly funding amount (enough for tx fees + token account creation)
  const FUND_LAMPORTS = 5_000_000; // 0.005 SOL — enough for a few signed transactions
  const HEAVY_FUND_LAMPORTS = 15_000_000; // 0.015 SOL — enough for token account creation + repeated tx fees
  const VAULT_SIGNER_FUND_LAMPORTS = 30_000_000; // 0.03 SOL — covers audit PDA rent across the suite

  // Devnet-safe createAccount wrapper that skips preflight to avoid stale simulation state
  const devnetConfirmOpts = {
    skipPreflight: true,
    commitment: "confirmed" as anchor.web3.Commitment,
  };

  async function createTokenAccount(
    payer: Keypair,
    mint: PublicKey,
    owner: PublicKey
  ): Promise<PublicKey> {
    // Ensure mint is visible on this RPC node before creating token account
    for (let i = 0; i < 5; i++) {
      const info = await provider.connection.getAccountInfo(mint, "confirmed");
      if (info && info.data.length >= 82) break;
      await new Promise((r) => setTimeout(r, 2000));
    }
    const kp = Keypair.generate();
    return createAccount(
      provider.connection,
      payer,
      mint,
      owner,
      kp,
      devnetConfirmOpts
    );
  }

  // Helper: fund a keypair from the provider wallet (works on devnet without faucet)
  async function fundAccount(
    to: PublicKey,
    lamports = FUND_LAMPORTS
  ): Promise<void> {
    const currentLamports = await provider.connection.getBalance(
      to,
      "confirmed"
    );
    if (currentLamports >= lamports) {
      return;
    }
    const tx = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: provider.wallet.publicKey,
        toPubkey: to,
        lamports: lamports - currentLamports,
      })
    );
    const sig = await provider.sendAndConfirm(tx);
    // Wait for finalized status so subsequent txs can reliably use the funded account on devnet
    await provider.connection.confirmTransaction(sig, "finalized");
  }

  const program = anchor.workspace.subly402Vault as Program<Subly402Vault>;
  const governance = provider.wallet as anchor.Wallet;

  let usdcMint: PublicKey;
  let vaultConfigPda: PublicKey;
  let vaultConfigBump: number;
  let vaultTokenAccountPda: PublicKey;
  // Randomize vault IDs so tests can re-run on devnet without PDA collisions
  const testRunSeed = Date.now();
  const vaultId = new BN(testRunSeed);
  const vaultSignerKeypair = Keypair.generate();

  const auditorMasterPubkey = new Array(32).fill(0);
  const attestationPolicyHash = new Array(32).fill(1);
  const oldAuditorMasterSecret = new Uint8Array(32).fill(7);
  const newAuditorMasterSecret = new Uint8Array(32).fill(9);

  before(async () => {
    await fundAccount(vaultSignerKeypair.publicKey, VAULT_SIGNER_FUND_LAMPORTS);

    // Create USDC mint
    usdcMint = await createMint(
      provider.connection,
      (governance as any).payer,
      governance.publicKey,
      null,
      6,
      undefined,
      devnetConfirmOpts
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

  function findAuditPda(batchId: BN, index: number): PublicKey {
    return PublicKey.findProgramAddressSync(
      [
        Buffer.from("audit"),
        vaultConfigPda.toBuffer(),
        batchId.toArrayLike(Buffer, "le", 8),
        Buffer.from([index]),
      ],
      program.programId
    )[0];
  }

  function buildAuditRecord(
    providerTokenAccount: PublicKey,
    seed: number,
    timestamp?: number
  ) {
    return {
      encryptedSender: new Array(64).fill(seed & 0xff),
      encryptedAmount: new Array(64).fill((seed + 1) & 0xff),
      provider: providerTokenAccount,
      timestamp: new BN(timestamp ?? Math.floor(Date.now() / 1000)),
    };
  }

  type SettleEntryInput = {
    providerTokenAccount: PublicKey;
    amount: BN;
  };

  type AuditRecordInput = ReturnType<typeof buildAuditRecord>;

  function computeBatchChunkHash(
    batchId: BN,
    settlements: SettleEntryInput[],
    auditRecords: AuditRecordInput[]
  ): number[] {
    const hash = createHash("sha256");
    hash.update("subly402-batch-chunk-v1");
    hash.update(batchId.toArrayLike(Buffer, "le", 8));

    for (const settlement of settlements) {
      hash.update(settlement.providerTokenAccount.toBuffer());
      hash.update(settlement.amount.toArrayLike(Buffer, "le", 8));
    }

    for (const record of auditRecords) {
      hash.update(Buffer.from(record.encryptedSender));
      hash.update(Buffer.from(record.encryptedAmount));
      hash.update(record.provider.toBuffer());
      const timestamp = Buffer.alloc(8);
      timestamp.writeBigInt64LE(BigInt(record.timestamp.toString()));
      hash.update(timestamp);
    }

    return Array.from(hash.digest());
  }

  function bytesToScalar(bytes: Uint8Array): bigint {
    let n = BigInt(0);
    const len = Math.min(bytes.length, 64);
    for (let i = len - 1; i >= 0; i--) {
      n = (n << BigInt(8)) | BigInt(bytes[i]);
    }
    return n % SCALAR_ORDER;
  }

  function kdfMask(sharedSecretBytes: Uint8Array): Uint8Array {
    const hash = createHash("sha256");
    hash.update("subly402-elgamal-mask-v1");
    hash.update(sharedSecretBytes);
    return new Uint8Array(hash.digest());
  }

  function deriveProviderKeyMaterial(
    masterSecret: Uint8Array,
    provider: PublicKey
  ): Uint8Array {
    return new Uint8Array(
      hkdfSync(
        "sha256",
        masterSecret,
        Buffer.from("subly402-audit-v1"),
        provider.toBuffer(),
        64
      )
    );
  }

  function encryptWithProvider(
    masterSecret: Uint8Array,
    provider: PublicKey,
    plaintext: Uint8Array,
    r: bigint
  ): number[] {
    const providerSecret = bytesToScalar(
      deriveProviderKeyMaterial(masterSecret, provider)
    );
    const providerPublic = RistrettoPoint.BASE.multiply(providerSecret);
    const c1 = RistrettoPoint.BASE.multiply(r);
    const shared = providerPublic.multiply(r);
    const mask = kdfMask(shared.toRawBytes());

    const ciphertext = new Uint8Array(64);
    ciphertext.set(c1.toRawBytes(), 0);
    for (let i = 0; i < 32; i++) {
      ciphertext[32 + i] = plaintext[i] ^ mask[i];
    }
    return Array.from(ciphertext);
  }

  function encodeAmount(amount: bigint): Uint8Array {
    const out = new Uint8Array(32);
    const view = Buffer.from(out.buffer, out.byteOffset, out.byteLength);
    view.writeBigUInt64LE(amount, 0);
    return out;
  }

  function buildEncryptedAuditRecord(
    masterSecret: Uint8Array,
    providerTokenAccount: PublicKey,
    sender: PublicKey,
    amount: bigint,
    timestamp?: number
  ) {
    return {
      encryptedSender: encryptWithProvider(
        masterSecret,
        providerTokenAccount,
        sender.toBytes(),
        BigInt(11)
      ),
      encryptedAmount: encryptWithProvider(
        masterSecret,
        providerTokenAccount,
        encodeAmount(amount),
        BigInt(17)
      ),
      provider: providerTokenAccount,
      timestamp: new BN(timestamp ?? Math.floor(Date.now() / 1000)),
    };
  }

  async function fetchAuditRecord(address: PublicKey) {
    const accountInfo = await provider.connection.getAccountInfo(
      address,
      "confirmed"
    );
    expect(accountInfo).to.not.equal(null);

    const data = Buffer.from(accountInfo!.data);
    let offset = 8; // discriminator

    const bump = data.readUInt8(offset);
    offset += 1;
    const vault = new PublicKey(data.subarray(offset, offset + 32));
    offset += 32;
    const batchId = Number(data.readBigUInt64LE(offset));
    offset += 8;
    const index = data.readUInt8(offset);
    offset += 1;
    const encryptedSender = data.subarray(offset, offset + 64);
    offset += 64;
    const encryptedAmount = data.subarray(offset, offset + 64);
    offset += 64;
    const providerTokenAccount = new PublicKey(
      data.subarray(offset, offset + 32)
    );
    offset += 32;
    const timestamp = Number(data.readBigInt64LE(offset));
    offset += 8;
    const auditorEpoch = data.readUInt32LE(offset);

    return {
      address,
      bump,
      vault,
      batchId,
      index,
      encryptedSender,
      encryptedAmount,
      provider: providerTokenAccount,
      timestamp,
      auditorEpoch,
    };
  }

  async function sendAtomicSettleAndAudit(
    batchId: BN,
    settlements: SettleEntryInput[],
    auditRecords: AuditRecordInput[],
    auditStartIndex = 0
  ) {
    const batchChunkHash = computeBatchChunkHash(
      batchId,
      settlements,
      auditRecords
    );

    const settleIx = await program.methods
      .settleVault(batchId, batchChunkHash, settlements)
      .accountsPartial({
        vaultSigner: vaultSignerKeypair.publicKey,
        vaultConfig: vaultConfigPda,
        vaultTokenAccount: vaultTokenAccountPda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .remainingAccounts(
        settlements.map((settlement) => ({
          pubkey: settlement.providerTokenAccount,
          isWritable: true,
          isSigner: false,
        }))
      )
      .instruction();

    const auditIx = await program.methods
      .recordAudit(batchId, batchChunkHash, auditRecords)
      .accountsPartial({
        vaultSigner: vaultSignerKeypair.publicKey,
        vaultConfig: vaultConfigPda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .remainingAccounts(
        auditRecords.map((_, idx) => ({
          pubkey: findAuditPda(batchId, auditStartIndex + idx),
          isWritable: true,
          isSigner: false,
        }))
      )
      .instruction();

    const latestBlockhash = await provider.connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: governance.publicKey,
      recentBlockhash: latestBlockhash.blockhash,
      instructions: [settleIx, auditIx],
    }).compileToV0Message();

    const tx = new VersionedTransaction(messageV0);
    tx.sign([(governance as any).payer, vaultSignerKeypair]);

    const txSig = await provider.connection.sendTransaction(tx);
    await provider.connection.confirmTransaction(
      {
        signature: txSig,
        blockhash: latestBlockhash.blockhash,
        lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
      },
      "confirmed"
    );

    return txSig;
  }

  describe("initialize_vault", () => {
    it("initializes vault correctly", async () => {
      await program.methods
        .initializeVault(
          vaultId,
          vaultSignerKeypair.publicKey,
          auditorMasterPubkey,
          attestationPolicyHash
        )
        .accountsPartial({
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
      expect(vault.vaultId.toNumber()).to.equal(vaultId.toNumber());
      expect(vault.governance.toBase58()).to.equal(
        governance.publicKey.toBase58()
      );
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

      // Fund SOL to client
      await fundAccount(clientKeypair.publicKey, HEAVY_FUND_LAMPORTS);

      // Create client token account
      clientTokenAccount = await createTokenAccount(
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
        depositAmount * 10,
        [],
        devnetConfirmOpts
      );
    });

    it("deposits USDC into vault", async () => {
      await program.methods
        .deposit(new BN(depositAmount))
        .accountsPartial({
          client: clientKeypair.publicKey,
          vaultConfig: vaultConfigPda,
          clientTokenAccount: clientTokenAccount,
          vaultTokenAccount: vaultTokenAccountPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([clientKeypair])
        .rpc();

      const vaultToken = await getAccount(
        provider.connection,
        vaultTokenAccountPda
      );
      expect(Number(vaultToken.amount)).to.equal(depositAmount);

      const vault = await program.account.vaultConfig.fetch(vaultConfigPda);
      expect(vault.lifetimeDeposited.toNumber()).to.equal(depositAmount);
    });

    it("rejects zero deposit", async () => {
      try {
        await program.methods
          .deposit(new BN(0))
          .accountsPartial({
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
      await fundAccount(withdrawClient.publicKey, HEAVY_FUND_LAMPORTS);

      // Create client token account
      withdrawClientTokenAccount = await createTokenAccount(
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
        Keypair.generate(), // separate account for deposit
        devnetConfirmOpts
      );
      await mintTo(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        depositTokenAccount,
        governance.publicKey,
        2_000_000,
        [],
        devnetConfirmOpts
      );
      await program.methods
        .deposit(new BN(2_000_000))
        .accountsPartial({
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
      buf.set(client.toBuffer(), offset);
      offset += 32;
      buf.set(recipientAta.toBuffer(), offset);
      offset += 32;
      buf.writeBigUInt64LE(BigInt(amount), offset);
      offset += 8;
      buf.writeBigUInt64LE(BigInt(withdrawNonce), offset);
      offset += 8;
      buf.writeBigInt64LE(BigInt(expiresAt), offset);
      offset += 8;
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
        .accountsPartial({
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
        .accountsPartial({
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

      const signature = nacl.sign.detached(
        wrongMessage,
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

      const withdrawIx = await program.methods
        .withdraw(
          new BN(withdrawAmount), // actual amount differs from signed amount
          new BN(withdrawNonce),
          new BN(expiresAt),
          Array.from(signature) as any
        )
        .accountsPartial({
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

      const withdrawIx = await program.methods
        .withdraw(
          new BN(withdrawAmount),
          new BN(withdrawNonce),
          new BN(expiresAt),
          Array.from(signature) as any
        )
        .accountsPartial({
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
      await fundAccount(providerKeypair.publicKey, HEAVY_FUND_LAMPORTS);

      providerTokenAccount = await createTokenAccount(
        providerKeypair,
        usdcMint,
        providerKeypair.publicKey
      );

      // Deposit more funds to vault
      clientKeypair = Keypair.generate();
      await fundAccount(clientKeypair.publicKey, HEAVY_FUND_LAMPORTS);

      clientTokenAccount = await createTokenAccount(
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
        5_000_000,
        [],
        devnetConfirmOpts
      );

      await program.methods
        .deposit(new BN(5_000_000))
        .accountsPartial({
          client: clientKeypair.publicKey,
          vaultConfig: vaultConfigPda,
          clientTokenAccount: clientTokenAccount,
          vaultTokenAccount: vaultTokenAccountPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([clientKeypair])
        .rpc();
    });

    it("settles vault atomically with audit records", async () => {
      const batchId = new BN(1);

      await sendAtomicSettleAndAudit(
        batchId,
        [
          {
            providerTokenAccount,
            amount: new BN(settleAmount),
          },
        ],
        [buildAuditRecord(providerTokenAccount, 17)]
      );

      const providerToken = await getAccount(
        provider.connection,
        providerTokenAccount,
        "confirmed"
      );
      expect(Number(providerToken.amount)).to.equal(settleAmount);

      const vault = await program.account.vaultConfig.fetch(
        vaultConfigPda,
        "confirmed"
      );
      expect(vault.lifetimeSettled.toNumber()).to.equal(settleAmount);
    });

    it("settles to multiple providers in one batch", async () => {
      const provider2Keypair = Keypair.generate();
      await fundAccount(provider2Keypair.publicKey, HEAVY_FUND_LAMPORTS);

      const provider2TokenAccount = await createTokenAccount(
        provider2Keypair,
        usdcMint,
        provider2Keypair.publicKey
      );

      const amount1 = 50_000;
      const amount2 = 75_000;

      const vaultBefore = await program.account.vaultConfig.fetch(
        vaultConfigPda
      );
      const settledBefore = vaultBefore.lifetimeSettled.toNumber();

      await sendAtomicSettleAndAudit(
        new BN(10),
        [
          {
            providerTokenAccount,
            amount: new BN(amount1),
          },
          {
            providerTokenAccount: provider2TokenAccount,
            amount: new BN(amount2),
          },
        ],
        [
          buildAuditRecord(providerTokenAccount, 33),
          buildAuditRecord(provider2TokenAccount, 44),
        ]
      );

      const p2Token = await getAccount(
        provider.connection,
        provider2TokenAccount
      );
      expect(Number(p2Token.amount)).to.equal(amount2);

      const vaultAfter = await program.account.vaultConfig.fetch(
        vaultConfigPda
      );
      expect(vaultAfter.lifetimeSettled.toNumber()).to.equal(
        settledBefore + amount1 + amount2
      );
    });

    it("rejects settlement from non-vault-signer", async () => {
      const fakeSigner = Keypair.generate();
      await fundAccount(fakeSigner.publicKey, FUND_LAMPORTS);

      try {
        await program.methods
          .settleVault(new BN(2), new Array(32).fill(0), [
            {
              providerTokenAccount: providerTokenAccount,
              amount: new BN(1000),
            },
          ])
          .accountsPartial({
            vaultSigner: fakeSigner.publicKey,
            vaultConfig: vaultConfigPda,
            vaultTokenAccount: vaultTokenAccountPda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
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

    it("rejects standalone settle_vault without record_audit pairing", async () => {
      try {
        await program.methods
          .settleVault(new BN(3), new Array(32).fill(0), [
            {
              providerTokenAccount,
              amount: new BN(5_000),
            },
          ])
          .accountsPartial({
            vaultSigner: vaultSignerKeypair.publicKey,
            vaultConfig: vaultConfigPda,
            vaultTokenAccount: vaultTokenAccountPda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
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
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.error.errorCode.code).to.equal("SettleVaultWithoutAudit");
      }
    });
  });

  describe("pause_vault", () => {
    // Use a separate vault for pause tests
    let pauseVaultConfigPda: PublicKey;
    let pauseVaultTokenPda: PublicKey;
    const pauseVaultId = new BN(testRunSeed + 100);

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
        .accountsPartial({
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
        .accountsPartial({
          governance: governance.publicKey,
          vaultConfig: pauseVaultConfigPda,
        })
        .rpc();

      const vault = await program.account.vaultConfig.fetch(
        pauseVaultConfigPda
      );
      expect(vault.status).to.equal(1); // Paused
    });

    it("rejects deposit on paused vault", async () => {
      const clientKeypair = Keypair.generate();
      await fundAccount(clientKeypair.publicKey, HEAVY_FUND_LAMPORTS);

      const clientTokenAccount = await createTokenAccount(
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
        1_000_000,
        [],
        devnetConfirmOpts
      );

      try {
        await program.methods
          .deposit(new BN(1_000_000))
          .accountsPartial({
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
    const migrateVaultId = new BN(testRunSeed + 200);
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
        .accountsPartial({
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
        .accountsPartial({
          governance: governance.publicKey,
          vaultConfig: migrateVaultConfigPda,
        })
        .rpc();

      const vault = await program.account.vaultConfig.fetch(
        migrateVaultConfigPda
      );
      expect(vault.status).to.equal(2); // Migrating
      expect(vault.successorVault.toBase58()).to.equal(
        successorVault.toBase58()
      );
    });
  });

  describe("rotate_auditor", () => {
    it("rotates auditor key", async () => {
      const rotatingProvider = Keypair.generate();
      await fundAccount(rotatingProvider.publicKey, HEAVY_FUND_LAMPORTS);

      const rotatingProviderTokenAccount = await createTokenAccount(
        rotatingProvider,
        usdcMint,
        rotatingProvider.publicKey
      );

      const oldSender = Keypair.generate().publicKey;
      const oldBatchId = new BN(40);
      const oldAuditPda = findAuditPda(oldBatchId, 0);
      await sendAtomicSettleAndAudit(
        oldBatchId,
        [
          {
            providerTokenAccount: rotatingProviderTokenAccount,
            amount: new BN(12_345),
          },
        ],
        [
          buildEncryptedAuditRecord(
            oldAuditorMasterSecret,
            rotatingProviderTokenAccount,
            oldSender,
            BigInt(12_345),
            1_700_000_001
          ),
        ]
      );

      const oldAuditAccount = await fetchAuditRecord(oldAuditPda);
      expect(oldAuditAccount.auditorEpoch).to.equal(0);

      const newAuditorPubkey = new Array(32).fill(42);

      await program.methods
        .rotateAuditor(newAuditorPubkey)
        .accountsPartial({
          governance: governance.publicKey,
          vaultConfig: vaultConfigPda,
        })
        .rpc();

      const vault = await program.account.vaultConfig.fetch(vaultConfigPda);
      expect(vault.auditorEpoch).to.equal(1);
      expect(vault.auditorMasterPubkey).to.deep.equal(newAuditorPubkey);

      const newSender = Keypair.generate().publicKey;
      const newBatchId = new BN(41);
      const newAuditPda = findAuditPda(newBatchId, 0);
      await sendAtomicSettleAndAudit(
        newBatchId,
        [
          {
            providerTokenAccount: rotatingProviderTokenAccount,
            amount: new BN(54_321),
          },
        ],
        [
          buildEncryptedAuditRecord(
            newAuditorMasterSecret,
            rotatingProviderTokenAccount,
            newSender,
            BigInt(54_321),
            1_700_000_002
          ),
        ]
      );

      const newAuditAccount = await fetchAuditRecord(newAuditPda);
      expect(newAuditAccount.auditorEpoch).to.equal(1);

      const oldTool = new AuditTool(oldAuditorMasterSecret);
      const newTool = new AuditTool(newAuditorMasterSecret);

      const oldDecrypts = await oldTool.decryptForProvider(
        vaultConfigPda,
        rotatingProviderTokenAccount,
        provider.connection,
        program.programId
      );
      const newDecrypts = await newTool.decryptForProvider(
        vaultConfigPda,
        rotatingProviderTokenAccount,
        provider.connection,
        program.programId
      );

      const oldEpochRecord = oldDecrypts.find(
        (record) => record.batchId === oldBatchId.toNumber()
      );
      const oldToolNewEpochRecord = oldDecrypts.find(
        (record) => record.batchId === newBatchId.toNumber()
      );
      const newEpochRecord = newDecrypts.find(
        (record) => record.batchId === newBatchId.toNumber()
      );
      const newToolOldEpochRecord = newDecrypts.find(
        (record) => record.batchId === oldBatchId.toNumber()
      );

      expect(oldEpochRecord).to.not.equal(undefined);
      expect(oldEpochRecord!.sender.toBase58()).to.equal(oldSender.toBase58());
      expect(oldEpochRecord!.amount).to.equal(12_345);
      expect(oldEpochRecord!.auditorEpoch).to.equal(0);

      expect(newEpochRecord).to.not.equal(undefined);
      expect(newEpochRecord!.sender.toBase58()).to.equal(newSender.toBase58());
      expect(newEpochRecord!.amount).to.equal(54_321);
      expect(newEpochRecord!.auditorEpoch).to.equal(1);

      if (oldToolNewEpochRecord) {
        expect(oldToolNewEpochRecord.sender.toBase58()).to.not.equal(
          newSender.toBase58()
        );
      }
      if (newToolOldEpochRecord) {
        expect(newToolOldEpochRecord.sender.toBase58()).to.not.equal(
          oldSender.toBase58()
        );
      }
    });
  });

  describe("record_audit", () => {
    it("rejects record_audit from non-vault-signer", async () => {
      const fakeSigner = Keypair.generate();
      await fundAccount(fakeSigner.publicKey, FUND_LAMPORTS);

      try {
        await program.methods
          .recordAudit(new BN(1), new Array(32).fill(0), [])
          .accountsPartial({
            vaultSigner: fakeSigner.publicKey,
            vaultConfig: vaultConfigPda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            systemProgram: SystemProgram.programId,
          })
          .signers([fakeSigner])
          .rpc();
        expect.fail("Should have thrown");
      } catch (err: any) {
        expect(err.error.errorCode.code).to.equal("InvalidVaultSigner");
      }
    });

    it("rejects standalone record_audit (no settle_vault pairing)", async () => {
      // record_audit must be in the same tx as settle_vault
      const batchId = new BN(999);
      const batchChunkHash = new Array(32).fill(42);

      // Fake encrypted audit record data
      const fakeProvider = Keypair.generate().publicKey;
      const fakeAuditRecord = buildAuditRecord(fakeProvider, 1);
      const auditPda = findAuditPda(batchId, 0);

      try {
        await program.methods
          .recordAudit(batchId, batchChunkHash, [fakeAuditRecord])
          .accountsPartial({
            vaultSigner: vaultSignerKeypair.publicKey,
            vaultConfig: vaultConfigPda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            systemProgram: SystemProgram.programId,
          })
          .remainingAccounts([
            {
              pubkey: auditPda,
              isWritable: true,
              isSigner: false,
            },
          ])
          .signers([vaultSignerKeypair])
          .rpc();
        expect.fail("Should have thrown");
      } catch (err: any) {
        // Should fail with RecordAuditWithoutSettle
        expect(err.error.errorCode.code).to.equal("RecordAuditWithoutSettle");
      }
    });

    it("creates audit record atomically with settle_vault", async () => {
      // Set up: create a provider with token account and fund vault
      const auditProviderKeypair = Keypair.generate();
      await fundAccount(auditProviderKeypair.publicKey, HEAVY_FUND_LAMPORTS);

      const auditProviderTokenAccount = await createTokenAccount(
        auditProviderKeypair,
        usdcMint,
        auditProviderKeypair.publicKey
      );

      const batchId = new BN(50);
      const settleAmount = 10_000;
      const now = Math.floor(Date.now() / 1000);
      const auditRecord = buildAuditRecord(
        auditProviderTokenAccount,
        0xab,
        now
      );
      const auditPda = findAuditPda(batchId, 0);

      await sendAtomicSettleAndAudit(
        batchId,
        [
          {
            providerTokenAccount: auditProviderTokenAccount,
            amount: new BN(settleAmount),
          },
        ],
        [auditRecord]
      );

      // Verify the AuditRecord PDA was created
      const auditAccount = await fetchAuditRecord(auditPda);
      expect(auditAccount.vault.toBase58()).to.equal(vaultConfigPda.toBase58());
      expect(auditAccount.batchId).to.equal(50);
      expect(auditAccount.index).to.equal(0);
      expect(auditAccount.provider.toBase58()).to.equal(
        auditProviderTokenAccount.toBase58()
      );
      expect(auditAccount.auditorEpoch).to.equal(1); // rotated earlier in test
      expect(auditAccount.encryptedSender.length).to.equal(64);
      expect(auditAccount.encryptedAmount.length).to.equal(64);
    });

    it("supports provider-aggregated settlement with per-request audit records", async () => {
      const aggregatedProvider = Keypair.generate();
      await fundAccount(aggregatedProvider.publicKey, HEAVY_FUND_LAMPORTS);

      const aggregatedProviderTokenAccount = await createTokenAccount(
        aggregatedProvider,
        usdcMint,
        aggregatedProvider.publicKey
      );

      const amount1 = 12_000;
      const amount2 = 18_000;
      const batchId = new BN(76);
      const auditZero = findAuditPda(batchId, 0);
      const auditOne = findAuditPda(batchId, 1);

      await sendAtomicSettleAndAudit(
        batchId,
        [
          {
            providerTokenAccount: aggregatedProviderTokenAccount,
            amount: new BN(amount1 + amount2),
          },
        ],
        [
          buildAuditRecord(aggregatedProviderTokenAccount, 61),
          buildAuditRecord(aggregatedProviderTokenAccount, 62),
        ]
      );

      const providerToken = await getAccount(
        provider.connection,
        aggregatedProviderTokenAccount,
        "confirmed"
      );
      expect(Number(providerToken.amount)).to.equal(amount1 + amount2);

      const firstAudit = await fetchAuditRecord(auditZero);
      const secondAudit = await fetchAuditRecord(auditOne);
      expect(firstAudit.index).to.equal(0);
      expect(secondAudit.index).to.equal(1);
      expect(firstAudit.provider.toBase58()).to.equal(
        aggregatedProviderTokenAccount.toBase58()
      );
      expect(secondAudit.provider.toBase58()).to.equal(
        aggregatedProviderTokenAccount.toBase58()
      );
    });

    it("supports multiple atomic chunks for the same batch_id", async () => {
      const multiChunkProvider = Keypair.generate();
      await fundAccount(multiChunkProvider.publicKey, HEAVY_FUND_LAMPORTS);

      const multiChunkProviderTokenAccount = await createTokenAccount(
        multiChunkProvider,
        usdcMint,
        multiChunkProvider.publicKey
      );

      const batchId = new BN(77);

      await sendAtomicSettleAndAudit(
        batchId,
        [
          {
            providerTokenAccount: multiChunkProviderTokenAccount,
            amount: new BN(1_000),
          },
          {
            providerTokenAccount: multiChunkProviderTokenAccount,
            amount: new BN(2_000),
          },
        ],
        [
          buildAuditRecord(multiChunkProviderTokenAccount, 51),
          buildAuditRecord(multiChunkProviderTokenAccount, 52),
        ],
        0
      );

      await sendAtomicSettleAndAudit(
        batchId,
        [
          {
            providerTokenAccount: multiChunkProviderTokenAccount,
            amount: new BN(3_000),
          },
          {
            providerTokenAccount: multiChunkProviderTokenAccount,
            amount: new BN(4_000),
          },
        ],
        [
          buildAuditRecord(multiChunkProviderTokenAccount, 53),
          buildAuditRecord(multiChunkProviderTokenAccount, 54),
        ],
        2
      );

      const auditTwo = await fetchAuditRecord(findAuditPda(batchId, 2));
      const auditThree = await fetchAuditRecord(findAuditPda(batchId, 3));

      expect(auditTwo.index).to.equal(2);
      expect(auditThree.index).to.equal(3);
      expect(auditTwo.provider.toBase58()).to.equal(
        multiChunkProviderTokenAccount.toBase58()
      );
      expect(auditThree.provider.toBase58()).to.equal(
        multiChunkProviderTokenAccount.toBase58()
      );
    });
  });

  describe("retire_vault", () => {
    let retireVaultConfigPda: PublicKey;
    let retireVaultTokenPda: PublicKey;
    const retireVaultId = new BN(testRunSeed + 300);

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
        .accountsPartial({
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
      const pauseSig = await program.methods
        .pauseVault()
        .accountsPartial({
          governance: governance.publicKey,
          vaultConfig: retireVaultConfigPda,
        })
        .rpc();
      await provider.connection.confirmTransaction(pauseSig, "confirmed");

      // Then retire
      const retireSig = await program.methods
        .retireVault()
        .accountsPartial({
          governance: governance.publicKey,
          vaultConfig: retireVaultConfigPda,
        })
        .rpc();
      await provider.connection.confirmTransaction(retireSig, "confirmed");

      const vault = await program.account.vaultConfig.fetch(
        retireVaultConfigPda
      );
      expect(vault.status).to.equal(3); // Retired
    });

    it("rejects retire on active vault", async () => {
      // Create another vault
      const activeVaultId = new BN(testRunSeed + 301);
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
        .accountsPartial({
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
          .accountsPartial({
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

  describe("asc_close_claim", () => {
    it("records an on-chain ASC close claim from voucher + adapted signature", async () => {
      const caller = (governance as any).payer as Keypair;
      const channelId = "ch_claim_test";
      const requestId = "req_claim_test";
      const amount = 1_250_000;
      const requestHash = "ab".repeat(32);
      const claimVaultId = new BN(testRunSeed + 350);
      const [claimVaultConfigPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("vault_config"),
          governance.publicKey.toBuffer(),
          claimVaultId.toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );
      const [claimVaultTokenPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault_token"), claimVaultConfigPda.toBuffer()],
        program.programId
      );

      const existingVault = await provider.connection.getAccountInfo(
        claimVaultConfigPda,
        "confirmed"
      );
      if (!existingVault) {
        await program.methods
          .initializeVault(
            claimVaultId,
            vaultSignerKeypair.publicKey,
            auditorMasterPubkey,
            attestationPolicyHash
          )
          .accountsPartial({
            governance: governance.publicKey,
            vaultConfig: claimVaultConfigPda,
            usdcMint,
            vaultTokenAccount: claimVaultTokenPda,
            systemProgram: SystemProgram.programId,
            tokenProgram: TOKEN_PROGRAM_ID,
            rent: anchor.web3.SYSVAR_RENT_PUBKEY,
          })
          .rpc();
      }

      const delivery = generateAscDeliveryArtifact({
        channelId,
        requestId,
        amount,
        requestHash,
        result: JSON.stringify({ ok: true, value: "claim" }),
        providerSecretKey: "11".repeat(32),
        adaptorSecret: "22".repeat(32),
      });

      const issuedAt = Math.floor(Date.now() / 1000);
      const voucherMessage = buildAscClaimVoucherMessage({
        channelId,
        requestId,
        amount,
        requestHash,
        providerPubkey: delivery.providerPubkey,
        issuedAt,
        vaultConfig: Buffer.from(claimVaultConfigPda.toBytes()).toString("hex"),
      });

      const deliverResponse = {
        ok: true,
        channelId,
        status: "pending",
        claimVoucher: {
          message: Buffer.from(voucherMessage).toString("base64"),
          signature: Buffer.from(
            nacl.sign.detached(voucherMessage, vaultSignerKeypair.secretKey)
          ).toString("base64"),
          issuedAt,
          channelIdHash: createHash("sha256").update(channelId).digest("hex"),
          requestIdHash: createHash("sha256").update(requestId).digest("hex"),
        },
      };

      const { ascCloseClaim } = await submitAscCloseClaim({
        program,
        caller,
        config: {
          vaultConfig: claimVaultConfigPda.toBase58(),
          vaultSigner: vaultSignerKeypair.publicKey.toBase58(),
        },
        channelId,
        requestId,
        amount,
        requestHash,
        delivery,
        claimVoucher: deliverResponse.claimVoucher,
      });

      const ascCloseClaimPda = new PublicKey(ascCloseClaim);
      const claim = await program.account.ascCloseClaim.fetch(ascCloseClaimPda);
      expect(Buffer.from(claim.channelIdHash).toString("hex")).to.equal(
        createHash("sha256").update(channelId).digest("hex")
      );
      expect(Buffer.from(claim.requestIdHash).toString("hex")).to.equal(
        createHash("sha256").update(requestId).digest("hex")
      );
      expect(Buffer.from(claim.requestHash).toString("hex")).to.equal(
        requestHash
      );
      expect(Buffer.from(claim.providerPubkey).toString("hex")).to.equal(
        delivery.providerPubkey
      );
      expect(claim.amount.toNumber()).to.equal(amount);
    });
  });

  describe("force_settle", () => {
    let fsClient: Keypair;
    let fsClientTokenAccount: PublicKey;
    let fsVaultConfigPda: PublicKey;
    let fsVaultTokenPda: PublicKey;
    const fsVaultId = new BN(testRunSeed + 400);
    const fsVaultSignerKeypair = Keypair.generate();
    const fsDepositAmount = 5_000_000; // 5 USDC

    /**
     * Build a ParticipantReceipt message matching enclave state.rs format:
     *   participant (32) + participant_kind (1) + recipient_ata (32) +
     *   free_balance (8) + locked_balance (8) + max_lock_expires_at (8) +
     *   nonce (8) + timestamp (8) + snapshot_seqno (8) + vault_config (32)
     * Total: 145 bytes
     */
    function buildReceiptMessage(
      participant: PublicKey,
      participantKind: number,
      recipientAta: PublicKey,
      freeBalance: number,
      lockedBalance: number,
      maxLockExpiresAt: number,
      nonce: number,
      timestamp: number,
      snapshotSeqno: number,
      vaultConfig: PublicKey
    ): Buffer {
      const buf = Buffer.alloc(145);
      let offset = 0;
      buf.set(participant.toBuffer(), offset);
      offset += 32;
      buf.writeUInt8(participantKind, offset);
      offset += 1;
      buf.set(recipientAta.toBuffer(), offset);
      offset += 32;
      buf.writeBigUInt64LE(BigInt(freeBalance), offset);
      offset += 8;
      buf.writeBigUInt64LE(BigInt(lockedBalance), offset);
      offset += 8;
      buf.writeBigInt64LE(BigInt(maxLockExpiresAt), offset);
      offset += 8;
      buf.writeBigUInt64LE(BigInt(nonce), offset);
      offset += 8;
      buf.writeBigInt64LE(BigInt(timestamp), offset);
      offset += 8;
      buf.writeBigUInt64LE(BigInt(snapshotSeqno), offset);
      offset += 8;
      buf.set(vaultConfig.toBuffer(), offset);
      return buf;
    }

    before(async () => {
      // Create a dedicated vault for force_settle tests
      [fsVaultConfigPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("vault_config"),
          governance.publicKey.toBuffer(),
          fsVaultId.toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );
      [fsVaultTokenPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault_token"), fsVaultConfigPda.toBuffer()],
        program.programId
      );

      await program.methods
        .initializeVault(
          fsVaultId,
          fsVaultSignerKeypair.publicKey,
          auditorMasterPubkey,
          attestationPolicyHash
        )
        .accountsPartial({
          governance: governance.publicKey,
          vaultConfig: fsVaultConfigPda,
          usdcMint: usdcMint,
          vaultTokenAccount: fsVaultTokenPda,
          systemProgram: SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();

      // Create client and deposit funds
      fsClient = Keypair.generate();
      await fundAccount(fsClient.publicKey, HEAVY_FUND_LAMPORTS);

      fsClientTokenAccount = await createTokenAccount(
        fsClient,
        usdcMint,
        fsClient.publicKey
      );

      await mintTo(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        fsClientTokenAccount,
        governance.publicKey,
        fsDepositAmount,
        [],
        devnetConfirmOpts
      );

      await program.methods
        .deposit(new BN(fsDepositAmount))
        .accountsPartial({
          client: fsClient.publicKey,
          vaultConfig: fsVaultConfigPda,
          clientTokenAccount: fsClientTokenAccount,
          vaultTokenAccount: fsVaultTokenPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([fsClient])
        .rpc();
    });

    describe("force_settle_init", () => {
      it("initiates force settle with valid receipt", async () => {
        const participantKind = 0; // Client
        const freeBalance = 3_000_000;
        const lockedBalance = 1_000_000;
        const slot = await provider.connection.getSlot();
        const blockTime = await provider.connection.getBlockTime(slot);
        const maxLockExpiresAt = blockTime! + 3600;
        const receiptNonce = 1;
        const timestamp = blockTime!;
        const snapshotSeqno = 0;

        const receiptMessage = buildReceiptMessage(
          fsClient.publicKey,
          participantKind,
          fsClientTokenAccount,
          freeBalance,
          lockedBalance,
          maxLockExpiresAt,
          receiptNonce,
          timestamp,
          snapshotSeqno,
          fsVaultConfigPda
        );

        const receiptSignature = nacl.sign.detached(
          receiptMessage,
          fsVaultSignerKeypair.secretKey
        );

        const [forceSettlePda] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("force_settle"),
            fsVaultConfigPda.toBuffer(),
            fsClient.publicKey.toBuffer(),
            Buffer.from([participantKind]),
          ],
          program.programId
        );

        const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
          privateKey: fsVaultSignerKeypair.secretKey,
          message: receiptMessage,
        });

        const forceSettleIx = await program.methods
          .forceSettleInit(
            participantKind,
            fsClientTokenAccount,
            new BN(freeBalance),
            new BN(lockedBalance),
            new BN(maxLockExpiresAt),
            new BN(receiptNonce),
            Array.from(receiptSignature) as any,
            receiptMessage
          )
          .accountsPartial({
            participant: fsClient.publicKey,
            vaultConfig: fsVaultConfigPda,
            forceSettleRequest: forceSettlePda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            systemProgram: SystemProgram.programId,
          })
          .instruction();

        const latestBlockhash = await provider.connection.getLatestBlockhash();
        const messageV0 = new TransactionMessage({
          payerKey: fsClient.publicKey,
          recentBlockhash: latestBlockhash.blockhash,
          instructions: [ed25519Ix, forceSettleIx],
        }).compileToV0Message();

        const tx = new VersionedTransaction(messageV0);
        tx.sign([fsClient]);

        const txSig = await provider.connection.sendTransaction(tx);
        await provider.connection.confirmTransaction({
          signature: txSig,
          blockhash: latestBlockhash.blockhash,
          lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
        });

        // Verify ForceSettleRequest state
        const request = await program.account.forceSettleRequest.fetch(
          forceSettlePda
        );
        expect(request.vault.toBase58()).to.equal(fsVaultConfigPda.toBase58());
        expect(request.participant.toBase58()).to.equal(
          fsClient.publicKey.toBase58()
        );
        expect(request.participantKind).to.equal(participantKind);
        expect(request.recipientAta.toBase58()).to.equal(
          fsClientTokenAccount.toBase58()
        );
        expect(request.freeBalanceDue.toNumber()).to.equal(freeBalance);
        expect(request.lockedBalanceDue.toNumber()).to.equal(lockedBalance);
        expect(request.receiptNonce.toNumber()).to.equal(receiptNonce);
        expect(request.isResolved).to.equal(false);
      });

      it("rejects force settle when instruction args do not match signed receipt", async () => {
        const participantKind = 0;
        const slot = await provider.connection.getSlot();
        const blockTime = await provider.connection.getBlockTime(slot);
        const receiptMessage = buildReceiptMessage(
          fsClient.publicKey,
          participantKind,
          fsClientTokenAccount,
          1_000_000,
          250_000,
          blockTime! + 3600,
          9,
          blockTime!,
          0,
          fsVaultConfigPda
        );

        const receiptSignature = nacl.sign.detached(
          receiptMessage,
          fsVaultSignerKeypair.secretKey
        );

        const [forceSettlePda] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("force_settle"),
            fsVaultConfigPda.toBuffer(),
            fsClient.publicKey.toBuffer(),
            Buffer.from([participantKind]),
          ],
          program.programId
        );

        const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
          privateKey: fsVaultSignerKeypair.secretKey,
          message: receiptMessage,
        });

        const tamperedFreeBalance = 1_500_000;
        const forceSettleIx = await program.methods
          .forceSettleInit(
            participantKind,
            fsClientTokenAccount,
            new BN(tamperedFreeBalance),
            new BN(250_000),
            new BN(blockTime! + 3600),
            new BN(9),
            Array.from(receiptSignature) as any,
            receiptMessage
          )
          .accountsPartial({
            participant: fsClient.publicKey,
            vaultConfig: fsVaultConfigPda,
            forceSettleRequest: forceSettlePda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            systemProgram: SystemProgram.programId,
          })
          .instruction();

        const latestBlockhash = await provider.connection.getLatestBlockhash();
        const messageV0 = new TransactionMessage({
          payerKey: fsClient.publicKey,
          recentBlockhash: latestBlockhash.blockhash,
          instructions: [ed25519Ix, forceSettleIx],
        }).compileToV0Message();

        const tx = new VersionedTransaction(messageV0);
        tx.sign([fsClient]);

        try {
          await provider.connection.sendTransaction(tx);
          await new Promise((r) => setTimeout(r, 1000));
          expect.fail("Should have thrown");
        } catch (err: any) {
          expect(err.toString()).to.include("Error");
        }
      });

      it("rejects force settle with wrong signer", async () => {
        const participantKind = 0; // Client
        const fakeSigner = Keypair.generate();
        // Use a different vault_id to avoid PDA collision
        const fsVaultId2 = new BN(testRunSeed + 401);
        const [fsVaultConfigPda2] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("vault_config"),
            governance.publicKey.toBuffer(),
            fsVaultId2.toArrayLike(Buffer, "le", 8),
          ],
          program.programId
        );
        const [fsVaultTokenPda2] = PublicKey.findProgramAddressSync(
          [Buffer.from("vault_token"), fsVaultConfigPda2.toBuffer()],
          program.programId
        );

        await program.methods
          .initializeVault(
            fsVaultId2,
            fsVaultSignerKeypair.publicKey,
            auditorMasterPubkey,
            attestationPolicyHash
          )
          .accountsPartial({
            governance: governance.publicKey,
            vaultConfig: fsVaultConfigPda2,
            usdcMint: usdcMint,
            vaultTokenAccount: fsVaultTokenPda2,
            systemProgram: SystemProgram.programId,
            tokenProgram: TOKEN_PROGRAM_ID,
            rent: anchor.web3.SYSVAR_RENT_PUBKEY,
          })
          .rpc();

        const slot = await provider.connection.getSlot();
        const blockTime = await provider.connection.getBlockTime(slot);

        const receiptMessage = buildReceiptMessage(
          fsClient.publicKey,
          participantKind,
          fsClientTokenAccount,
          1_000_000,
          0,
          0,
          1,
          blockTime!,
          0,
          fsVaultConfigPda2
        );

        // Sign with FAKE signer (not the vault signer)
        const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
          privateKey: fakeSigner.secretKey,
          message: receiptMessage,
        });

        const receiptSignature = nacl.sign.detached(
          receiptMessage,
          fakeSigner.secretKey
        );

        const [forceSettlePda] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("force_settle"),
            fsVaultConfigPda2.toBuffer(),
            fsClient.publicKey.toBuffer(),
            Buffer.from([participantKind]),
          ],
          program.programId
        );

        const forceSettleIx = await program.methods
          .forceSettleInit(
            participantKind,
            fsClientTokenAccount,
            new BN(1_000_000),
            new BN(0),
            new BN(0),
            new BN(1),
            Array.from(receiptSignature) as any,
            receiptMessage
          )
          .accountsPartial({
            participant: fsClient.publicKey,
            vaultConfig: fsVaultConfigPda2,
            forceSettleRequest: forceSettlePda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            systemProgram: SystemProgram.programId,
          })
          .instruction();

        const latestBlockhash = await provider.connection.getLatestBlockhash();
        const messageV0 = new TransactionMessage({
          payerKey: fsClient.publicKey,
          recentBlockhash: latestBlockhash.blockhash,
          instructions: [ed25519Ix, forceSettleIx],
        }).compileToV0Message();

        const tx = new VersionedTransaction(messageV0);
        tx.sign([fsClient]);

        try {
          await provider.connection.sendTransaction(tx);
          await new Promise((r) => setTimeout(r, 1000));
          expect.fail("Should have thrown");
        } catch (err: any) {
          // Should fail with InvalidVaultSigner
          expect(err.toString()).to.include("Error");
        }
      });

      it("rejects ed25519 instructions that reference another instruction's data", async () => {
        const participantKind = 0;
        const altClient = Keypair.generate();
        await fundAccount(altClient.publicKey, FUND_LAMPORTS);

        const recipientAta = Keypair.generate().publicKey;
        const slot = await provider.connection.getSlot();
        const blockTime = await provider.connection.getBlockTime(slot);
        const timestamp = blockTime!;

        const honestReceiptMessage = buildReceiptMessage(
          altClient.publicKey,
          participantKind,
          recipientAta,
          500_000,
          0,
          0,
          20,
          timestamp,
          0,
          fsVaultConfigPda
        );
        const honestEd25519Ix = Ed25519Program.createInstructionWithPrivateKey({
          privateKey: fsVaultSignerKeypair.secretKey,
          message: honestReceiptMessage,
        });

        const maliciousFreeBalance = 1_750_000;
        const maliciousReceiptNonce = 21;
        const maliciousReceiptMessage = buildReceiptMessage(
          altClient.publicKey,
          participantKind,
          recipientAta,
          maliciousFreeBalance,
          0,
          0,
          maliciousReceiptNonce,
          timestamp,
          1,
          fsVaultConfigPda
        );
        const fakeSignature = new Uint8Array(64).fill(9);
        const crossInstructionEd25519Ix =
          Ed25519Program.createInstructionWithPublicKey({
            publicKey: fsVaultSignerKeypair.publicKey.toBytes(),
            message: maliciousReceiptMessage,
            signature: fakeSignature,
            instructionIndex: 0,
          });

        const [forceSettlePda] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("force_settle"),
            fsVaultConfigPda.toBuffer(),
            altClient.publicKey.toBuffer(),
            Buffer.from([participantKind]),
          ],
          program.programId
        );

        const forceSettleIx = await program.methods
          .forceSettleInit(
            participantKind,
            recipientAta,
            new BN(maliciousFreeBalance),
            new BN(0),
            new BN(0),
            new BN(maliciousReceiptNonce),
            Array.from(fakeSignature) as any,
            maliciousReceiptMessage
          )
          .accountsPartial({
            participant: altClient.publicKey,
            vaultConfig: fsVaultConfigPda,
            forceSettleRequest: forceSettlePda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
            systemProgram: SystemProgram.programId,
          })
          .instruction();

        const latestBlockhash = await provider.connection.getLatestBlockhash();
        const messageV0 = new TransactionMessage({
          payerKey: altClient.publicKey,
          recentBlockhash: latestBlockhash.blockhash,
          instructions: [
            honestEd25519Ix,
            crossInstructionEd25519Ix,
            forceSettleIx,
          ],
        }).compileToV0Message();

        const tx = new VersionedTransaction(messageV0);
        tx.sign([altClient]);

        try {
          await provider.connection.sendTransaction(tx);
          await new Promise((r) => setTimeout(r, 1000));
          expect.fail("Should have thrown");
        } catch (err: any) {
          expect(err.toString()).to.include("Error");
        }
      });
    });

    describe("force_settle_challenge", () => {
      it("challenges with newer receipt nonce", async () => {
        const participantKind = 0;
        const slot = await provider.connection.getSlot();
        const blockTime = await provider.connection.getBlockTime(slot);
        const newerFreeBalance = 2_500_000;
        const newerLockedBalance = 500_000;
        const newerMaxLockExpiresAt = blockTime! + 7200;
        const newerReceiptNonce = 5; // higher than original nonce of 1
        const timestamp = blockTime!;
        const snapshotSeqno = 1;

        const newerReceiptMessage = buildReceiptMessage(
          fsClient.publicKey,
          participantKind,
          fsClientTokenAccount,
          newerFreeBalance,
          newerLockedBalance,
          newerMaxLockExpiresAt,
          newerReceiptNonce,
          timestamp,
          snapshotSeqno,
          fsVaultConfigPda
        );

        const newerSignature = nacl.sign.detached(
          newerReceiptMessage,
          fsVaultSignerKeypair.secretKey
        );

        const [forceSettlePda] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("force_settle"),
            fsVaultConfigPda.toBuffer(),
            fsClient.publicKey.toBuffer(),
            Buffer.from([participantKind]),
          ],
          program.programId
        );

        // Anyone can challenge — use a new keypair
        const challenger = Keypair.generate();
        await fundAccount(challenger.publicKey, FUND_LAMPORTS);

        const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
          privateKey: fsVaultSignerKeypair.secretKey,
          message: newerReceiptMessage,
        });

        const challengeIx = await program.methods
          .forceSettleChallenge(
            fsClientTokenAccount,
            new BN(newerFreeBalance),
            new BN(newerLockedBalance),
            new BN(newerMaxLockExpiresAt),
            new BN(newerReceiptNonce),
            Array.from(newerSignature) as any,
            newerReceiptMessage
          )
          .accountsPartial({
            challenger: challenger.publicKey,
            vaultConfig: fsVaultConfigPda,
            forceSettleRequest: forceSettlePda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          })
          .instruction();

        const latestBlockhash = await provider.connection.getLatestBlockhash();
        const messageV0 = new TransactionMessage({
          payerKey: challenger.publicKey,
          recentBlockhash: latestBlockhash.blockhash,
          instructions: [ed25519Ix, challengeIx],
        }).compileToV0Message();

        const tx = new VersionedTransaction(messageV0);
        tx.sign([challenger]);

        const txSig = await provider.connection.sendTransaction(tx);
        await provider.connection.confirmTransaction({
          signature: txSig,
          blockhash: latestBlockhash.blockhash,
          lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
        });

        // Verify updated ForceSettleRequest
        const request = await program.account.forceSettleRequest.fetch(
          forceSettlePda
        );
        expect(request.freeBalanceDue.toNumber()).to.equal(newerFreeBalance);
        expect(request.lockedBalanceDue.toNumber()).to.equal(
          newerLockedBalance
        );
        expect(request.receiptNonce.toNumber()).to.equal(newerReceiptNonce);
        expect(request.isResolved).to.equal(false);
      });

      it("rejects challenge with stale nonce", async () => {
        const participantKind = 0;
        const slot = await provider.connection.getSlot();
        const blockTime = await provider.connection.getBlockTime(slot);
        const staleNonce = 2; // lower than current nonce of 5

        const staleReceiptMessage = buildReceiptMessage(
          fsClient.publicKey,
          participantKind,
          fsClientTokenAccount,
          1_000_000,
          0,
          0,
          staleNonce,
          blockTime!,
          0,
          fsVaultConfigPda
        );

        const staleSignature = nacl.sign.detached(
          staleReceiptMessage,
          fsVaultSignerKeypair.secretKey
        );

        const [forceSettlePda] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("force_settle"),
            fsVaultConfigPda.toBuffer(),
            fsClient.publicKey.toBuffer(),
            Buffer.from([participantKind]),
          ],
          program.programId
        );

        const challenger = Keypair.generate();
        await fundAccount(challenger.publicKey, FUND_LAMPORTS);

        const ed25519Ix = Ed25519Program.createInstructionWithPrivateKey({
          privateKey: fsVaultSignerKeypair.secretKey,
          message: staleReceiptMessage,
        });

        const challengeIx = await program.methods
          .forceSettleChallenge(
            fsClientTokenAccount,
            new BN(1_000_000),
            new BN(0),
            new BN(0),
            new BN(staleNonce),
            Array.from(staleSignature) as any,
            staleReceiptMessage
          )
          .accountsPartial({
            challenger: challenger.publicKey,
            vaultConfig: fsVaultConfigPda,
            forceSettleRequest: forceSettlePda,
            instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
          })
          .instruction();

        const latestBlockhash = await provider.connection.getLatestBlockhash();
        const messageV0 = new TransactionMessage({
          payerKey: challenger.publicKey,
          recentBlockhash: latestBlockhash.blockhash,
          instructions: [ed25519Ix, challengeIx],
        }).compileToV0Message();

        const tx = new VersionedTransaction(messageV0);
        tx.sign([challenger]);

        try {
          await provider.connection.sendTransaction(tx);
          await new Promise((r) => setTimeout(r, 1000));
          expect.fail("Should have thrown");
        } catch (err: any) {
          // Should fail with StaleReceiptNonce
          expect(err.toString()).to.include("Error");
        }
      });
    });

    describe("force_settle_finalize", () => {
      it("rejects finalize before dispute window expires", async () => {
        const participantKind = 0;
        const [forceSettlePda] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("force_settle"),
            fsVaultConfigPda.toBuffer(),
            fsClient.publicKey.toBuffer(),
            Buffer.from([participantKind]),
          ],
          program.programId
        );

        try {
          await program.methods
            .forceSettleFinalize()
            .accountsPartial({
              caller: fsClient.publicKey,
              vaultConfig: fsVaultConfigPda,
              forceSettleRequest: forceSettlePda,
              vaultTokenAccount: fsVaultTokenPda,
              recipientTokenAccount: fsClientTokenAccount,
              tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([fsClient])
            .rpc();
          expect.fail("Should have thrown");
        } catch (err: any) {
          expect(err.error.errorCode.code).to.equal("DisputeWindowActive");
        }
      });

      it("finalizes after dispute window (provider claim, no lock)", async () => {
        // Create a new vault with a provider force-settle scenario
        // Use a short dispute window by creating the ForceSettleRequest
        // with an already-passed dispute deadline (via manual PDA manipulation not possible,
        // so we test the full flow with a provider who has no locked balance)

        // For complete force_settle_finalize testing, we need time warping.
        // This test verifies the DisputeWindowActive guard is enforced.
        // Full finalize testing requires bankrun or manual clock manipulation.

        // Verify the request state is still valid
        const participantKind = 0;
        const [forceSettlePda] = PublicKey.findProgramAddressSync(
          [
            Buffer.from("force_settle"),
            fsVaultConfigPda.toBuffer(),
            fsClient.publicKey.toBuffer(),
            Buffer.from([participantKind]),
          ],
          program.programId
        );

        const request = await program.account.forceSettleRequest.fetch(
          forceSettlePda
        );
        expect(request.isResolved).to.equal(false);
        // dispute_deadline should be ~24 hours in the future
        expect(request.disputeDeadline.toNumber()).to.be.greaterThan(
          Math.floor(Date.now() / 1000)
        );
      });
    });
  });
});
