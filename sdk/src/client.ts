import * as anchor from "@coral-xyz/anchor";
import {
  createAccount,
  getAssociatedTokenAddressSync,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import {
  Connection,
  Ed25519Program,
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import BN from "bn.js";

import {
  buildSignatureMessage,
  computePaymentDetailsHash,
  computeRequestHash,
  ed25519Sign,
  sha256hex,
} from "./crypto";
import {
  A402ClientConfig,
  AttestationResponse,
  BalanceResponse,
  ParticipantReceiptResponse,
  PaymentDetails,
  PaymentPayload,
  PaymentRequiredResponse,
  PaymentResponse,
  SettleResponse,
  VerifyResponse,
  WithdrawAuthResponse,
} from "./types";

/**
 * A402 Client SDK — deposit, withdraw, and x402-compatible fetch.
 */
export class A402Client {
  private wallet: { publicKey: PublicKey; secretKey: Uint8Array };
  private vaultAddress: PublicKey;
  private enclaveUrl: string;
  private connection: Connection;
  private cachedAttestation: AttestationResponse | null = null;

  constructor(config: A402ClientConfig) {
    this.wallet = config.walletKeypair;
    this.vaultAddress = config.vaultAddress;
    this.enclaveUrl = config.enclaveUrl.replace(/\/$/, "");
    this.connection = new Connection(
      config.rpcUrl || "http://localhost:8899",
      "confirmed"
    );
  }

  // ── Attestation ──

  /** Verify enclave attestation. Caches result. */
  async verifyAttestation(): Promise<AttestationResponse> {
    const res = await globalThis.fetch(`${this.enclaveUrl}/v1/attestation`);
    if (!res.ok) {
      throw new Error(`Attestation fetch failed: ${res.status}`);
    }
    const attestation: AttestationResponse = await res.json();

    // Phase 1 local dev: basic validation only
    // Production: verify AWS Nitro attestation document, PCR values, etc.
    if (attestation.vaultConfig !== this.vaultAddress.toBase58()) {
      throw new Error("Vault config mismatch in attestation");
    }

    this.cachedAttestation = attestation;
    return attestation;
  }

  // ── Deposit ──

  /**
   * Deposit USDC into the vault on-chain.
   * @param amount Amount in atomic units (e.g., 1_000_000 = 1 USDC)
   * @param program Anchor program instance
   */
  async deposit(
    amount: number,
    program: anchor.Program,
    usdcMint: PublicKey
  ): Promise<string> {
    const clientAta = getAssociatedTokenAddressSync(
      usdcMint,
      this.wallet.publicKey
    );

    const [vaultTokenAccountPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault_token"), this.vaultAddress.toBuffer()],
      program.programId
    );

    const txSig = await program.methods
      .deposit(new BN(amount))
      .accounts({
        client: this.wallet.publicKey,
        vaultConfig: this.vaultAddress,
        clientTokenAccount: clientAta,
        vaultTokenAccount: vaultTokenAccountPda,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();

    return txSig;
  }

  // ── Withdraw ──

  /**
   * Withdraw USDC from the vault. Requests authorization from enclave.
   * @param amount Amount in atomic units
   * @param program Anchor program instance
   */
  async withdraw(
    amount: number,
    program: anchor.Program,
    usdcMint: PublicKey
  ): Promise<string> {
    const clientAta = getAssociatedTokenAddressSync(
      usdcMint,
      this.wallet.publicKey
    );

    // Request withdraw authorization from enclave
    const authRes = await globalThis.fetch(
      `${this.enclaveUrl}/v1/withdraw-auth`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: this.wallet.publicKey.toBase58(),
          recipientAta: clientAta.toBase58(),
          amount,
        }),
      }
    );

    if (!authRes.ok) {
      const err = await authRes.json();
      throw new Error(`Withdraw auth failed: ${err.message}`);
    }

    const auth: WithdrawAuthResponse = await authRes.json();

    const [usedNoncePda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("withdraw_nonce"),
        this.vaultAddress.toBuffer(),
        this.wallet.publicKey.toBuffer(),
        new BN(auth.withdrawNonce).toArrayLike(Buffer, "le", 8),
      ],
      program.programId
    );

    const signatureBytes = Buffer.from(auth.signature, "base64");
    const messageBytes = Buffer.from(auth.message, "base64");

    // Build Ed25519 precompile instruction
    const attestation = this.cachedAttestation || (await this.verifyAttestation());
    const vaultSignerPubkey = new PublicKey(attestation.vaultSigner);

    const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
      publicKey: vaultSignerPubkey.toBytes(),
      message: messageBytes,
      signature: signatureBytes,
    });

    const withdrawIx = await program.methods
      .withdraw(
        new BN(amount),
        new BN(auth.withdrawNonce),
        new BN(auth.expiresAt),
        Array.from(signatureBytes) as any
      )
      .accounts({
        client: this.wallet.publicKey,
        vaultConfig: this.vaultAddress,
        vaultTokenAccount: PublicKey.findProgramAddressSync(
          [Buffer.from("vault_token"), this.vaultAddress.toBuffer()],
          program.programId
        )[0],
        clientTokenAccount: clientAta,
        usedWithdrawNonce: usedNoncePda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .instruction();

    const latestBlockhash = await this.connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: this.wallet.publicKey,
      recentBlockhash: latestBlockhash.blockhash,
      instructions: [ed25519Ix, withdrawIx],
    }).compileToV0Message();

    const tx = new VersionedTransaction(messageV0);
    // Sign with the wallet keypair
    const signer = Keypair.fromSecretKey(this.wallet.secretKey);
    tx.sign([signer]);

    const txSig = await this.connection.sendTransaction(tx);
    await this.connection.confirmTransaction({
      signature: txSig,
      blockhash: latestBlockhash.blockhash,
      lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
    });

    return txSig;
  }

  // ── Balance ──

  /** Query client balance from enclave. */
  async getBalance(): Promise<BalanceResponse> {
    const res = await globalThis.fetch(`${this.enclaveUrl}/v1/balance`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: this.wallet.publicKey.toBase58(),
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(`Balance query failed: ${err.message || res.status}`);
    }

    return res.json();
  }

  // ── Receipt ──

  /**
   * Request a signed ParticipantReceipt from the enclave.
   * Used for force-settle (emergency withdrawal when enclave is down).
   */
  async getReceipt(usdcMint: PublicKey): Promise<ParticipantReceiptResponse> {
    const recipientAta = getAssociatedTokenAddressSync(
      usdcMint,
      this.wallet.publicKey
    );

    const res = await globalThis.fetch(`${this.enclaveUrl}/v1/receipt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: this.wallet.publicKey.toBase58(),
        recipientAta: recipientAta.toBase58(),
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(`Receipt request failed: ${err.message || res.status}`);
    }

    return res.json();
  }

  // ── Force Settle ──

  /**
   * Initiate a force settle using a ParticipantReceipt.
   * Used when the enclave is unresponsive and funds need to be recovered.
   */
  async forceSettle(
    receipt: ParticipantReceiptResponse,
    program: anchor.Program
  ): Promise<string> {
    const participantKind = receipt.participantKind;
    const signatureBytes = Buffer.from(receipt.signature, "base64");
    const messageBytes = Buffer.from(receipt.message, "base64");

    const [forceSettlePda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("force_settle"),
        this.vaultAddress.toBuffer(),
        this.wallet.publicKey.toBuffer(),
        Buffer.from([participantKind]),
      ],
      program.programId
    );

    const attestation =
      this.cachedAttestation || (await this.verifyAttestation());
    const vaultSignerPubkey = new PublicKey(attestation.vaultSigner);

    // Build Ed25519 precompile instruction for receipt verification
    const ed25519Ix = Ed25519Program.createInstructionWithPublicKey({
      publicKey: vaultSignerPubkey.toBytes(),
      message: messageBytes,
      signature: signatureBytes,
    });

    const recipientAta = new PublicKey(receipt.recipientAta);

    const forceSettleIx = await program.methods
      .forceSettleInit(
        participantKind,
        recipientAta,
        new BN(receipt.freeBalance),
        new BN(receipt.lockedBalance),
        new BN(receipt.maxLockExpiresAt),
        new BN(receipt.nonce),
        Array.from(signatureBytes) as any,
        Array.from(messageBytes)
      )
      .accounts({
        participant: this.wallet.publicKey,
        vaultConfig: this.vaultAddress,
        forceSettleRequest: forceSettlePda,
        instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    const latestBlockhash = await this.connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: this.wallet.publicKey,
      recentBlockhash: latestBlockhash.blockhash,
      instructions: [ed25519Ix, forceSettleIx],
    }).compileToV0Message();

    const tx = new VersionedTransaction(messageV0);
    const signer = Keypair.fromSecretKey(this.wallet.secretKey);
    tx.sign([signer]);

    const txSig = await this.connection.sendTransaction(tx);
    await this.connection.confirmTransaction({
      signature: txSig,
      blockhash: latestBlockhash.blockhash,
      lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
    });

    return txSig;
  }

  // ── x402-compatible fetch ──

  /**
   * Fetch a URL with automatic x402 payment handling.
   * If the server returns 402, constructs and sends payment signature.
   */
  async fetch(
    url: string,
    options?: RequestInit
  ): Promise<Response> {
    // First request (no payment)
    const initialRes = await globalThis.fetch(url, options);

    if (initialRes.status !== 402) {
      return initialRes;
    }

    // Parse 402 response
    const body: PaymentRequiredResponse = await initialRes.json();
    const details = body.accepts?.find(
      (a) => a.scheme === "a402-svm-v1"
    );

    if (!details) {
      throw new Error("No a402-svm-v1 payment option in 402 response");
    }

    // Verify attestation if not cached
    if (!this.cachedAttestation) {
      await this.verifyAttestation();
    }

    // Build payment payload
    const payload = await this.buildPaymentPayload(url, options, details);

    // Base64URL encode payload
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString(
      "base64url"
    );

    // Retry with payment signature
    const retryHeaders = new Headers(options?.headers || {});
    retryHeaders.set("PAYMENT-SIGNATURE", payloadB64);

    const retryRes = await globalThis.fetch(url, {
      ...options,
      headers: retryHeaders,
    });

    return retryRes;
  }

  // ── Internal helpers ──

  private async buildPaymentPayload(
    url: string,
    options: RequestInit | undefined,
    details: PaymentDetails
  ): Promise<PaymentPayload> {
    const parsedUrl = new URL(url);
    const method = (options?.method || "GET").toUpperCase();
    const origin = parsedUrl.origin;
    const pathAndQuery = parsedUrl.pathname + parsedUrl.search;
    const bodyStr = options?.body?.toString() || "";
    const bodySha256 = sha256hex(bodyStr);

    const paymentDetailsHash = computePaymentDetailsHash(details);
    const requestHash = computeRequestHash(
      method,
      origin,
      pathAndQuery,
      bodySha256,
      paymentDetailsHash
    );

    const paymentId = `pay_${crypto.randomUUID()}`;
    const nonce = Date.now().toString();
    const expiresAt = new Date(
      Date.now() + 30 * 60 * 1000
    ).toISOString();

    const sigMessage = buildSignatureMessage({
      version: 1,
      scheme: "a402-svm-v1",
      paymentId,
      client: this.wallet.publicKey.toBase58(),
      vault: details.vault.config,
      providerId: details.providerId,
      payTo: details.payTo,
      network: details.network,
      assetMint: details.asset.mint,
      amount: details.amount,
      requestHash,
      paymentDetailsHash,
      expiresAt,
      nonce,
    });

    const signature = ed25519Sign(sigMessage, this.wallet.secretKey);
    const clientSig = Buffer.from(signature).toString("base64");

    return {
      version: 1,
      scheme: "a402-svm-v1",
      paymentId,
      client: this.wallet.publicKey.toBase58(),
      vault: details.vault.config,
      providerId: details.providerId,
      payTo: details.payTo,
      network: details.network,
      assetMint: details.asset.mint,
      amount: details.amount,
      requestHash,
      paymentDetailsHash,
      expiresAt,
      nonce,
      clientSig,
    };
  }
}
