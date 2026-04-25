import * as anchor from "@coral-xyz/anchor";
import { X509Certificate } from "node:crypto";
import { isIP } from "node:net";
import tls from "node:tls";
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

import { verifyNitroAttestationDocument } from "./attestation";
import {
  bodyToBytes,
  buildSignatureMessage,
  computePaymentDetailsHash,
  computeRequestHash,
  ed25519Sign,
  sha256hex,
} from "./crypto";
import {
  AttestationResponse,
  BalanceResponse,
  ChannelFinalizeResponse,
  ChannelRequestResponse,
  CloseChannelResponse,
  OpenChannelResponse,
  ParticipantReceiptResponse,
  PaymentDetails,
  PaymentPayload,
  PaymentRequiredResponse,
  PaymentResponse,
  SettleResponse,
  Subly402VaultClientConfig,
  VerifyResponse,
  WithdrawAuthResponse,
} from "./types";

type ErrorResponse = {
  message?: string;
};

type LocalDevAttestationDocument = {
  version: number;
  mode: string;
  vaultConfig: string;
  vaultSigner: string;
  attestationPolicyHash: string;
  recipientPublicKeyPem: string;
  recipientPublicKeySha256: string;
  tlsPublicKeyPem?: string;
  tlsPublicKeySha256?: string;
  manifestHash?: string;
  snapshotSeqno?: number;
  issuedAt: string;
  expiresAt: string;
};

async function readJson<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

function decodeJsonHeader<T>(value: string, headerName: string): T {
  const encodings: Array<"base64" | "base64url"> = ["base64", "base64url"];
  let lastError: unknown;

  for (const encoding of encodings) {
    try {
      const decoded = Buffer.from(value, encoding).toString("utf8");
      return JSON.parse(decoded) as T;
    } catch (error) {
      lastError = error;
    }
  }

  const reason =
    lastError instanceof Error ? lastError.message : "invalid encoded JSON";
  throw new Error(`Invalid ${headerName} header: ${reason}`);
}

async function readPaymentRequiredResponse(
  response: Response
): Promise<PaymentRequiredResponse> {
  const header =
    response.headers.get("PAYMENT-REQUIRED") ??
    response.headers.get("payment-required");
  if (header) {
    return decodeJsonHeader<PaymentRequiredResponse>(
      header,
      "PAYMENT-REQUIRED"
    );
  }

  return readJson<PaymentRequiredResponse>(response);
}

export async function probeTlsPublicKeySha256(
  urlString: string
): Promise<string> {
  const url = new URL(urlString);
  if (url.protocol !== "https:") {
    throw new Error("TLS endpoint binding requires an https:// enclaveUrl");
  }

  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port || 443),
      servername: isIP(url.hostname) === 0 ? url.hostname : undefined,
      rejectUnauthorized: false,
    });

    socket.once("secureConnect", () => {
      try {
        const certificate = socket.getPeerCertificate(true);
        if (!certificate || !certificate.raw) {
          throw new Error("TLS peer certificate is missing");
        }
        const x509 = new X509Certificate(certificate.raw);
        const publicKeyDer = x509.publicKey.export({
          format: "der",
          type: "spki",
        }) as Buffer;
        resolve(sha256hex(publicKeyDer));
      } catch (error) {
        reject(error);
      } finally {
        socket.end();
      }
    });

    socket.once("error", (error) => {
      reject(error);
    });
  });
}

async function verifyAttestedTlsEndpointBinding(
  enclaveUrl: string,
  expectedTlsPublicKeySha256: string | undefined,
  allowMissingForLocalDev: boolean
): Promise<void> {
  if (!expectedTlsPublicKeySha256) {
    if (allowMissingForLocalDev) {
      return;
    }
    throw new Error(
      "Non-local attestation is missing attested tlsPublicKeySha256"
    );
  }

  const observedTlsPublicKeySha256 = await probeTlsPublicKeySha256(enclaveUrl);
  if (
    normalizeHex(observedTlsPublicKeySha256) !==
    normalizeHex(expectedTlsPublicKeySha256)
  ) {
    throw new Error(
      "Enclave TLS endpoint certificate does not match attested tlsPublicKeySha256"
    );
  }
}

/**
 * Subly402 vault client SDK — deposit, withdraw, and direct enclave fetch.
 */
export class Subly402VaultClient {
  private wallet: { publicKey: PublicKey; secretKey: Uint8Array };
  private vaultAddress: PublicKey;
  private enclaveUrl: string;
  private connection: Connection;
  private cachedAttestation: AttestationResponse | null = null;
  private latestClientReceipt: ParticipantReceiptResponse | null = null;
  private nitroAttestation: Subly402VaultClientConfig["nitroAttestation"];
  private attestationVerifier: Subly402VaultClientConfig["attestationVerifier"];

  constructor(config: Subly402VaultClientConfig) {
    this.wallet = config.walletKeypair;
    this.vaultAddress = config.vaultAddress;
    this.enclaveUrl = config.enclaveUrl.replace(/\/$/, "");
    this.nitroAttestation = config.nitroAttestation;
    this.attestationVerifier = config.attestationVerifier;
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
    const attestation = await readJson<AttestationResponse>(res);

    if (attestation.vaultConfig !== this.vaultAddress.toBase58()) {
      throw new Error("Vault config mismatch in attestation");
    }
    const issuedAtMs = Date.parse(attestation.issuedAt);
    const expiresAtMs = Date.parse(attestation.expiresAt);
    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)) {
      throw new Error("Attestation timestamps are invalid");
    }
    if (expiresAtMs <= Date.now()) {
      throw new Error("Attestation has expired");
    }
    if (expiresAtMs <= issuedAtMs) {
      throw new Error("Attestation expiry must be after issuance");
    }

    const decodedDocument = Buffer.from(
      attestation.attestationDocument,
      "base64"
    );
    const decodedText = decodedDocument.toString("utf8");
    let localDocument: LocalDevAttestationDocument | null = null;
    try {
      localDocument = JSON.parse(decodedText) as LocalDevAttestationDocument;
    } catch {
      localDocument = null;
    }

    let isLocalDevAttestation = false;
    if (localDocument?.mode === "local-dev") {
      isLocalDevAttestation = true;
      this.verifyLocalAttestationDocument(attestation, localDocument);
    } else if (this.nitroAttestation) {
      await verifyNitroAttestationDocument(attestation, {
        ...this.nitroAttestation,
        expectedVaultSigner:
          this.nitroAttestation.expectedVaultSigner ?? attestation.vaultSigner,
        requireSubly402UserData:
          this.nitroAttestation.requireSubly402UserData ?? true,
      });
      if (this.attestationVerifier) {
        await this.attestationVerifier(attestation);
      }
    } else if (this.attestationVerifier) {
      await this.attestationVerifier(attestation);
    } else {
      throw new Error(
        "Non-local attestation document requires nitroAttestation or attestationVerifier"
      );
    }

    await verifyAttestedTlsEndpointBinding(
      this.enclaveUrl,
      attestation.tlsPublicKeySha256,
      isLocalDevAttestation
    );

    this.cachedAttestation = attestation;
    return attestation;
  }

  private verifyLocalAttestationDocument(
    attestation: AttestationResponse,
    document: LocalDevAttestationDocument
  ): void {
    if (document.version !== 1) {
      throw new Error("Unsupported local attestation document version");
    }
    if (document.vaultConfig !== attestation.vaultConfig) {
      throw new Error("Local attestation document vaultConfig mismatch");
    }
    if (document.vaultSigner !== attestation.vaultSigner) {
      throw new Error("Local attestation document vaultSigner mismatch");
    }
    if (
      document.attestationPolicyHash.toLowerCase() !==
      attestation.attestationPolicyHash.toLowerCase()
    ) {
      throw new Error("Local attestation document policy hash mismatch");
    }
    if (!document.recipientPublicKeyPem.includes("BEGIN PUBLIC KEY")) {
      throw new Error("Local attestation document recipient key is invalid");
    }
    if (
      document.tlsPublicKeyPem &&
      !document.tlsPublicKeyPem.includes("BEGIN PUBLIC KEY")
    ) {
      throw new Error("Local attestation document TLS public key is invalid");
    }
    if (
      document.snapshotSeqno !== undefined &&
      !Number.isFinite(document.snapshotSeqno)
    ) {
      throw new Error("Local attestation document snapshotSeqno is invalid");
    }
    if (
      document.snapshotSeqno !== undefined &&
      attestation.snapshotSeqno === undefined
    ) {
      throw new Error(
        "Local attestation response is missing snapshotSeqno binding"
      );
    }
    if (
      document.snapshotSeqno !== undefined &&
      document.snapshotSeqno !== attestation.snapshotSeqno
    ) {
      throw new Error("Local attestation document snapshotSeqno mismatch");
    }
    if (
      document.tlsPublicKeySha256 !== undefined &&
      attestation.tlsPublicKeySha256 === undefined
    ) {
      throw new Error(
        "Local attestation response is missing TLS public key binding"
      );
    }
    if (
      document.tlsPublicKeySha256 !== undefined &&
      normalizeHex(document.tlsPublicKeySha256) !==
        normalizeHex(attestation.tlsPublicKeySha256 ?? "")
    ) {
      throw new Error("Local attestation document TLS public key mismatch");
    }
    if (
      document.manifestHash !== undefined &&
      attestation.manifestHash === undefined
    ) {
      throw new Error("Local attestation response is missing manifestHash");
    }
    if (
      document.manifestHash !== undefined &&
      normalizeHex(document.manifestHash) !==
        normalizeHex(attestation.manifestHash ?? "")
    ) {
      throw new Error("Local attestation document manifestHash mismatch");
    }

    const docIssuedAtMs = Date.parse(document.issuedAt);
    const docExpiresAtMs = Date.parse(document.expiresAt);
    if (!Number.isFinite(docIssuedAtMs) || !Number.isFinite(docExpiresAtMs)) {
      throw new Error("Local attestation document timestamps are invalid");
    }
    if (docExpiresAtMs <= Date.now()) {
      throw new Error("Local attestation document has expired");
    }
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
      .accountsPartial({
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
    const authRequest = this.buildClientAuth((issuedAt, expiresAt) =>
      [
        "SUBLY402-CLIENT-WITHDRAW-AUTH",
        this.wallet.publicKey.toBase58(),
        clientAta.toBase58(),
        String(amount),
        String(issuedAt),
        String(expiresAt),
        "",
      ].join("\n")
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
          issuedAt: authRequest.issuedAt,
          expiresAt: authRequest.expiresAt,
          clientSig: authRequest.clientSig,
        }),
      }
    );

    if (!authRes.ok) {
      const err = await readJson<ErrorResponse>(authRes);
      throw new Error(`Withdraw auth failed: ${err.message}`);
    }

    const auth = await readJson<WithdrawAuthResponse>(authRes);

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
    const attestation =
      this.cachedAttestation || (await this.verifyAttestation());
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
      .accountsPartial({
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
    const auth = this.buildClientAuth((issuedAt, expiresAt) =>
      [
        "SUBLY402-CLIENT-BALANCE",
        this.wallet.publicKey.toBase58(),
        String(issuedAt),
        String(expiresAt),
        "",
      ].join("\n")
    );
    const res = await globalThis.fetch(`${this.enclaveUrl}/v1/balance`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: this.wallet.publicKey.toBase58(),
        issuedAt: auth.issuedAt,
        expiresAt: auth.expiresAt,
        clientSig: auth.clientSig,
      }),
    });

    if (!res.ok) {
      const err = await readJson<ErrorResponse>(res);
      throw new Error(`Balance query failed: ${err.message || res.status}`);
    }

    return readJson<BalanceResponse>(res);
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
    const auth = this.buildClientAuth((issuedAt, expiresAt) =>
      [
        "SUBLY402-CLIENT-RECEIPT",
        this.wallet.publicKey.toBase58(),
        recipientAta.toBase58(),
        String(issuedAt),
        String(expiresAt),
        "",
      ].join("\n")
    );

    const res = await globalThis.fetch(`${this.enclaveUrl}/v1/receipt`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: this.wallet.publicKey.toBase58(),
        recipientAta: recipientAta.toBase58(),
        issuedAt: auth.issuedAt,
        expiresAt: auth.expiresAt,
        clientSig: auth.clientSig,
      }),
    });

    if (!res.ok) {
      const err = await readJson<ErrorResponse>(res);
      throw new Error(`Receipt request failed: ${err.message || res.status}`);
    }

    const receipt = await readJson<ParticipantReceiptResponse>(res);
    this.rememberClientReceipt(receipt);
    return receipt;
  }

  /** Return the most recently cached client receipt, if any. */
  getLatestClientReceipt(): ParticipantReceiptResponse | null {
    return this.latestClientReceipt;
  }

  /** Restore or update the cached client receipt. */
  rememberClientReceipt(receipt: ParticipantReceiptResponse): void {
    if (receipt.participant !== this.wallet.publicKey.toBase58()) {
      throw new Error("Receipt participant does not match the current wallet");
    }
    if (receipt.vaultConfig !== this.vaultAddress.toBase58()) {
      throw new Error("Receipt vaultConfig does not match this client vault");
    }
    this.latestClientReceipt = receipt;
  }

  // ── Force Settle ──

  /**
   * Initiate a force settle using a ParticipantReceipt.
   * Used when the enclave is unresponsive and funds need to be recovered.
   */
  async forceSettle(
    receipt: ParticipantReceiptResponse | undefined,
    program: anchor.Program
  ): Promise<string> {
    const resolvedReceipt = receipt ?? this.latestClientReceipt;
    if (!resolvedReceipt) {
      throw new Error("No cached client receipt is available for force-settle");
    }
    this.rememberClientReceipt(resolvedReceipt);

    const participantKind = resolvedReceipt.participantKind;
    const signatureBytes = Buffer.from(resolvedReceipt.signature, "base64");
    const messageBytes = Buffer.from(resolvedReceipt.message, "base64");

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

    const recipientAta = new PublicKey(resolvedReceipt.recipientAta);

    const forceSettleIx = await program.methods
      .forceSettleInit(
        participantKind,
        recipientAta,
        new BN(resolvedReceipt.freeBalance),
        new BN(resolvedReceipt.lockedBalance),
        new BN(resolvedReceipt.maxLockExpiresAt),
        new BN(resolvedReceipt.nonce),
        Array.from(signatureBytes) as any,
        Array.from(messageBytes)
      )
      .accountsPartial({
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

  /**
   * Finalize a previously initiated force settle after the dispute window elapses.
   */
  async finalizeForceSettle(
    program: anchor.Program,
    receipt?: ParticipantReceiptResponse
  ): Promise<string> {
    const resolvedReceipt = receipt ?? this.latestClientReceipt;
    if (!resolvedReceipt) {
      throw new Error("No cached client receipt is available for force-settle");
    }
    this.rememberClientReceipt(resolvedReceipt);

    const participantKind = resolvedReceipt.participantKind;
    const [forceSettlePda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from("force_settle"),
        this.vaultAddress.toBuffer(),
        this.wallet.publicKey.toBuffer(),
        Buffer.from([participantKind]),
      ],
      program.programId
    );

    const recipientAta = new PublicKey(resolvedReceipt.recipientAta);
    const [vaultTokenAccountPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("vault_token"), this.vaultAddress.toBuffer()],
      program.programId
    );

    const finalizeIx = await program.methods
      .forceSettleFinalize()
      .accountsPartial({
        caller: this.wallet.publicKey,
        vaultConfig: this.vaultAddress,
        forceSettleRequest: forceSettlePda,
        vaultTokenAccount: vaultTokenAccountPda,
        recipientTokenAccount: recipientAta,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .instruction();

    const latestBlockhash = await this.connection.getLatestBlockhash();
    const messageV0 = new TransactionMessage({
      payerKey: this.wallet.publicKey,
      recentBlockhash: latestBlockhash.blockhash,
      instructions: [finalizeIx],
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
  async fetch(url: string, options?: RequestInit): Promise<Response> {
    // First request (no payment)
    const initialRes = await globalThis.fetch(url, options);

    if (initialRes.status !== 402) {
      return initialRes;
    }

    // Parse 402 response
    const body = await readPaymentRequiredResponse(initialRes);
    const details = body.accepts?.find((a) => a.scheme === "subly402-svm-v1");

    if (!details) {
      throw new Error("No subly402-svm-v1 payment option in 402 response");
    }

    // Verify attestation if not cached
    if (!this.cachedAttestation) {
      await this.verifyAttestation();
    }

    // Build payment payload
    const payload = await this.buildPaymentPayload(url, options, details);

    // x402 v2 headers are standard Base64-encoded JSON.
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64");

    // Retry with payment signature
    const retryHeaders = new Headers(options?.headers || {});
    retryHeaders.set("PAYMENT-SIGNATURE", payloadB64);

    const retryRes = await globalThis.fetch(url, {
      ...options,
      headers: retryHeaders,
    });

    return retryRes;
  }

  // ── Phase 3: Atomic Service Channel ──

  /**
   * Open an Atomic Service Channel with a provider.
   * @param providerId Provider identifier
   * @param initialDeposit Amount to lock in the channel (atomic units)
   */
  async openChannel(
    providerId: string,
    initialDeposit: number
  ): Promise<OpenChannelResponse> {
    const message =
      `SUBLY402-CHANNEL-OPEN\n` +
      `${this.wallet.publicKey.toBase58()}\n` +
      `${providerId}\n` +
      `${initialDeposit}\n`;
    const clientSig = this.signTextMessage(message);

    const res = await globalThis.fetch(`${this.enclaveUrl}/v1/channel/open`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: this.wallet.publicKey.toBase58(),
        providerId,
        initialDeposit,
        clientSig,
      }),
    });

    if (!res.ok) {
      const err = (await res.json()) as { message?: string };
      throw new Error(`Channel open failed: ${err.message || res.status}`);
    }

    return (await res.json()) as OpenChannelResponse;
  }

  /**
   * Submit a request within an open channel (locks funds for this request).
   */
  async channelRequest(
    channelId: string,
    requestId: string,
    amount: number,
    requestHash: string
  ): Promise<ChannelRequestResponse> {
    const message =
      `SUBLY402-CHANNEL-REQUEST\n` +
      `${channelId}\n` +
      `${requestId}\n` +
      `${amount}\n` +
      `${requestHash}\n`;
    const clientSig = this.signTextMessage(message);

    const res = await globalThis.fetch(
      `${this.enclaveUrl}/v1/channel/request`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          channelId,
          requestId,
          amount,
          requestHash,
          clientSig,
        }),
      }
    );

    if (!res.ok) {
      const err = (await res.json()) as { message?: string };
      throw new Error(`Channel request failed: ${err.message || res.status}`);
    }

    return (await res.json()) as ChannelRequestResponse;
  }

  /**
   * Finalize an off-chain exchange by providing the adaptor secret.
   * Returns the decrypted result.
   */
  async channelFinalize(
    channelId: string,
    adaptorSecret: string
  ): Promise<ChannelFinalizeResponse> {
    const message =
      `SUBLY402-CHANNEL-FINALIZE\n` + `${channelId}\n` + `${adaptorSecret}\n`;
    const clientSig = this.signTextMessage(message);

    const res = await globalThis.fetch(
      `${this.enclaveUrl}/v1/channel/finalize`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          channelId,
          adaptorSecret,
          clientSig,
        }),
      }
    );

    if (!res.ok) {
      const err = (await res.json()) as { message?: string };
      throw new Error(`Channel finalize failed: ${err.message || res.status}`);
    }

    return (await res.json()) as ChannelFinalizeResponse;
  }

  /**
   * Close an ASC and settle accumulated provider earnings.
   */
  async closeChannel(channelId: string): Promise<CloseChannelResponse> {
    const message = `SUBLY402-CHANNEL-CLOSE\n${channelId}\n`;
    const clientSig = this.signTextMessage(message);

    const res = await globalThis.fetch(`${this.enclaveUrl}/v1/channel/close`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ channelId, clientSig }),
    });

    if (!res.ok) {
      const err = (await res.json()) as { message?: string };
      throw new Error(`Channel close failed: ${err.message || res.status}`);
    }

    return (await res.json()) as CloseChannelResponse;
  }

  private buildClientAuth(
    buildMessage: (issuedAt: number, expiresAt: number) => string
  ): { issuedAt: number; expiresAt: number; clientSig: string } {
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + 300;
    const clientSig = this.signTextMessage(buildMessage(issuedAt, expiresAt));
    return { issuedAt, expiresAt, clientSig };
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
    const bodySha256 = sha256hex(bodyToBytes(options?.body));

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
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();

    const sigMessage = buildSignatureMessage({
      version: 1,
      scheme: "subly402-svm-v1",
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
      scheme: "subly402-svm-v1",
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

  private signTextMessage(message: string): string {
    const messageBytes = new TextEncoder().encode(message);
    const signature = ed25519Sign(messageBytes, this.wallet.secretKey);
    return Buffer.from(signature).toString("base64");
  }
}

function normalizeHex(value: string): string {
  return value.toLowerCase().replace(/^0x/, "");
}
