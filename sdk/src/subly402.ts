import { randomUUID } from "crypto";
import { createSignableMessage } from "@solana/kit";
import {
  bodyToBytes,
  buildSignatureMessage,
  computePaymentDetailsHash,
  computeRequestHash,
  ed25519Sign,
  sha256hex,
} from "./crypto";
import { verifyNitroAttestationDocument } from "./attestation";
import { probeTlsPublicKeySha256 } from "./tls";
import type {
  AttestationResponse,
  PaymentDetails,
  PaymentPayload,
  PaymentRequiredResponse,
  Subly402AutoDepositConfig,
  Subly402ClientConfig,
  Subly402Signer,
} from "./types";

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

type NormalizedAutoDepositConfig = Required<
  Pick<Subly402AutoDepositConfig, "deposit">
> &
  Omit<Subly402AutoDepositConfig, "deposit">;

type LocalDevAttestationDocument = {
  version: number;
  mode: string;
  vaultConfig: string;
  vaultSigner: string;
  attestationPolicyHash: string;
  tlsPublicKeySha256?: string;
  snapshotSeqno?: number;
  issuedAt: string;
  expiresAt: string;
};

function normalizeBaseUrl(url: string): string {
  return url.replace(/\/$/, "");
}

function networkMatches(pattern: string, network: string): boolean {
  if (pattern === "*" || pattern === network) {
    return true;
  }
  if (pattern.endsWith(":*")) {
    return network.startsWith(pattern.slice(0, -1));
  }
  return false;
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
    const decoded = decodeJsonHeader<PaymentRequiredResponse>(
      header,
      "PAYMENT-REQUIRED"
    );
    try {
      const body = (await response.clone().json()) as PaymentRequiredResponse;
      return { ...body, ...decoded };
    } catch {
      return decoded;
    }
  }

  return (await response.json()) as PaymentRequiredResponse;
}

function signerAddress(signer: Subly402Signer): string {
  if (signer.address) {
    return signer.address;
  }
  const publicKey = signer.publicKey;
  if (typeof publicKey === "string") {
    return publicKey;
  }
  if (publicKey && typeof publicKey.toBase58 === "function") {
    return publicKey.toBase58();
  }
  throw new Error("Subly402 signer public key is required");
}

async function signMessage(
  signer: Subly402Signer,
  message: Uint8Array
): Promise<string> {
  if (signer.signMessages) {
    const address = signerAddress(signer);
    const [signatures] = await signer.signMessages([
      createSignableMessage(message),
    ]);
    const signature =
      (signatures as Record<string, Uint8Array>)[address] ??
      Object.values(signatures)[0];
    if (!signature) {
      throw new Error("Subly402 signer did not return a message signature");
    }
    return Buffer.from(signature).toString("base64");
  }
  if (signer.signMessage) {
    const signature = await signer.signMessage(message);
    return Buffer.from(signature).toString("base64");
  }
  if (signer.secretKey) {
    return Buffer.from(ed25519Sign(message, signer.secretKey)).toString(
      "base64"
    );
  }
  throw new Error("Subly402 signer must provide signMessage or secretKey");
}

function parseAmountToAtomic(
  amount: string | number,
  decimals: number
): bigint {
  if (typeof amount === "number") {
    if (!Number.isFinite(amount) || amount < 0) {
      throw new Error("Subly402 amount must be a non-negative number");
    }
    return BigInt(Math.trunc(amount));
  }

  const trimmed = amount.trim();
  if (/^\d+$/.test(trimmed)) {
    return BigInt(trimmed);
  }

  const decimal = trimmed.startsWith("$") ? trimmed.slice(1) : trimmed;
  if (!/^\d+(\.\d+)?$/.test(decimal)) {
    throw new Error(`Unsupported Subly402 amount: ${amount}`);
  }

  const [whole, fraction = ""] = decimal.split(".");
  if (fraction.length > decimals) {
    throw new Error(
      `Subly402 amount ${amount} has more than ${decimals} decimal places`
    );
  }
  return (
    BigInt(whole) * 10n ** BigInt(decimals) +
    BigInt((fraction + "0".repeat(decimals)).slice(0, decimals) || "0")
  );
}

function normalizeAutoDeposit(
  autoDeposit: Subly402ClientConfig["autoDeposit"]
): NormalizedAutoDepositConfig | undefined {
  if (!autoDeposit) {
    return undefined;
  }
  if (typeof autoDeposit === "function") {
    return { mode: "on-demand", deposit: autoDeposit };
  }
  return {
    mode: autoDeposit.mode ?? "on-demand",
    maxDepositPerRequest: autoDeposit.maxDepositPerRequest,
    deposit: autoDeposit.deposit,
  };
}

function insufficientBalanceReason(
  body: PaymentRequiredResponse
): string | null {
  const code = body.facilitatorError ?? body.error;
  if (code === "insufficient_balance") {
    return code;
  }
  if (body.message?.toLowerCase().includes("insufficient")) {
    return body.message;
  }
  return null;
}

function depositSyncReason(body: PaymentRequiredResponse): string | null {
  const code = body.facilitatorError ?? body.error;
  if (code === "deposit_sync_in_progress") {
    return code;
  }
  if (body.message?.toLowerCase().includes("deposit synchronization")) {
    return body.message;
  }
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function decodeLocalAttestationDocument(
  attestation: AttestationResponse
): LocalDevAttestationDocument | null {
  try {
    return JSON.parse(
      Buffer.from(attestation.attestationDocument, "base64").toString("utf8")
    ) as LocalDevAttestationDocument;
  } catch {
    return null;
  }
}

function assertAttestationMatchesDetails(
  attestation: AttestationResponse,
  details: PaymentDetails
): void {
  if (attestation.vaultConfig !== details.vault.config) {
    throw new Error("Subly402 attestation vaultConfig mismatch");
  }
  if (attestation.vaultSigner !== details.vault.signer) {
    throw new Error("Subly402 attestation vaultSigner mismatch");
  }
  if (
    attestation.attestationPolicyHash.toLowerCase() !==
    details.vault.attestationPolicyHash.toLowerCase()
  ) {
    throw new Error("Subly402 attestation policy hash mismatch");
  }

  const issuedAtMs = Date.parse(attestation.issuedAt);
  const expiresAtMs = Date.parse(attestation.expiresAt);
  if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)) {
    throw new Error("Subly402 attestation timestamps are invalid");
  }
  if (expiresAtMs <= Date.now() || expiresAtMs <= issuedAtMs) {
    throw new Error("Subly402 attestation is expired or invalid");
  }
}

/**
 * Cache-entry freshness check. Returns a non-empty reason string when the
 * cached attestation should be evicted and re-fetched, or `null` to keep it.
 * Runs on every cache hit so long-lived buyer processes don't use stale or
 * details-mismatched attestations.
 *
 * - `EXPIRY_SAFETY_MARGIN_MS` — refuse to reuse an attestation that would
 *   expire while the pending request is still in flight.
 */
const EXPIRY_SAFETY_MARGIN_MS = 60 * 1000;
const DEPOSIT_SYNC_RETRY_ATTEMPTS = 12;
const DEPOSIT_SYNC_RETRY_DELAY_MS = 1000;

function cacheEntryStaleReason(
  cached: AttestationResponse,
  details: PaymentDetails
): string | null {
  if (cached.vaultConfig !== details.vault.config) {
    return "vaultConfig mismatch";
  }
  if (cached.vaultSigner !== details.vault.signer) {
    return "vaultSigner mismatch";
  }
  if (
    cached.attestationPolicyHash.toLowerCase() !==
    details.vault.attestationPolicyHash.toLowerCase()
  ) {
    return "attestationPolicyHash mismatch";
  }
  const expiresAtMs = Date.parse(cached.expiresAt);
  if (!Number.isFinite(expiresAtMs)) {
    return "invalid expiresAt";
  }
  if (expiresAtMs <= Date.now() + EXPIRY_SAFETY_MARGIN_MS) {
    return "near or past expiry";
  }
  return null;
}

function verifyLocalAttestationDocument(
  attestation: AttestationResponse,
  localDocument: LocalDevAttestationDocument
): void {
  if (localDocument.version !== 1 || localDocument.mode !== "local-dev") {
    throw new Error("Unsupported Subly402 local attestation document");
  }
  if (localDocument.vaultConfig !== attestation.vaultConfig) {
    throw new Error("Subly402 local attestation vaultConfig mismatch");
  }
  if (localDocument.vaultSigner !== attestation.vaultSigner) {
    throw new Error("Subly402 local attestation vaultSigner mismatch");
  }
  if (
    localDocument.attestationPolicyHash.toLowerCase() !==
    attestation.attestationPolicyHash.toLowerCase()
  ) {
    throw new Error("Subly402 local attestation policy hash mismatch");
  }
  if (
    localDocument.snapshotSeqno !== undefined &&
    localDocument.snapshotSeqno !== attestation.snapshotSeqno
  ) {
    throw new Error("Subly402 local attestation snapshotSeqno mismatch");
  }
}

async function verifyAttestedTlsBinding(
  facilitatorUrl: string,
  attestation: AttestationResponse,
  allowMissingForLocalDev: boolean
): Promise<void> {
  if (!attestation.tlsPublicKeySha256) {
    if (allowMissingForLocalDev) {
      return;
    }
    throw new Error(
      "Subly402 non-local attestation is missing attested tlsPublicKeySha256"
    );
  }

  const observed = await probeTlsPublicKeySha256(facilitatorUrl);
  if (observed.toLowerCase() !== attestation.tlsPublicKeySha256.toLowerCase()) {
    throw new Error("Subly402 attested TLS public key mismatch");
  }
}

export class Subly402Client {
  private readonly trustedFacilitators: string[];
  private readonly maxPaymentPerRequest?: string | number;
  private readonly autoDeposit?: NormalizedAutoDepositConfig;
  private readonly nitroAttestation: Subly402ClientConfig["nitroAttestation"];
  private readonly attestationVerifier: Subly402ClientConfig["attestationVerifier"];
  private readonly attestationCache = new Map<string, AttestationResponse>();
  private readonly schemes: Array<{
    network: string;
    scheme: Subly402ExactScheme;
  }> = [];
  private defaultScheme?: Subly402ExactScheme;

  constructor(config: Subly402ClientConfig = {}) {
    this.trustedFacilitators = (config.trustedFacilitators ?? []).map(
      normalizeBaseUrl
    );
    this.maxPaymentPerRequest = config.policy?.maxPaymentPerRequest;
    this.autoDeposit = normalizeAutoDeposit(config.autoDeposit);
    this.nitroAttestation = config.nitroAttestation;
    this.attestationVerifier = config.attestationVerifier;

    if (config.signer) {
      const scheme = new Subly402ExactScheme(config.signer);
      if (config.network) {
        this.register(config.network, scheme);
      } else {
        this.defaultScheme = scheme;
      }
    }
  }

  register(network: string, scheme: Subly402ExactScheme): this {
    this.schemes.push({ network, scheme });
    return this;
  }

  async fetch(
    input: string | URL,
    options?: RequestInit,
    fetchImpl: FetchLike = globalThis.fetch
  ): Promise<Response> {
    const url = input.toString();
    const initialRes = await fetchImpl(url, options);
    if (initialRes.status !== 402) {
      return initialRes;
    }

    const body = await readPaymentRequiredResponse(initialRes);
    const selected = body.accepts
      ?.map((accept) => ({
        details: accept,
        scheme:
          accept.scheme === "subly402-svm-v1"
            ? this.findSchemeForNetwork(accept.network)
            : undefined,
      }))
      .find(
        (candidate) =>
          candidate.details.scheme === "subly402-svm-v1" && candidate.scheme
      );
    if (!selected?.scheme) {
      throw new Error(
        "No Subly402-compatible payment option for registered networks"
      );
    }
    const { details, scheme } = selected;

    this.assertBudget(details);
    await this.verifyAttestation(details);

    const payload = await this.buildPaymentPayload(
      url,
      options,
      details,
      scheme.signer
    );
    const retryHeaders = new Headers(options?.headers || {});
    retryHeaders.set(
      "PAYMENT-SIGNATURE",
      Buffer.from(JSON.stringify(payload)).toString("base64")
    );

    const paidResponse = await fetchImpl(url, {
      ...options,
      headers: retryHeaders,
    });
    if (paidResponse.status !== 402 || !this.autoDeposit) {
      return paidResponse;
    }

    let retryBody: PaymentRequiredResponse;
    try {
      retryBody = await readPaymentRequiredResponse(paidResponse.clone());
    } catch {
      return paidResponse;
    }
    const reason = insufficientBalanceReason(retryBody);
    if (!reason) {
      return paidResponse;
    }

    await this.depositOnDemand(details, reason, 1);

    let lastSyncResponse: Response | null = null;
    for (let attempt = 0; attempt < DEPOSIT_SYNC_RETRY_ATTEMPTS; attempt += 1) {
      const secondPayload = await this.buildPaymentPayload(
        url,
        options,
        details,
        scheme.signer
      );
      const secondHeaders = new Headers(options?.headers || {});
      secondHeaders.set(
        "PAYMENT-SIGNATURE",
        Buffer.from(JSON.stringify(secondPayload)).toString("base64")
      );

      const retryResponse = await fetchImpl(url, {
        ...options,
        headers: secondHeaders,
      });
      if (retryResponse.status !== 402) {
        return retryResponse;
      }

      let retryBody: PaymentRequiredResponse;
      try {
        retryBody = await readPaymentRequiredResponse(retryResponse.clone());
      } catch {
        return retryResponse;
      }
      const syncReason = depositSyncReason(retryBody);
      if (!syncReason) {
        return retryResponse;
      }
      lastSyncResponse = retryResponse;
      await sleep(DEPOSIT_SYNC_RETRY_DELAY_MS);
    }

    return lastSyncResponse ?? paidResponse;
  }

  private findSchemeForNetwork(network: string): Subly402ExactScheme | null {
    for (const registered of this.schemes) {
      if (networkMatches(registered.network, network)) {
        return registered.scheme;
      }
    }
    return this.defaultScheme ?? null;
  }

  private assertBudget(details: PaymentDetails): void {
    if (this.maxPaymentPerRequest === undefined) {
      return;
    }
    const amount = BigInt(details.amount);
    const maxAmount = parseAmountToAtomic(
      this.maxPaymentPerRequest,
      details.asset.decimals
    );
    if (amount > maxAmount) {
      throw new Error(
        `Subly402 payment exceeds policy: ${
          details.amount
        } > ${maxAmount.toString()}`
      );
    }
  }

  private async depositOnDemand(
    details: PaymentDetails,
    reason: string,
    attempt: number
  ): Promise<void> {
    if (!this.autoDeposit) {
      return;
    }
    const amountAtomic = BigInt(details.amount);
    if (this.autoDeposit.maxDepositPerRequest !== undefined) {
      const maxDeposit = parseAmountToAtomic(
        this.autoDeposit.maxDepositPerRequest,
        details.asset.decimals
      );
      if (amountAtomic > maxDeposit) {
        throw new Error(
          `Subly402 autoDeposit exceeds policy: ${
            details.amount
          } > ${maxDeposit.toString()}`
        );
      }
    }

    await this.autoDeposit.deposit({
      amount: details.amount,
      amountAtomic,
      details,
      facilitatorUrl: normalizeBaseUrl(details.facilitatorUrl),
      reason,
      attempt,
    });
  }

  private async verifyAttestation(
    details: PaymentDetails
  ): Promise<AttestationResponse> {
    const facilitatorUrl = normalizeBaseUrl(details.facilitatorUrl);
    if (
      this.trustedFacilitators.length > 0 &&
      !this.trustedFacilitators.includes(facilitatorUrl)
    ) {
      throw new Error(`Untrusted Subly402 facilitator: ${facilitatorUrl}`);
    }

    const cached = this.attestationCache.get(facilitatorUrl);
    if (cached) {
      const staleReason = cacheEntryStaleReason(cached, details);
      if (!staleReason) {
        return cached;
      }
      this.attestationCache.delete(facilitatorUrl);
    }

    const response = await globalThis.fetch(`${facilitatorUrl}/v1/attestation`);
    if (!response.ok) {
      throw new Error(`Subly402 attestation fetch failed: ${response.status}`);
    }
    const attestation = (await response.json()) as AttestationResponse;
    assertAttestationMatchesDetails(attestation, details);

    const localDocument = decodeLocalAttestationDocument(attestation);
    const isLocalDevAttestation = localDocument?.mode === "local-dev";
    if (isLocalDevAttestation) {
      verifyLocalAttestationDocument(attestation, localDocument);
    } else if (this.nitroAttestation) {
      await verifyNitroAttestationDocument(attestation, {
        ...this.nitroAttestation,
        expectedPolicyHash:
          this.nitroAttestation.expectedPolicyHash ??
          details.vault.attestationPolicyHash,
        expectedVaultSigner:
          this.nitroAttestation.expectedVaultSigner ?? details.vault.signer,
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
        "Subly402Client requires nitroAttestation or attestationVerifier for non-local attestation"
      );
    }

    await verifyAttestedTlsBinding(
      facilitatorUrl,
      attestation,
      isLocalDevAttestation
    );

    this.attestationCache.set(facilitatorUrl, attestation);
    return attestation;
  }

  private async buildPaymentPayload(
    url: string,
    options: RequestInit | undefined,
    details: PaymentDetails,
    signer: Subly402Signer
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
    const paymentId = `pay_${randomUUID()}`;
    const nonce = Date.now().toString();
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const client = signerAddress(signer);

    const signatureMessage = buildSignatureMessage({
      version: 1,
      scheme: "subly402-svm-v1",
      paymentId,
      client,
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

    return {
      version: 1,
      scheme: "subly402-svm-v1",
      paymentId,
      client,
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
      clientSig: await signMessage(signer, signatureMessage),
    };
  }
}

export class Subly402ExactScheme {
  readonly scheme = "exact";
  readonly wireScheme = "subly402-svm-v1";

  constructor(readonly signer: Subly402Signer) {}
}

export function wrapFetchWithSubly402Payment(
  fetchImpl: FetchLike,
  client: Subly402Client
): FetchLike {
  return (input, init) => client.fetch(input, init, fetchImpl);
}
