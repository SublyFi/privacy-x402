import type { Request, Response, NextFunction } from "express";

/** Provider payment configuration */
export interface Subly402ProviderConfig {
  /** Base URL of the enclave facilitator */
  facilitatorUrl: string;
  /** Provider's registered ID */
  providerId: string;
  /** Provider auth mode used against the facilitator */
  authMode?: "none" | "bearer" | "api-key" | "mtls";
  /** Provider API key for facilitator auth */
  apiKey?: string;
  /** Optional mTLS client certificate configuration */
  mtls?: {
    certPath: string;
    keyPath: string;
    caPath?: string;
    serverName?: string;
  };
  /** Provider's settlement token account (base58) */
  payTo: string;
  /** CAIP-2 network identifier */
  network: string;
  /** SPL token mint address */
  assetMint: string;
  /** Asset decimals */
  assetDecimals: number;
  /** Asset symbol */
  assetSymbol: string;
  /** VaultConfig PDA address */
  vaultConfig: string;
  /** Vault signer pubkey */
  vaultSigner: string;
  /** Attestation policy hash */
  attestationPolicyHash: string;
}

/** Inputs required to produce an ASC delivery artifact */
export interface AscDeliveryInput {
  channelId: string;
  requestId: string;
  amount: string | number;
  requestHash: string;
  result: Uint8Array | Buffer | string;
  providerSecretKey?: Uint8Array | string;
  adaptorSecret?: Uint8Array | string;
}

/** Provider-generated ASC delivery payload */
export interface AscDeliveryArtifact {
  adaptorPoint: string;
  preSigRPrime: string;
  preSigSPrime: string;
  encryptedResult: string;
  resultHash: string;
  providerPubkey: string;
  adaptorSecret: string;
}

export interface AscClaimVoucher {
  message: string;
  signature: string;
  issuedAt: number;
  channelIdHash: string;
  requestIdHash: string;
}

/** Facilitator /v1/channel/deliver response */
export interface AscDeliverResponse {
  ok: boolean;
  channelId: string;
  status: string;
  claimVoucher: AscClaimVoucher;
}

/** Pricing function: given a request, return the price in atomic units (or null if free) */
export type PricingFn = (req: Request) => string | null;

/** Options for the subly402 middleware */
export interface Subly402MiddlewareOptions {
  config: Subly402ProviderConfig;
  /** Return the price for this request, or null if no payment required */
  pricing: PricingFn;
}

/** Extended request with payment context */
export interface Subly402Request extends Request {
  rawBody?: Buffer | string;
  subly402?: {
    verificationId: string;
    paymentId: string;
    amount: string;
    providerId: string;
  };
}

export interface SettlementStatusResponse {
  ok: boolean;
  settlementId: string;
  verificationId: string;
  providerId: string;
  status: string;
  batchId: number | null;
  txSignature: string | null;
}

export type Subly402Scheme = "exact" | "subly402-exact" | "subly402-svm-v1";

export interface Subly402RouteAccept {
  /** Developer-facing scheme. "exact" is mapped to the current subly402-svm-v1 wire scheme. */
  scheme?: Subly402Scheme;
  /** Human-readable price such as "$0.001", or atomic token units such as "1000". */
  price: string | number;
  /** CAIP-2 network identifier. */
  network: string;
  /** Optional provider identifier. If omitted, Subly402 derives one from network, asset mint, and payTo. */
  providerId?: string;
  /** Seller wallet owner. If payTo is omitted, Subly402 derives the seller's associated token account. */
  sellerWallet?: string;
  /** Provider settlement token account. Advanced override; normally derive this from sellerWallet. */
  payTo?: string;
  /** Optional per-route asset override. Defaults to the facilitator client's asset config. */
  asset?: {
    kind?: "spl-token";
    mint: string;
    decimals?: number;
    symbol?: string;
  };
  assetMint?: string;
  assetDecimals?: number;
  assetSymbol?: string;
}

export interface Subly402RouteConfig {
  accepts: Subly402RouteAccept[];
  description?: string;
  mimeType?: string;
}

export type Subly402Routes = Record<string, Subly402RouteConfig>;

export interface Subly402FacilitatorClientOptions {
  /** Base URL of the Subly402 facilitator / Nitro enclave ingress. */
  url: string;
  /** Provider API key used by the seller middleware for /verify and /settle. */
  providerApiKey?: string;
  authMode?: Subly402ProviderConfig["authMode"];
  mtls?: Subly402ProviderConfig["mtls"];
  /** Optional cached attestation fields. If omitted, middleware fetches /v1/attestation. */
  vaultConfig?: string;
  vaultSigner?: string;
  attestationPolicyHash?: string;
  /** Default settlement asset used by route accepts that omit asset fields. */
  assetMint?: string;
  assetDecimals?: number;
  assetSymbol?: string;
}
