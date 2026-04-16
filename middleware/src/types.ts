import type { Request, Response, NextFunction } from "express";

/** Provider payment configuration */
export interface A402ProviderConfig {
  /** Base URL of the enclave facilitator */
  facilitatorUrl: string;
  /** Provider's registered ID */
  providerId: string;
  /** Provider auth mode used against the facilitator */
  authMode?: "bearer" | "api-key" | "mtls";
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

/** Options for the a402 middleware */
export interface A402MiddlewareOptions {
  config: A402ProviderConfig;
  /** Return the price for this request, or null if no payment required */
  pricing: PricingFn;
}

/** Extended request with payment context */
export interface A402Request extends Request {
  rawBody?: Buffer | string;
  a402?: {
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
