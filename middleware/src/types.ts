import type { Request, Response, NextFunction } from "express";

/** Provider payment configuration */
export interface A402ProviderConfig {
  /** Base URL of the enclave facilitator */
  facilitatorUrl: string;
  /** Provider's registered ID */
  providerId: string;
  /** Provider API key for facilitator auth */
  apiKey: string;
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
  a402?: {
    verificationId: string;
    paymentId: string;
    amount: string;
    providerId: string;
  };
}
