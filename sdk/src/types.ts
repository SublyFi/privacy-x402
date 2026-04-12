import { PublicKey } from "@solana/web3.js";

/** Payment details from a 402 response */
export interface PaymentDetails {
  scheme: "a402-svm-v1";
  network: string;
  amount: string;
  asset: {
    kind: string;
    mint: string;
    decimals: number;
    symbol: string;
  };
  payTo: string;
  providerId: string;
  facilitatorUrl: string;
  vault: {
    config: string;
    signer: string;
    attestationPolicyHash: string;
  };
  paymentDetailsId: string;
  verifyWindowSec: number;
  maxSettlementDelaySec: number;
  privacyMode: string;
}

/** 402 Payment Required response body */
export interface PaymentRequiredResponse {
  accepts: PaymentDetails[];
}

/** Payment signature payload sent by client */
export interface PaymentPayload {
  version: number;
  scheme: string;
  paymentId: string;
  client: string;
  vault: string;
  providerId: string;
  payTo: string;
  network: string;
  assetMint: string;
  amount: string;
  requestHash: string;
  paymentDetailsHash: string;
  expiresAt: string;
  nonce: string;
  clientSig: string;
}

/** Facilitator /v1/verify response */
export interface VerifyResponse {
  ok: boolean;
  verificationId: string;
  reservationId: string;
  reservationExpiresAt: string;
  providerId: string;
  amount: string;
  verificationReceipt: string;
}

/** Facilitator /v1/settle response */
export interface SettleResponse {
  ok: boolean;
  settlementId: string;
  offchainSettledAt: string;
  providerCreditAmount: string;
  batchId: number | null;
  participantReceipt: string;
}

/** Facilitator /v1/attestation response */
export interface AttestationResponse {
  vaultConfig: string;
  vaultSigner: string;
  attestationPolicyHash: string;
  attestationDocument: string;
  issuedAt: string;
  expiresAt: string;
}

/** Facilitator /v1/withdraw-auth response */
export interface WithdrawAuthResponse {
  ok: boolean;
  withdrawNonce: number;
  expiresAt: number;
  signature: string;
  message: string;
}

/** PAYMENT-RESPONSE header content */
export interface PaymentResponse {
  scheme: string;
  paymentId: string;
  verificationId: string;
  settlementId: string;
  batchId: number | null;
  txSignature: string | null;
  participantReceipt: string;
}

/** A402Client configuration */
export interface A402ClientConfig {
  /** Client wallet keypair */
  walletKeypair: {
    publicKey: PublicKey;
    secretKey: Uint8Array;
  };
  /** VaultConfig PDA address */
  vaultAddress: PublicKey;
  /** Enclave facilitator base URL */
  enclaveUrl: string;
  /** Solana RPC URL */
  rpcUrl?: string;
}
