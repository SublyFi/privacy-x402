import { createHash } from "crypto";
import nacl from "tweetnacl";
import { PaymentDetails } from "./types";

/** Compute SHA-256 hash, return hex string */
export function sha256hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Compute SHA-256 hash of canonical JSON payment details */
export function computePaymentDetailsHash(
  details: PaymentDetails
): string {
  const canonical = JSON.stringify(details);
  return sha256hex(canonical);
}

/**
 * Compute requestHash per A402-SVM-V1 spec:
 * SHA-256("A402-SVM-V1-REQ\n" || METHOD || "\n" || ORIGIN || "\n" ||
 *         PATH_AND_QUERY || "\n" || BODY_SHA256_HEX || "\n" ||
 *         PAYMENT_DETAILS_HASH_HEX || "\n")
 */
export function computeRequestHash(
  method: string,
  origin: string,
  pathAndQuery: string,
  bodySha256: string,
  paymentDetailsHash: string
): string {
  const preimage =
    `A402-SVM-V1-REQ\n` +
    `${method}\n` +
    `${origin}\n` +
    `${pathAndQuery}\n` +
    `${bodySha256}\n` +
    `${paymentDetailsHash}\n`;
  return sha256hex(preimage);
}

/**
 * Build client signature message per spec:
 * "A402-SVM-V1-AUTH\n" followed by each field + "\n"
 */
export function buildSignatureMessage(fields: {
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
}): Uint8Array {
  const message =
    `A402-SVM-V1-AUTH\n` +
    `${fields.version}\n` +
    `${fields.scheme}\n` +
    `${fields.paymentId}\n` +
    `${fields.client}\n` +
    `${fields.vault}\n` +
    `${fields.providerId}\n` +
    `${fields.payTo}\n` +
    `${fields.network}\n` +
    `${fields.assetMint}\n` +
    `${fields.amount}\n` +
    `${fields.requestHash}\n` +
    `${fields.paymentDetailsHash}\n` +
    `${fields.expiresAt}\n` +
    `${fields.nonce}\n`;
  return new TextEncoder().encode(message);
}

/** Sign a message with Ed25519 */
export function ed25519Sign(
  message: Uint8Array,
  secretKey: Uint8Array
): Uint8Array {
  return nacl.sign.detached(message, secretKey);
}
