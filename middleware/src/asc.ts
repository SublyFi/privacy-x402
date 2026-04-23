import * as anchor from "@coral-xyz/anchor";
import { createHash, randomBytes } from "crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  utf8ToBytes,
} from "@noble/hashes/utils";
import type {
  Subly402ProviderConfig,
  AscClaimVoucher,
  AscDeliverResponse,
  AscDeliveryArtifact,
  AscDeliveryInput,
} from "./types";
import { postFacilitatorJson } from "./facilitator";
import {
  Ed25519Program,
  Keypair,
  PublicKey,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  SystemProgram,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

const CURVE_ORDER =
  7237005577332262213973186563042994240857116359379907606001950938285454250989n;

function mod(value: bigint, order: bigint = CURVE_ORDER): bigint {
  const result = value % order;
  return result >= 0n ? result : result + order;
}

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    value = (value << 8n) + BigInt(bytes[i]);
  }
  return value;
}

function bigintToBytesLE(value: bigint, length = 32): Uint8Array {
  const out = new Uint8Array(length);
  let current = mod(value);
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(current & 0xffn);
    current >>= 8n;
  }
  return out;
}

function normalizeHex32(value: string, field: string): Uint8Array {
  const bytes = hexToBytes(value.toLowerCase());
  if (bytes.length !== 32) {
    throw new Error(`${field} must be 32 bytes`);
  }
  return bytes;
}

function normalizeSecretBytes(
  value: Uint8Array | string | undefined,
  field: string
): Uint8Array {
  if (!value) {
    return randomBytes(32);
  }
  if (typeof value === "string") {
    return normalizeHex32(value, field);
  }
  if (value.length !== 32) {
    throw new Error(`${field} must be 32 bytes`);
  }
  return Uint8Array.from(value);
}

function normalizeResultBytes(
  result: Uint8Array | Buffer | string
): Uint8Array {
  if (typeof result === "string") {
    return utf8ToBytes(result);
  }
  return Uint8Array.from(result);
}

function canonicalScalarBytes(
  source: Uint8Array | string | undefined,
  field: string
): {
  scalar: bigint;
  bytes: Uint8Array;
} {
  const raw = normalizeSecretBytes(source, field);
  let scalar = mod(bytesToBigIntLE(raw));
  if (scalar === 0n) {
    scalar = 1n;
  }
  return {
    scalar,
    bytes: bigintToBytesLE(scalar),
  };
}

function challengeHash(
  rBytes: Uint8Array,
  publicKey: Uint8Array,
  message: Uint8Array
): bigint {
  return mod(bytesToBigIntLE(sha512(concatBytes(rBytes, publicKey, message))));
}

function deriveNonce(
  prefix: Uint8Array,
  adaptorPoint: Uint8Array,
  message: Uint8Array
): bigint {
  return mod(
    bytesToBigIntLE(sha512(concatBytes(prefix, adaptorPoint, message)))
  );
}

function keystreamXor(data: Uint8Array, keyBytes: Uint8Array): Uint8Array {
  const output = new Uint8Array(data.length);

  for (let offset = 0; offset < data.length; offset += 32) {
    const blockIndex = offset / 32;
    const counter = new Uint8Array(8);
    let index = BigInt(blockIndex);
    for (let i = 0; i < 8; i += 1) {
      counter[i] = Number(index & 0xffn);
      index >>= 8n;
    }

    const keystream = sha256(
      concatBytes(utf8ToBytes("subly402-asc-enc-v1"), keyBytes, counter)
    );

    for (let i = 0; i < 32 && offset + i < data.length; i += 1) {
      output[offset + i] = data[offset + i] ^ keystream[i];
    }
  }

  return output;
}

export function buildAscPaymentMessage(
  channelId: string,
  requestId: string,
  amount: string | number,
  requestHash: string
): Uint8Array {
  const hashBytes = normalizeHex32(requestHash, "requestHash");
  const channelIdHash = hexToBytes(hashAscIdentifier(channelId));
  const requestIdHash = hexToBytes(hashAscIdentifier(requestId));
  const amountBytes = new Uint8Array(8);
  let current = BigInt(String(amount));
  for (let i = 0; i < 8; i += 1) {
    amountBytes[i] = Number(current & 0xffn);
    current >>= 8n;
  }

  return concatBytes(
    utf8ToBytes("subly402-asc-pay-v1"),
    channelIdHash,
    requestIdHash,
    amountBytes,
    hashBytes
  );
}

export function hashAscIdentifier(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function buildAscClaimVoucherMessage(input: {
  channelId: string;
  requestId: string;
  amount: string | number;
  requestHash: string;
  providerPubkey: string;
  issuedAt: number | bigint;
  vaultConfig: string;
}): Uint8Array {
  const requestHash = bytesToHex(
    normalizeHex32(input.requestHash, "requestHash")
  );
  const providerPubkey = bytesToHex(
    normalizeHex32(input.providerPubkey, "providerPubkey")
  );
  const vaultConfig = bytesToHex(
    normalizeHex32(input.vaultConfig, "vaultConfig")
  );
  const channelIdHash = hexToBytes(hashAscIdentifier(input.channelId));
  const requestIdHash = hexToBytes(hashAscIdentifier(input.requestId));
  const amountBytes = new Uint8Array(8);
  let amountValue = BigInt(String(input.amount));
  for (let i = 0; i < 8; i += 1) {
    amountBytes[i] = Number(amountValue & 0xffn);
    amountValue >>= 8n;
  }
  const issuedAtBytes = new Uint8Array(8);
  let issuedAtValue = BigInt(input.issuedAt.toString());
  const modulo = 1n << 64n;
  if (issuedAtValue < 0n) {
    issuedAtValue = modulo + issuedAtValue;
  }
  for (let i = 0; i < 8; i += 1) {
    issuedAtBytes[i] = Number(issuedAtValue & 0xffn);
    issuedAtValue >>= 8n;
  }

  return concatBytes(
    utf8ToBytes("SUBLY402-ASC-CLAIM-VOUCHER"),
    new Uint8Array([0]),
    channelIdHash,
    requestIdHash,
    amountBytes,
    hexToBytes(requestHash),
    hexToBytes(providerPubkey),
    issuedAtBytes,
    hexToBytes(vaultConfig)
  );
}

export function adaptAscSignature(input: {
  adaptorPoint: string;
  preSigRPrime: string;
  preSigSPrime: string;
  adaptorSecret: Uint8Array | string;
}): Uint8Array {
  const adaptorPoint = ed25519.Point.fromHex(
    normalizeHex32(input.adaptorPoint, "adaptorPoint")
  );
  const rPrime = ed25519.Point.fromHex(
    normalizeHex32(input.preSigRPrime, "preSigRPrime")
  );
  const sPrime = bytesToBigIntLE(
    normalizeHex32(input.preSigSPrime, "preSigSPrime")
  );
  const adaptorSecret = canonicalScalarBytes(
    input.adaptorSecret,
    "adaptorSecret"
  );
  const adaptedR = rPrime.add(adaptorPoint).toRawBytes();
  const adaptedS = bigintToBytesLE(sPrime + adaptorSecret.scalar);
  return concatBytes(adaptedR, adaptedS);
}

export function encryptAscResult(
  plaintext: Uint8Array | Buffer | string,
  adaptorSecret: Uint8Array | string
): Uint8Array {
  const plaintextBytes = normalizeResultBytes(plaintext);
  const secretBytes = normalizeSecretBytes(adaptorSecret, "adaptorSecret");
  return keystreamXor(plaintextBytes, secretBytes);
}

export function decryptAscResult(
  ciphertext: Uint8Array | string,
  adaptorSecret: Uint8Array | string
): Uint8Array {
  const ciphertextBytes =
    typeof ciphertext === "string"
      ? Uint8Array.from(Buffer.from(ciphertext, "base64"))
      : Uint8Array.from(ciphertext);
  const secretBytes = normalizeSecretBytes(adaptorSecret, "adaptorSecret");
  return keystreamXor(ciphertextBytes, secretBytes);
}

export function generateAscDeliveryArtifact(
  input: AscDeliveryInput
): AscDeliveryArtifact {
  const providerSecretKey = normalizeSecretBytes(
    input.providerSecretKey,
    "providerSecretKey"
  );
  const expanded = ed25519.utils.getExtendedPublicKey(providerSecretKey);
  const adaptorSecret = canonicalScalarBytes(
    input.adaptorSecret,
    "adaptorSecret"
  );
  const adaptorPoint = ed25519.Point.BASE.multiply(adaptorSecret.scalar);
  const adaptorPointBytes = adaptorPoint.toRawBytes();
  const message = buildAscPaymentMessage(
    input.channelId,
    input.requestId,
    input.amount,
    input.requestHash
  );

  const nonce = deriveNonce(expanded.prefix, adaptorPointBytes, message);
  const rPrimePoint = ed25519.Point.BASE.multiply(nonce);
  const rPrimeBytes = rPrimePoint.toRawBytes();
  const adaptedRBytes = rPrimePoint.add(adaptorPoint).toRawBytes();
  const challenge = challengeHash(adaptedRBytes, expanded.pointBytes, message);
  const sPrime = mod(nonce + challenge * expanded.scalar);

  const resultBytes = normalizeResultBytes(input.result);
  const encryptedResult = keystreamXor(resultBytes, adaptorSecret.bytes);

  return {
    adaptorPoint: bytesToHex(adaptorPointBytes),
    preSigRPrime: bytesToHex(rPrimeBytes),
    preSigSPrime: bytesToHex(bigintToBytesLE(sPrime)),
    encryptedResult: Buffer.from(encryptedResult).toString("base64"),
    resultHash: bytesToHex(sha256(resultBytes)),
    providerPubkey: bytesToHex(expanded.pointBytes),
    adaptorSecret: bytesToHex(adaptorSecret.bytes),
  };
}

export async function submitAscDelivery(
  config: Subly402ProviderConfig,
  channelId: string,
  delivery: AscDeliveryArtifact
): Promise<AscDeliverResponse> {
  const body = (await postFacilitatorJson(
    `${config.facilitatorUrl}/v1/channel/deliver`,
    {
      channelId,
      adaptorPoint: delivery.adaptorPoint,
      preSigRPrime: delivery.preSigRPrime,
      preSigSPrime: delivery.preSigSPrime,
      encryptedResult: delivery.encryptedResult,
      resultHash: delivery.resultHash,
      providerPubkey: delivery.providerPubkey,
    },
    config
  )) as AscDeliverResponse & { message?: string };
  if (!body.ok) {
    throw new Error(`ASC deliver failed: ${body.message || "unknown error"}`);
  }

  return body as AscDeliverResponse;
}

export async function deliverAscResult(
  config: Subly402ProviderConfig,
  input: AscDeliveryInput
): Promise<{ delivery: AscDeliveryArtifact; response: AscDeliverResponse }> {
  const delivery = generateAscDeliveryArtifact(input);
  const response = await submitAscDelivery(config, input.channelId, delivery);
  return { delivery, response };
}

export async function submitAscCloseClaim(input: {
  program: anchor.Program<any>;
  caller: Keypair;
  config: Pick<Subly402ProviderConfig, "vaultConfig" | "vaultSigner">;
  channelId: string;
  requestId: string;
  amount: string | number;
  requestHash: string;
  delivery: AscDeliveryArtifact;
  claimVoucher: AscClaimVoucher;
}): Promise<{ signature: string; ascCloseClaim: string }> {
  const channelIdHashHex = hashAscIdentifier(input.channelId);
  const requestIdHashHex = hashAscIdentifier(input.requestId);
  if (input.claimVoucher.channelIdHash.toLowerCase() !== channelIdHashHex) {
    throw new Error("claimVoucher.channelIdHash mismatch");
  }
  if (input.claimVoucher.requestIdHash.toLowerCase() !== requestIdHashHex) {
    throw new Error("claimVoucher.requestIdHash mismatch");
  }

  const expectedVoucherMessage = buildAscClaimVoucherMessage({
    channelId: input.channelId,
    requestId: input.requestId,
    amount: input.amount,
    requestHash: input.requestHash,
    providerPubkey: input.delivery.providerPubkey,
    issuedAt: input.claimVoucher.issuedAt,
    vaultConfig: new PublicKey(input.config.vaultConfig)
      .toBuffer()
      .toString("hex"),
  });
  const voucherMessage = Buffer.from(input.claimVoucher.message, "base64");
  if (!voucherMessage.equals(Buffer.from(expectedVoucherMessage))) {
    throw new Error("claimVoucher.message mismatch");
  }

  const voucherSignature = Buffer.from(input.claimVoucher.signature, "base64");
  if (voucherSignature.length !== 64) {
    throw new Error("claimVoucher.signature must be 64 bytes");
  }

  const paymentMessage = buildAscPaymentMessage(
    input.channelId,
    input.requestId,
    input.amount,
    input.requestHash
  );
  const fullSig = adaptAscSignature(input.delivery);
  if (
    !ed25519.verify(
      fullSig,
      paymentMessage,
      Buffer.from(input.delivery.providerPubkey, "hex")
    )
  ) {
    throw new Error(
      "delivery artifact does not produce a valid adapted signature"
    );
  }

  const voucherEd25519Ix = Ed25519Program.createInstructionWithPublicKey({
    publicKey: new PublicKey(input.config.vaultSigner).toBytes(),
    message: voucherMessage,
    signature: voucherSignature,
  });
  const paymentEd25519Ix = Ed25519Program.createInstructionWithPublicKey({
    publicKey: Buffer.from(input.delivery.providerPubkey, "hex"),
    message: paymentMessage,
    signature: fullSig,
  });

  const vaultConfig = new PublicKey(input.config.vaultConfig);
  const channelIdHash = Buffer.from(channelIdHashHex, "hex");
  const requestIdHash = Buffer.from(requestIdHashHex, "hex");
  const [ascCloseClaimPda] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("asc_close_claim"),
      vaultConfig.toBuffer(),
      channelIdHash,
      requestIdHash,
    ],
    input.program.programId
  );

  const claimIx = await input.program.methods
    .ascCloseClaim(
      Array.from(channelIdHash) as any,
      Array.from(requestIdHash) as any
    )
    .accountsPartial({
      caller: input.caller.publicKey,
      vaultConfig,
      ascCloseClaim: ascCloseClaimPda,
      instructionsSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .instruction();

  const provider = input.program.provider as anchor.AnchorProvider;
  const latestBlockhash = await provider.connection.getLatestBlockhash(
    "confirmed"
  );
  const messageV0 = new TransactionMessage({
    payerKey: input.caller.publicKey,
    recentBlockhash: latestBlockhash.blockhash,
    instructions: [voucherEd25519Ix, paymentEd25519Ix, claimIx],
  }).compileToV0Message();

  const tx = new VersionedTransaction(messageV0);
  tx.sign([input.caller]);

  const signature = await provider.connection.sendTransaction(tx);
  await provider.connection.confirmTransaction(
    {
      signature,
      blockhash: latestBlockhash.blockhash,
      lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
    },
    "confirmed"
  );

  return {
    signature,
    ascCloseClaim: ascCloseClaimPda.toBase58(),
  };
}
