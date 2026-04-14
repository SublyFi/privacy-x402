import { randomBytes } from "crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256, sha512 } from "@noble/hashes/sha2";
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  utf8ToBytes,
} from "@noble/hashes/utils";
import type {
  A402ProviderConfig,
  AscDeliverResponse,
  AscDeliveryArtifact,
  AscDeliveryInput,
} from "./types";
import { postFacilitatorJson } from "./facilitator";

const CURVE_ORDER =
  723700557733226221397318656304299424085711635937990760600195093828545425857n;

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

function canonicalScalarBytes(source: Uint8Array | string | undefined, field: string): {
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
  return mod(bytesToBigIntLE(sha512(concatBytes(prefix, adaptorPoint, message))));
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
      concatBytes(utf8ToBytes("a402-asc-enc-v1"), keyBytes, counter)
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
  const normalizedHash = bytesToHex(hashBytes);
  return utf8ToBytes(
    `${channelId}:${requestId}:${String(amount)}:${normalizedHash}`
  );
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
  config: A402ProviderConfig,
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
  config: A402ProviderConfig,
  input: AscDeliveryInput
): Promise<{ delivery: AscDeliveryArtifact; response: AscDeliverResponse }> {
  const delivery = generateAscDeliveryArtifact(input);
  const response = await submitAscDelivery(config, input.channelId, delivery);
  return { delivery, response };
}
