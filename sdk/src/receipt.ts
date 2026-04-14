import type {
  ParticipantReceiptResponse,
  VerificationReceiptEnvelope,
} from "./types";

export function decodeParticipantReceiptEnvelope(
  envelope: string
): ParticipantReceiptResponse {
  const json = Buffer.from(envelope, "base64").toString("utf-8");
  return JSON.parse(json) as ParticipantReceiptResponse;
}

export function decodeVerificationReceiptEnvelope(
  envelope: string
): VerificationReceiptEnvelope {
  const json = Buffer.from(envelope, "base64").toString("utf-8");
  return JSON.parse(json) as VerificationReceiptEnvelope;
}
