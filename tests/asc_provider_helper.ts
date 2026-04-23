import { expect } from "chai";
import { createHash } from "crypto";
import { ed25519 } from "@noble/curves/ed25519";
import {
  adaptAscSignature,
  buildAscClaimVoucherMessage,
  buildAscPaymentMessage,
  decryptAscResult,
  generateAscDeliveryArtifact,
  hashAscIdentifier,
} from "../middleware/src/asc";

describe("asc_provider_helper", () => {
  it("generates a verifiable ASC delivery artifact", async () => {
    const channelId = "ch_test_123";
    const requestId = "req_test_456";
    const amount = 1_250_000;
    const requestHash = "ab".repeat(32);
    const result = JSON.stringify({
      ok: true,
      data: "hello from provider tee",
    });

    const artifact = generateAscDeliveryArtifact({
      channelId,
      requestId,
      amount,
      requestHash,
      result,
      providerSecretKey: "11".repeat(32),
      adaptorSecret: "22".repeat(32),
    });

    expect(artifact.adaptorPoint).to.have.length(64);
    expect(artifact.preSigRPrime).to.have.length(64);
    expect(artifact.preSigSPrime).to.have.length(64);
    expect(artifact.providerPubkey).to.have.length(64);
    expect(artifact.adaptorSecret).to.have.length(64);

    const decrypted = Buffer.from(
      decryptAscResult(artifact.encryptedResult, artifact.adaptorSecret)
    ).toString("utf8");
    expect(decrypted).to.equal(result);

    const resultHash = createHash("sha256").update(result).digest("hex");
    expect(artifact.resultHash).to.equal(resultHash);
  });

  it("builds the ASC payment transcript with request hash binding", async () => {
    const message = buildAscPaymentMessage(
      "ch_demo",
      "req_demo",
      "42",
      "CD".repeat(32)
    );

    expect(Buffer.from(message.subarray(0, 15)).toString("utf8")).to.equal(
      "subly402-asc-pay-v1"
    );
    expect(message.length).to.equal(119);
  });

  it("builds ASC claim artifacts for on-chain fallback", async () => {
    const delivery = generateAscDeliveryArtifact({
      channelId: "ch_claim",
      requestId: "req_claim",
      amount: 99,
      requestHash: "ef".repeat(32),
      result: "claim result",
      providerSecretKey: "33".repeat(32),
      adaptorSecret: "44".repeat(32),
    });

    const voucher = buildAscClaimVoucherMessage({
      channelId: "ch_claim",
      requestId: "req_claim",
      amount: 99,
      requestHash: "ef".repeat(32),
      providerPubkey: delivery.providerPubkey,
      issuedAt: 1234,
      vaultConfig: "55".repeat(32),
    });
    expect(Buffer.from(voucher.subarray(0, 23)).toString("utf8")).to.equal(
      "SUBLY402-ASC-CLAIM-VOUCHER\u0000"
    );
    expect(Buffer.from(voucher.subarray(0, 22)).toString("utf8")).to.equal(
      "SUBLY402-ASC-CLAIM-VOUCHER"
    );

    const fullSig = adaptAscSignature(delivery);
    expect(fullSig).to.have.length(64);
    expect(
      ed25519.verify(
        fullSig,
        buildAscPaymentMessage("ch_claim", "req_claim", 99, "ef".repeat(32)),
        Buffer.from(delivery.providerPubkey, "hex")
      )
    ).to.equal(true);
    expect(hashAscIdentifier("ch_claim")).to.have.length(64);
  });
});
