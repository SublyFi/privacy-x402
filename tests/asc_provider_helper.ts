import { expect } from "chai";
import { createHash } from "crypto";
import {
  buildAscPaymentMessage,
  decryptAscResult,
  generateAscDeliveryArtifact,
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
    const message = Buffer.from(
      buildAscPaymentMessage("ch_demo", "req_demo", "42", "CD".repeat(32))
    ).toString("utf8");

    expect(message).to.equal(`ch_demo:req_demo:42:${"cd".repeat(32)}`);
  });
});
