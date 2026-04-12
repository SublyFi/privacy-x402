import { expect } from "chai";
import { createHash } from "crypto";
import nacl from "tweetnacl";
import { Keypair } from "@solana/web3.js";

/**
 * Enclave Facilitator API integration tests.
 *
 * Prerequisites: enclave must be running on localhost:3100
 * Run: cargo run -p a402-enclave &
 * Then: yarn run ts-mocha -p ./tsconfig.json -t 30000 tests/enclave_api.ts
 */

const ENCLAVE_URL = "http://localhost:3100";

// Helper: register a provider directly via internal state
// In production this would be an admin API; for testing we add a /v1/admin/register-provider endpoint
// For now, we test the public API flow assuming the enclave has a pre-registered provider

describe("enclave_api", () => {
  let attestation: any;

  describe("GET /v1/attestation", () => {
    it("returns attestation document", async () => {
      const res = await fetch(`${ENCLAVE_URL}/v1/attestation`);
      expect(res.status).to.equal(200);

      attestation = await res.json();
      expect(attestation.vaultSigner).to.be.a("string");
      expect(attestation.attestationPolicyHash).to.be.a("string");
      expect(attestation.issuedAt).to.be.a("string");
      expect(attestation.expiresAt).to.be.a("string");
    });
  });

  describe("POST /v1/verify", () => {
    it("rejects invalid scheme", async () => {
      const res = await fetch(`${ENCLAVE_URL}/v1/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          paymentPayload: {
            version: 1,
            scheme: "invalid-scheme",
            paymentId: "pay_test",
            client: Keypair.generate().publicKey.toBase58(),
            vault: "11111111111111111111111111111111",
            providerId: "prov_test",
            payTo: Keypair.generate().publicKey.toBase58(),
            network: "solana:devnet",
            assetMint: Keypair.generate().publicKey.toBase58(),
            amount: "1000000",
            requestHash: "0".repeat(64),
            paymentDetailsHash: "0".repeat(64),
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            nonce: "123",
            clientSig: "",
          },
          requestContext: {
            method: "POST",
            origin: "http://localhost",
            pathAndQuery: "/test",
            bodySha256: "0".repeat(64),
          },
        }),
      });

      expect(res.status).to.equal(400);
      const body = await res.json();
      expect(body.error).to.equal("invalid_scheme");
    });

    it("rejects unknown provider", async () => {
      const res = await fetch(`${ENCLAVE_URL}/v1/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          paymentPayload: {
            version: 1,
            scheme: "a402-svm-v1",
            paymentId: "pay_test",
            client: Keypair.generate().publicKey.toBase58(),
            vault: "11111111111111111111111111111111",
            providerId: "prov_unknown",
            payTo: Keypair.generate().publicKey.toBase58(),
            network: "solana:devnet",
            assetMint: Keypair.generate().publicKey.toBase58(),
            amount: "1000000",
            requestHash: "0".repeat(64),
            paymentDetailsHash: "0".repeat(64),
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
            nonce: "123",
            clientSig: "",
          },
          requestContext: {
            method: "POST",
            origin: "http://localhost",
            pathAndQuery: "/test",
            bodySha256: "0".repeat(64),
          },
        }),
      });

      expect(res.status).to.equal(400);
      const body = await res.json();
      expect(body.error).to.equal("provider_not_found");
    });
  });

  describe("POST /v1/cancel", () => {
    it("rejects unknown verification_id", async () => {
      const res = await fetch(`${ENCLAVE_URL}/v1/cancel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          verificationId: "ver_nonexistent",
          reason: "test",
        }),
      });

      expect(res.status).to.equal(404);
      const body = await res.json();
      expect(body.error).to.equal("reservation_not_found");
    });
  });

  describe("POST /v1/settle", () => {
    it("rejects unknown verification_id", async () => {
      const res = await fetch(`${ENCLAVE_URL}/v1/settle`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          verificationId: "ver_nonexistent",
          resultHash: "0".repeat(64),
          statusCode: 200,
        }),
      });

      expect(res.status).to.equal(404);
      const body = await res.json();
      expect(body.error).to.equal("reservation_not_found");
    });
  });

  describe("POST /v1/withdraw-auth", () => {
    it("rejects unknown client", async () => {
      const res = await fetch(`${ENCLAVE_URL}/v1/withdraw-auth`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: Keypair.generate().publicKey.toBase58(),
          recipientAta: Keypair.generate().publicKey.toBase58(),
          amount: 1000000,
        }),
      });

      expect(res.status).to.equal(400);
      const body = await res.json();
      expect(body.error).to.equal("client_not_found");
    });
  });
});
