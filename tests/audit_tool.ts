import { expect } from "chai";
import { createHash, hkdfSync } from "crypto";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { Keypair, PublicKey } from "@solana/web3.js";
import { AuditTool, RawAuditRecord } from "../sdk/src/audit";

const SCALAR_ORDER = BigInt(
  "7237005577332262213973186563042994240857116359379907606001950938285454250989"
);

function bytesToScalar(bytes: Uint8Array): bigint {
  let n = BigInt(0);
  const len = Math.min(bytes.length, 64);
  for (let i = len - 1; i >= 0; i--) {
    n = (n << BigInt(8)) | BigInt(bytes[i]);
  }
  return n % SCALAR_ORDER;
}

function scalarToBytes(scalar: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let value = scalar;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(value & BigInt(0xff));
    value >>= BigInt(8);
  }
  return out;
}

function kdfMask(sharedSecretBytes: Uint8Array): Uint8Array {
  const hash = createHash("sha256");
  hash.update("subly402-elgamal-mask-v1");
  hash.update(sharedSecretBytes);
  return new Uint8Array(hash.digest());
}

function deriveProviderKeyMaterial(
  masterSecret: Uint8Array,
  provider: PublicKey
): Uint8Array {
  return new Uint8Array(
    hkdfSync(
      "sha256",
      masterSecret,
      Buffer.from("subly402-audit-v1"),
      provider.toBuffer(),
      64
    )
  );
}

function encryptWithProvider(
  masterSecret: Uint8Array,
  provider: PublicKey,
  plaintext: Uint8Array,
  r: bigint
): Uint8Array {
  const providerSecret = bytesToScalar(
    deriveProviderKeyMaterial(masterSecret, provider)
  );
  const providerPublic = RistrettoPoint.BASE.multiply(providerSecret);
  const c1 = RistrettoPoint.BASE.multiply(r);
  const shared = providerPublic.multiply(r);
  const mask = kdfMask(shared.toRawBytes());

  const ciphertext = new Uint8Array(64);
  ciphertext.set(c1.toRawBytes(), 0);
  for (let i = 0; i < 32; i++) {
    ciphertext[32 + i] = plaintext[i] ^ mask[i];
  }
  return ciphertext;
}

function encodeAmount(amount: bigint): Uint8Array {
  const out = new Uint8Array(32);
  const view = Buffer.from(out.buffer, out.byteOffset, out.byteLength);
  view.writeBigUInt64LE(amount, 0);
  return out;
}

function buildRawRecord(
  masterSecret: Uint8Array,
  provider: PublicKey,
  sender: PublicKey,
  amount: bigint
): RawAuditRecord {
  return {
    address: Keypair.generate().publicKey,
    vault: Keypair.generate().publicKey,
    batchId: 7,
    index: 0,
    encryptedSender: encryptWithProvider(
      masterSecret,
      provider,
      sender.toBytes(),
      BigInt(11)
    ),
    encryptedAmount: encryptWithProvider(
      masterSecret,
      provider,
      encodeAmount(amount),
      BigInt(17)
    ),
    provider,
    timestamp: 1_700_000_000,
    auditorEpoch: 3,
  };
}

describe("audit_tool", () => {
  it("exports provider key as a 32-byte reduced scalar", async () => {
    const masterSecret = new Uint8Array(32).fill(9);
    const provider = Keypair.generate().publicKey;
    const tool = new AuditTool(masterSecret);

    const exportedKey = await tool.exportProviderKey(provider);
    const expectedKey = scalarToBytes(
      bytesToScalar(deriveProviderKeyMaterial(masterSecret, provider))
    );

    expect(exportedKey.length).to.equal(32);
    expect(Buffer.from(exportedKey).equals(Buffer.from(expectedKey))).to.equal(
      true
    );
  });

  it("decrypts records with the exported provider key", async () => {
    const masterSecret = new Uint8Array(32).fill(5);
    const provider = Keypair.generate().publicKey;
    const sender = Keypair.generate().publicKey;
    const wrongProvider = Keypair.generate().publicKey;
    const tool = new AuditTool(masterSecret);

    const rawRecord = buildRawRecord(
      masterSecret,
      provider,
      sender,
      BigInt(123456)
    );
    const exportedKey = await tool.exportProviderKey(provider);
    const wrongKey = await tool.exportProviderKey(wrongProvider);

    const decrypted = await AuditTool.decryptWithKey(exportedKey, [rawRecord]);
    const wrongDecrypted = await AuditTool.decryptWithKey(wrongKey, [
      rawRecord,
    ]);

    expect(decrypted).to.have.length(1);
    expect(decrypted[0].sender.toBase58()).to.equal(sender.toBase58());
    expect(decrypted[0].amount).to.equal(123456);

    if (wrongDecrypted.length === 1) {
      expect(wrongDecrypted[0].sender.toBase58()).to.not.equal(
        sender.toBase58()
      );
    } else {
      expect(wrongDecrypted).to.have.length(0);
    }
  });
});
