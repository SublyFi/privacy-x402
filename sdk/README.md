# subly402-sdk

Privacy-first x402 client SDK for Solana. Pays paid APIs through a TEE-based vault so on-chain observers never see a direct buyer-to-provider edge.

- `a402-svm-v1` scheme on top of the x402 HTTP envelope
- Nitro attestation verification (PCR pinning required by default)
- Batched vault settlement hides the sender / amount / timing correlation
- Selective disclosure via hierarchical ElGamal audit records

## Install

```bash
yarn add subly402-sdk
```

## Quickstart

```ts
import { Subly402Client } from "subly402-sdk";
import { createKeyPairSignerFromBytes } from "@solana/kit";

const secretKeyBytes = Uint8Array.from(/* your 64-byte keypair */);
const signer = await createKeyPairSignerFromBytes(secretKeyBytes, true);

const client = new Subly402Client({
  signer,
  network: "solana:devnet",
  trustedFacilitators: ["https://enclave.example.com"],
  nitroAttestation: {
    policy: {
      version: 1,
      pcrs: {
        "0": "<hex>",
        "1": "<hex>",
        "2": "<hex>",
        "3": "<hex>",
        "8": "<hex>",
      },
      eifSigningCertSha256: "<hex>",
      kmsKeyArnSha256: "<hex>",
      protocol: "a402",
    },
  },
});

const res = await client.fetch("https://paid-api.example.com/resource");
const body = await res.json();
```

If the server returns HTTP 402, the client automatically:

1. Downloads and verifies the Nitro attestation (fails closed unless PCR pinning is configured)
2. Opens / reuses a reservation in the vault
3. Retries the request with a signed `PAYMENT-SIGNATURE`

## Security defaults

- `verifyNitroAttestationDocument()` throws if neither `policy.pcrs` nor `expectedPcrs` is configured. Callers who deliberately want to skip PCR pinning must set `allowMissingPcrPinning: true`.
- The SDK verifies the enclave TLS public key hash against the attestation document, so a MITM that swaps certificates is rejected.
- Receipt / withdrawal signatures are Ed25519-signed by the in-enclave vault signer.

See [`docs/quickstart.md`](../docs/quickstart.md) for a full walkthrough and the current privacy threat model.

## License

ISC
