# subly402-sdk

Privacy-first x402 client SDK for Solana. Pays paid APIs through a TEE-based vault so on-chain observers never see a direct buyer-to-provider edge.

- `subly402-svm-v1` scheme on top of the x402 HTTP envelope
- Nitro attestation verification (PCR pinning required by default)
- Batched vault settlement hides the sender / amount / timing correlation
- Selective disclosure via hierarchical ElGamal audit records

## Install

```bash
yarn add subly402-sdk
```

The default import path is the x402-like Buyer SDK and uses `@solana/kit` signers. Advanced direct-vault, audit, and Arcium helpers live behind `subly402-sdk/vault`, `subly402-sdk/audit`, and `subly402-sdk/arcium`; those optional paths require their matching Solana/Anchor/Arcium dependencies.

## Quickstart for Buyers

No Subly API key or account registration is required. A buyer only needs a funded Solana signer and the attestation policy for the facilitator they are willing to trust.

```ts
import { Subly402Client, wrapFetchWithPayment } from "subly402-sdk";
import { createKeyPairSignerFromBytes } from "@solana/kit";

const secretKeyBytes = Uint8Array.from(/* your 64-byte keypair */);
const signer = await createKeyPairSignerFromBytes(secretKeyBytes, true);

const client = new Subly402Client({
  signer,
  network: "solana:devnet",
  trustedFacilitators: ["https://enclave.example.com"],
  autoDeposit: {
    maxDepositPerRequest: "$0.05",
    deposit: async ({ amount, details }) => {
      // Send a vault deposit transaction for `amount`, then wait until the
      // facilitator observes it. Browser wallets, custodial wallets, and agents
      // can each plug in their own transaction implementation here.
      await depositIntoSublyVault({ amount, mint: details.asset.mint });
    },
  },
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
      protocol: "subly402-svm-v1",
    },
  },
});

const fetchWithPayment = wrapFetchWithPayment(fetch, client);

const res = await fetchWithPayment("https://paid-api.example.com/resource");
const body = await res.json();
```

If the server returns HTTP 402, the client automatically:

1. Downloads and verifies the Nitro attestation (fails closed unless PCR pinning is configured)
2. Builds and signs the Subly x402 payment payload for the selected Solana payment option
3. Retries the request with a signed `PAYMENT-SIGNATURE`
4. If the vault balance is insufficient and `autoDeposit` is configured, deposits on demand, signs a fresh payment payload, and retries once more

If `autoDeposit` is disabled, the buyer must already have spendable balance in the Subly vault for the facilitator. The vault replaces direct buyer-to-seller settlement with batched settlement, which is the privacy layer.

## Security defaults

- `verifyNitroAttestationDocument()` throws if neither `policy.pcrs` nor `expectedPcrs` is configured. Callers who deliberately want to skip PCR pinning must set `allowMissingPcrPinning: true`.
- The SDK verifies the enclave TLS public key hash against the attestation document, so a MITM that swaps certificates is rejected.
- Receipt / withdrawal signatures are Ed25519-signed by the in-enclave vault signer.

See [`docs/quickstart.md`](../docs/quickstart.md) for a full walkthrough and the current privacy threat model.

## Arcium helpers

Arcium support is exposed as an optional subpath so normal x402 buyers do not load Arcium dependencies:

```ts
import {
  createArciumSharedCipher,
  deriveArciumX25519Keypair,
  encryptArciumBudgetRequest,
  encryptArciumWithdrawalRequest,
  fetchArciumMxePublicKeyWithRetry,
  splitU256Le,
} from "subly402-sdk/arcium";
```

```ts
const arciumKeys = await deriveArciumX25519Keypair(signer, {
  programId: "3iusaL6ys79DsbpweDwGhHvtjdnhAhtpyczPtMbu5Mbe",
  vaultConfig: paymentDetails.vault.config,
  derivationScope: "subly402:owner-view:v1",
});
```

Install `@arcium-hq/client@0.9.7` and run this subpath on Node.js >=20.18.0. The helpers derive a recoverable x25519 key from `signMessages`, `signMessage`, or `secretKey`; bind the derivation message to a program, vault, wallet, and caller-supplied scope; encrypt budget, withdrawal, and reconcile payloads in circuit argument order; and expose decryptors for owner, budget grant, and withdrawal grant views. Enforced-mode control-plane payloads are exported as TypeScript types: `SetArciumModeRequest`, `LoadArciumBudgetGrantRequest`, and `LoadArciumWithdrawalGrantRequest`.

## License

ISC
