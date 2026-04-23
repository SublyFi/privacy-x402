# Subly402 Quickstart

Privacy-first x402 for Solana. Your AI agent pays paid APIs through a TEE-backed vault so on-chain observers never see the direct buyer-to-provider edge.

- **Client**: you ship an agent, call any `a402-svm-v1` API with `subly402-sdk`, and the vault handles the rest.
- **Provider**: you ship a paid API, plug in `subly402-express`, and settle through the facilitator instead of direct on-chain transfers.

## 1. Prerequisites

- Node.js 18+
- A Solana wallet (devnet SOL + devnet USDC)
- The URL of a running Subly facilitator (your own Nitro deployment, or a public one)
- The facilitator's `attestationPolicyHash` and the PCR pinning values for its EIF

```bash
# export these once
export SUBLY_ENCLAVE_URL="https://enclave.example.com"
export SUBLY_NETWORK="solana:devnet"
export SUBLY_USDC_MINT="<devnet USDC mint>"
```

## 2. Install the client SDK

```bash
yarn add subly402-sdk @solana/kit
```

## 3. Call a paid API

```ts
import { Subly402Client } from "subly402-sdk";
import { createKeyPairSignerFromBytes } from "@solana/kit";

// 64-byte secret key (e.g. from a Solana CLI keypair JSON)
const secretKeyBytes = Uint8Array.from(/* your keypair bytes */);
const signer = await createKeyPairSignerFromBytes(secretKeyBytes, true);

const client = new Subly402Client({
  signer,
  network: process.env.SUBLY_NETWORK!,
  trustedFacilitators: [process.env.SUBLY_ENCLAVE_URL!],
  nitroAttestation: {
    policy: {
      version: 1,
      pcrs: {
        "0": process.env.SUBLY_PCR0!,
        "1": process.env.SUBLY_PCR1!,
        "2": process.env.SUBLY_PCR2!,
        "3": process.env.SUBLY_PCR3!,
        "8": process.env.SUBLY_PCR8!,
      },
      eifSigningCertSha256: process.env.SUBLY_EIF_CERT_SHA!,
      kmsKeyArnSha256: process.env.SUBLY_KMS_KEY_SHA!,
      protocol: "a402",
    },
  },
  policy: {
    maxPaymentPerRequest: "$0.10",
  },
});

const res = await client.fetch("https://paid-api.example.com/weather");
const body = await res.json();
```

What happens behind the scenes:

1. The server returns HTTP 402 with `PAYMENT-REQUIRED` envelope.
2. The SDK fetches `/v1/attestation` from the facilitator and verifies the full Nitro chain — fails closed if PCR pinning is not configured.
3. The SDK signs a reservation and retries with `PAYMENT-SIGNATURE`.
4. The provider settles through the facilitator, which batches the settlement and writes `settle_vault` + `record_audit` on-chain.

## 4. Serve a paid API (provider side)

```bash
yarn add subly402-express express
```

```ts
import express from "express";
import {
  Subly402FacilitatorClient,
  Subly402ResourceServer,
  Subly402ExactScheme,
  paymentMiddleware,
  captureA402RawBody,
} from "subly402-express";

const app = express();
app.use(express.json({ verify: captureA402RawBody }));

const facilitator = new Subly402FacilitatorClient({
  url: process.env.SUBLY_ENCLAVE_URL!,
  providerApiKey: process.env.SUBLY_PROVIDER_API_KEY!,
  authMode: "bearer",
  assetMint: process.env.SUBLY_USDC_MINT!,
});

const resourceServer = new Subly402ResourceServer(facilitator).register(
  process.env.SUBLY_NETWORK!,
  new Subly402ExactScheme()
);

app.use(
  paymentMiddleware(
    {
      "GET /weather": {
        accepts: [
          {
            scheme: "exact",
            price: "$0.001",
            network: process.env.SUBLY_NETWORK!,
            payTo: process.env.SUBLY_PROVIDER_TOKEN_ACCOUNT!,
            providerId: process.env.SUBLY_PROVIDER_ID!,
          },
        ],
      },
    },
    resourceServer
  )
);

app.get("/weather", (_req, res) => {
  res.json({ temperature: 72, conditions: "clear" });
});

app.listen(3000);
```

Your route handler runs only after the facilitator verifies + reserves. The middleware settles before the response leaves the server, so WAL durability is honored.

## 5. Privacy model at launch

What is hidden from on-chain observers:

- Which buyer paid which provider for any individual request.
- Per-request amounts (observers only see aggregated `Vault → Provider` payouts).
- Request content, provider endpoints, and payment metadata.

What is **still visible** at launch:

- **Vault deposits** (client wallet → vault token account) are public. The anonymity set equals the number of active depositors.
- **Provider aggregate payouts** are public. Amount / timing metadata can still be correlated across windows.
- The facilitator operator (AWS + EIF signer) can see raw payment data inside the TEE. On-chain observers and the parent instance cannot.

Defaults for the time-based anonymity window:

| Constant | Default | Env override |
|---|---|---|
| `MIN_ANONYMITY_WINDOW_SEC` | `60` | `A402_MIN_ANONYMITY_WINDOW_SEC` |
| `BATCH_WINDOW_SEC` | `120` | — |
| `MIN_BATCH_PROVIDERS` | `1` | `A402_MIN_BATCH_PROVIDERS` |
| `MAX_SETTLEMENT_DELAY_SEC` | `900` | — |

Every individual settlement is held in the vault for at least `MIN_ANONYMITY_WINDOW_SEC` before it is eligible for an on-chain batch — fresh siblings in the same provider credit keep aging even when an older sibling is already being paid out. Operators running high-volume vaults should raise `MIN_BATCH_PROVIDERS` to enforce k-anonymity across providers in addition to the time window.

## 6. Running your own facilitator

End-to-end Nitro deployment (KMS bootstrap, PCR pinning, NLB, watchtower, Terraform) is in the root [`README.md`](../README.md). Protocol-level details are in [`a402-svm-v1-protocol.md`](./a402-svm-v1-protocol.md) and [`a402-solana-design.md`](./a402-solana-design.md).
