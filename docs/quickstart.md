# Subly402 Quickstart

Privacy-first x402 for Solana. Your AI agent pays paid APIs through a TEE-backed vault so on-chain observers never see the direct buyer-to-provider edge.

- **Client**: you ship an agent, call any `subly402-svm-v1` API with `subly402-sdk`, and the vault handles the rest.
- **Provider**: you ship a paid API, plug in `subly402-express`, and settle through the facilitator instead of direct on-chain transfers.

## 1. Prerequisites

- Node.js 18+
- A Solana signer for the buyer (devnet SOL + devnet USDC for testing)
- A Solana wallet or token account for the seller payout destination
- The URL of a running Subly facilitator (your own Nitro deployment, or a public one)
- The facilitator's `attestationPolicyHash` and the PCR pinning values for its EIF

```bash
# export these once
export SUBLY402_FACILITATOR_URL="https://enclave.example.com"
export SUBLY402_NETWORK="solana:devnet"
export SUBLY402_USDC_MINT="<devnet USDC mint>"
```

## 2. Buyer: call a paid API

```bash
yarn add subly402-sdk @solana/kit
```

No Subly API key or account registration is required. A buyer needs a funded Solana signer, a trusted facilitator, and an optional `autoDeposit` hook if they want x402-style on-demand top-ups.

```ts
import { Subly402Client, wrapFetchWithPayment } from "subly402-sdk";
import { createKeyPairSignerFromBytes } from "@solana/kit";

// 64-byte secret key (e.g. from a Solana CLI keypair JSON)
const secretKeyBytes = Uint8Array.from(/* your keypair bytes */);
const signer = await createKeyPairSignerFromBytes(secretKeyBytes, true);

const client = new Subly402Client({
  signer,
  network: process.env.SUBLY402_NETWORK!,
  trustedFacilitators: [process.env.SUBLY402_FACILITATOR_URL!],
  autoDeposit: {
    maxDepositPerRequest: "$0.05",
    deposit: async ({ amountAtomic, details, facilitatorUrl }) => {
      // Send a vault deposit transaction, then wait until the facilitator
      // observes it. Browser wallets, custodial wallets, and agents can plug in
      // their own transaction implementation here.
      await depositIntoSublyVault({
        amountAtomic,
        mint: details.asset.mint,
        vaultConfig: details.vault.config,
        facilitatorUrl,
      });
    },
  },
  nitroAttestation: {
    policy: {
      version: 1,
      pcrs: {
        "0": process.env.SUBLY402_PCR0!,
        "1": process.env.SUBLY402_PCR1!,
        "2": process.env.SUBLY402_PCR2!,
        "3": process.env.SUBLY402_PCR3!,
        "8": process.env.SUBLY402_PCR8!,
      },
      eifSigningCertSha256: process.env.SUBLY402_EIF_CERT_SHA256!,
      kmsKeyArnSha256: process.env.SUBLY402_KMS_KEY_ARN_SHA256!,
      protocol: "subly402-svm-v1",
    },
  },
  policy: {
    maxPaymentPerRequest: "$0.10",
  },
});

const fetchWithPayment = wrapFetchWithPayment(fetch, client);

const res = await fetchWithPayment("https://paid-api.example.com/weather");
const body = await res.json();
```

What happens behind the scenes:

1. The server returns HTTP 402 with `PAYMENT-REQUIRED` envelope.
2. The SDK fetches `/v1/attestation` from the facilitator and verifies the full Nitro chain — fails closed if PCR pinning is not configured.
3. The SDK signs a reservation and retries with `PAYMENT-SIGNATURE`.
4. If the vault balance is insufficient and `autoDeposit` is configured, the SDK calls the deposit hook and retries with a fresh payment signature.
5. The seller settles through the facilitator, which batches payouts from the vault instead of exposing a direct buyer-to-seller transfer.

If `autoDeposit` is disabled, the buyer must already have spendable balance in the Subly vault.

## 3. Seller: serve a paid API

```bash
yarn add subly402-express express
```

No provider registration or API key is required for the default seller flow. The facilitator derives the open seller identity from `network + asset mint + payTo` and auto-registers it the first time a valid paid request is verified.

```ts
import express from "express";
import {
  Subly402FacilitatorClient,
  Subly402ResourceServer,
  Subly402ExactScheme,
  paymentMiddleware,
  captureSubly402RawBody,
} from "subly402-express";

const app = express();
app.use(express.json({ verify: captureSubly402RawBody }));

const facilitator = new Subly402FacilitatorClient({
  url: process.env.SUBLY402_FACILITATOR_URL!,
  assetMint: process.env.SUBLY402_USDC_MINT!,
});

const resourceServer = new Subly402ResourceServer(facilitator).register(
  process.env.SUBLY402_NETWORK!,
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
            network: process.env.SUBLY402_NETWORK!,
            sellerWallet: process.env.SELLER_WALLET!,
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

That is the default seller integration: install the package, point it at a deployed Subly facilitator, choose a route, price, network, and receiving wallet.

For Solana, `sellerWallet` is the wallet owner. The middleware derives the USDC associated token account and uses it as `payTo`. Advanced sellers can pass `payTo` directly when they want to settle to a specific token account.

Your route handler runs only after the facilitator verifies + reserves. The middleware settles before the response leaves the server, so WAL durability is honored.

## 4. Privacy model at launch

What is hidden from on-chain observers:

- Which buyer paid which provider for any individual request.
- Per-request amounts (observers only see aggregated `Vault → Provider` payouts).
- Request content, provider endpoints, and payment metadata.

What is **still visible** at launch:

- **Vault deposits** (client wallet → vault token account) are public. The anonymity set equals the number of active depositors.
- **Provider aggregate payouts** are public. Amount / timing metadata can still be correlated across windows.
- The facilitator operator (AWS + EIF signer) can see raw payment data inside the TEE. On-chain observers and the parent instance cannot.

Defaults for the time-based anonymity window:

| Constant                   | Default | Env override                        |
| -------------------------- | ------- | ----------------------------------- |
| `MIN_ANONYMITY_WINDOW_SEC` | `300`   | `SUBLY402_MIN_ANONYMITY_WINDOW_SEC` |
| `BATCH_WINDOW_SEC`         | `120`   | `SUBLY402_BATCH_WINDOW_SEC`         |
| `MIN_BATCH_PROVIDERS`      | `2`     | `SUBLY402_MIN_BATCH_PROVIDERS`      |
| `MAX_SETTLEMENT_DELAY_SEC` | `900`   | —                                   |

Every individual settlement is held in the vault for at least `MIN_ANONYMITY_WINDOW_SEC` before it is eligible for an on-chain batch — fresh siblings in the same provider credit keep aging even when an older sibling is already being paid out. Automatic batches require at least `MIN_BATCH_PROVIDERS` distinct providers unless the liveness deadline is reached.

For a public demo you can set `SUBLY402_BATCH_WINDOW_SEC=60`,
`SUBLY402_MIN_ANONYMITY_WINDOW_SEC=60`, and
`SUBLY402_MIN_BATCH_PROVIDERS=1` so viewers can see the payout resolve. Do not
use that posture for production unless traffic volume supports it; low-volume
one-minute batches are easier to correlate.

## 5. Running your own facilitator

End-to-end Nitro deployment (KMS bootstrap, PCR pinning, NLB, watchtower, Terraform) is in the root [`README.md`](../README.md). Protocol-level details are in [`subly402-svm-v1-protocol.md`](./a402-svm-v1-protocol.md) and [`a402-solana-design.md`](./a402-solana-design.md).
