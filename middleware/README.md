# subly402-express

Express middleware that serves paid APIs through the Subly privacy-first x402 facilitator. Drop-in replacement for x402 sellers who want their settlements hidden behind a TEE-backed vault.

## Install

```bash
yarn add subly402-express
```

The default import path is the x402-like Seller middleware and uses `@solana/kit` plus `@solana-program/token` for Solana address handling. Advanced ASC helpers are available from `subly402-express/asc`; that optional path requires the legacy Solana/Anchor dependencies.

## Quickstart for Sellers

No provider registration or API key is required for the default seller flow. The facilitator derives the seller identity from `network + asset mint + payTo` and auto-registers that open seller the first time a valid paid request is verified. For Solana, sellers can provide a wallet owner and the middleware derives the USDC associated token account.

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
  url: "https://enclave.example.com",
  assetMint: process.env.USDC_MINT!,
});

const resourceServer = new Subly402ResourceServer(facilitator).register(
  "solana:*",
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
            network: "solana:devnet",
            sellerWallet: process.env.SELLER_WALLET!,
          },
        ],
        description: "Weather data",
        mimeType: "application/json",
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

That is the full seller integration: install the package, point it at a deployed Subly facilitator, choose a route, price, network, and receiving wallet.

Advanced sellers can still pass `payTo` directly when they want to settle to a specific token account instead of the wallet's associated token account. The normal x402-compatible path does not require pre-registration, API-key issuance, or a cloud-provider account.

## Behaviour

- Returns HTTP 402 with `subly402-svm-v1` details when a request does not present a valid `PAYMENT-SIGNATURE`.
- Verifies + reserves in the enclave before the route handler runs.
- Settles in the enclave before returning the 2xx response, so WAL durability is honored (`§8.3`).
- Adds a `PAYMENT-RESPONSE` header describing the settlement / batch / receipt identifiers.
- Enforces the Single-Execution Rule on `verificationId` to reject duplicates.

## License

ISC
