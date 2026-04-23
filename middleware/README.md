# subly402-express

Express middleware that serves paid APIs through the Subly privacy-first x402 facilitator. Drop-in replacement for x402 sellers who want their settlements hidden behind a TEE-backed vault.

## Install

```bash
yarn add subly402-express
```

## Quickstart

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
  url: "https://enclave.example.com",
  providerApiKey: process.env.SUBLY_PROVIDER_API_KEY,
  authMode: "bearer",
  assetMint: "<USDC mint>",
});

const resourceServer = new Subly402ResourceServer(facilitator).register(
  "solana:devnet",
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
            payTo: "<provider settlement token account>",
            providerId: "prov_demo",
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

## Behaviour

- Returns HTTP 402 with `a402-svm-v1` details when a request does not present a valid `PAYMENT-SIGNATURE`.
- Verifies + reserves in the enclave before the route handler runs.
- Settles in the enclave before returning the 2xx response, so WAL durability is honored (`§8.3`).
- Adds a `PAYMENT-RESPONSE` header describing the settlement / batch / receipt identifiers.
- Enforces the Single-Execution Rule on `verificationId` to reject duplicates.

## License

ISC
