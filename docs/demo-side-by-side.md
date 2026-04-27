# x402 vs Subly402 Side-by-Side Demo

This demo provides four runnable entry points for recording the same paid
`GET /weather` flow:

- official x402 Seller: `scripts/demo/x402-official-seller.js`
- official x402 Buyer: `scripts/demo/x402-official-buyer.js`
- Subly402 Seller: `scripts/demo/subly402-seller.js`
- Subly402 Buyer: `scripts/demo/subly402-buyer.js`
- public Seller host for EC2: `scripts/demo/public-seller-host.js`

The x402 scripts follow the official quickstart shape:

- Seller: `@x402/express` `paymentMiddleware` + `x402ResourceServer`
- Buyer: `@x402/fetch` `wrapFetchWithPayment`

References:

- https://docs.x402.org/getting-started/quickstart-for-sellers
- https://docs.x402.org/getting-started/quickstart-for-buyers
- https://www.x402.org/

The Subly402 scripts follow the repo quickstart shape:

- Seller: `subly402-express` `paymentMiddleware` + `Subly402ResourceServer`
- Buyer: `subly402-sdk` `wrapFetchWithPayment`

References:

- `docs/quickstart.md`
- `middleware/README.md`
- `sdk/README.md`

## One-Time Local Devnet Setup

Use this path when you need a faucetable Devnet mint for recording. The
facilitator/watchtower processes run on your machine, but all token transfers and
vault transactions are on Solana Devnet.

```bash
yarn install --frozen-lockfile
npm --prefix middleware run build
npm --prefix sdk run build

yarn devnet:bootstrap
yarn devnet:start
```

If local WAL replay fails after re-bootstrap, move the old local demo WAL aside:

```bash
yarn devnet:stop
mv data/wal-devnet.jsonl "data/wal-devnet.jsonl.bak-$(date -u +%Y%m%dT%H%M%SZ)"
yarn devnet:start
```

## Official x402 Direct Payment

Terminal 1:

```bash
yarn demo:x402-seller
```

Terminal 2:

```bash
yarn demo:x402-buyer
```

What to show:

- The paid API returns the weather JSON.
- The payment response includes a Solana devnet settlement transaction.
- The public chain view is `buyer token account -> seller token account`.

## Subly402 Private Vault Payment

Terminal 1:

```bash
SUBLY402_PUBLIC_ENCLAVE_URL="http://127.0.0.1:3100" yarn demo:subly-seller
```

Terminal 2:

```bash
SUBLY402_PUBLIC_ENCLAVE_URL="http://127.0.0.1:3100" \
SUBLY402_SUBLY_SELLER_URL="http://127.0.0.1:4022/weather" \
yarn demo:subly-buyer
```

What to show:

- The Buyer still uses a fetch wrapper and calls the same paid `/weather` API.
- The first visible transaction is `buyer token account -> Subly vault`.
- The seller payout is `Subly vault -> seller token account` after batching.
- There is no direct buyer token account -> seller token account edge.

The public privacy defaults intentionally delay payout batching. Depending on
the deployed facilitator settings, the payout transaction may appear minutes
after the paid API response. That delay is the privacy feature being shown.
For the hosted demo, use a one-minute payout posture only when you want viewers
to see the `Vault -> Seller` movement during the session:

```bash
export SUBLY402_BATCH_WINDOW_SEC=60
export SUBLY402_MIN_ANONYMITY_WINDOW_SEC=60
export SUBLY402_MIN_BATCH_PROVIDERS=1
```

This is a demo tradeoff. With low volume, one-minute batches can make it easier
to correlate who participated, so keep longer windows for public production
deployments.

## EC2 Seller Host

Use this when the seller needs a public URL. The host process exposes both demo
routes from one EC2 instance:

- `GET /x402/weather` for official x402 direct settlement
- `GET /subly/weather` for Subly402 private vault settlement
- `GET /.well-known/subly402.json` for public route and attestation metadata

On the seller EC2:

```bash
git clone <repo-url> subly
cd subly
yarn install --frozen-lockfile
npm --prefix middleware run build
npm --prefix sdk run build

export SUBLY402_SELLER_HOST="0.0.0.0"
export SUBLY402_SELLER_PORT="8080"
export SUBLY402_SELLER_PUBLIC_URL="https://seller.example.com"

export SELLER_WALLET="<seller wallet owner address>"
export SUBLY402_PUBLIC_ENCLAVE_URL="https://api.demo.sublyfi.com"
export SUBLY402_NETWORK="solana:devnet"
export SUBLY402_USDC_MINT="<facilitator Devnet USDC mint>"
export SUBLY402_DEMO_PAYMENT_AMOUNT="1100000"

yarn demo:seller-host
```

Put nginx or an AWS load balancer in front of port `8080` for HTTPS.

The seller host only needs the seller's public wallet address. It does not load
the seller private key, does not issue a provider API key, and does not register
the seller in advance. The Buyer demo preflights the public route's 402 response
and creates the seller's associated token account with the Buyer's fee payer if
that account does not exist yet.

Buyer commands against the public seller:

```bash
SUBLY402_X402_SELLER_URL="https://seller.example.com/x402/weather" \
yarn demo:x402-buyer

SUBLY402_PUBLIC_ENCLAVE_URL="https://api.demo.sublyfi.com" \
SUBLY402_SUBLY_SELLER_URL="https://seller.example.com/subly/weather" \
yarn demo:subly-buyer
```

The Buyer machine still needs Devnet funding configuration for the selected
asset mint:

- `SUBLY402_USDC_MINT`
- `SUBLY402_SOLANA_RPC_URL` or `ANCHOR_PROVIDER_URL` using an authenticated
  Solana Devnet RPC such as Alchemy
- `ANCHOR_WALLET`
- either `SUBLY402_USDC_MINT_AUTHORITY_WALLET` or
  `SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT`

For a long-running EC2 process, use the same environment variables in systemd:

```ini
[Unit]
Description=Subly402 public seller demo
After=network-online.target

[Service]
WorkingDirectory=/opt/subly
Environment=SUBLY402_SELLER_HOST=0.0.0.0
Environment=SUBLY402_SELLER_PORT=8080
Environment=SUBLY402_SELLER_PUBLIC_URL=https://seller.example.com
Environment=SELLER_WALLET=<seller wallet owner address>
Environment=SUBLY402_PUBLIC_ENCLAVE_URL=https://api.demo.sublyfi.com
Environment=SUBLY402_NETWORK=solana:devnet
Environment=SUBLY402_USDC_MINT=<facilitator Devnet USDC mint>
ExecStart=/usr/bin/yarn demo:seller-host
Restart=always

[Install]
WantedBy=multi-user.target
```

## Public Facilitator Note

`https://api.demo.sublyfi.com` is the Subly402 facilitator URL, not a seller API.
It serves `/v1/attestation`, `/v1/verify`, `/v1/settle`, and related facilitator
routes. It does not serve `GET /weather` directly. The seller script provides the
paid `/weather` route and points to the facilitator.

## Attestation Metadata

The facilitator returns live attestation at `/v1/attestation`. That response
contains the current `vaultConfig`, `vaultSigner`, `attestationPolicyHash`,
TLS public key hash, and the attestation document. The seller host also republishes
a summarized view at `/.well-known/subly402.json`.

For a production-grade Buyer verification policy, pin expected PCR values and
signing identity in the Buyer environment, then let `subly402-sdk` verify the
Nitro attestation before paying. Without PCR pinning, the demo Buyer only checks
that the response matches the expected vault and policy hash.

PCRs are Nitro Enclave measurements of the enclave image/runtime and selected
launch context. They are not the seller wallet address. The seller wallet only
chooses where payouts go; PCR pinning chooses which facilitator enclave binary
the Buyer trusts.

The metadata can be published in two places:

- Facilitator live attestation: `GET <facilitator>/v1/attestation`
- Seller route metadata: `GET <seller>/.well-known/subly402.json`

Buyers do not need to re-verify Nitro attestation on every HTTP request. The SDK
fetches and caches attestation per facilitator, reusing it until it is near
expiry or no longer matches the 402 payment details. For recording, this means
the first paid request shows the verification step, and later requests can reuse
the cached attestation.

## Batch Settings

There is no special "shooting mode" in these demo scripts. Subly402 payout timing
comes from the facilitator/enclave runtime configuration. The relevant privacy
settings, such as minimum anonymity window and minimum batch providers, belong to
the deployed facilitator environment. They are not Buyer or Seller EC2
environment variables.
