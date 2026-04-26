#!/usr/bin/env node

const express = require("express");
const {
  Subly402ExactScheme,
  Subly402FacilitatorClient,
  Subly402ResourceServer,
  captureSubly402RawBody,
  paymentMiddleware,
} = require("../../middleware/dist");

const {
  DEFAULT_SUBLY_NETWORK,
  DEMO_DESCRIPTION,
  DEMO_MIME_TYPE,
  DEMO_ROUTE_PATH,
  demoPaymentAmount,
  demoWeatherResponse,
  explorerAddress,
  formatUsdcAtomic,
  loadFourWayDemoEnv,
  logKV,
  printHeader,
  requireEnv,
  resolveDemoSeller,
  shortKey,
} = require("./four-way-common");

function listen(app, host, port) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host);
    server.once("listening", () => resolve(server));
    server.once("error", reject);
  });
}

async function main() {
  loadFourWayDemoEnv();

  const facilitatorUrl = requireEnv("SUBLY402_PUBLIC_ENCLAVE_URL").replace(
    /\/$/,
    ""
  );
  const usdcMint = requireEnv("SUBLY402_USDC_MINT");
  const network = process.env.SUBLY402_NETWORK || DEFAULT_SUBLY_NETWORK;
  const host = process.env.SUBLY402_SUBLY_SELLER_HOST || "127.0.0.1";
  const port = Number(process.env.SUBLY402_SUBLY_SELLER_PORT || 4022);
  const paymentAmount = demoPaymentAmount();
  const { sellerWallet, associatedTokenAccount } = await resolveDemoSeller();

  const facilitatorOptions = {
    url: facilitatorUrl,
    assetMint: usdcMint,
  };

  const routeAccept = {
    scheme: "exact",
    price: paymentAmount,
    network,
    sellerWallet,
  };

  const app = express();
  app.use(express.json({ verify: captureSubly402RawBody }));

  const facilitator = new Subly402FacilitatorClient(facilitatorOptions);
  const resourceServer = new Subly402ResourceServer(facilitator).register(
    "solana:*",
    new Subly402ExactScheme()
  );

  app.use(
    paymentMiddleware(
      {
        [`GET ${DEMO_ROUTE_PATH}`]: {
          accepts: [routeAccept],
          description: DEMO_DESCRIPTION,
          mimeType: DEMO_MIME_TYPE,
        },
      },
      resourceServer
    )
  );

  app.get(DEMO_ROUTE_PATH, (req, res) => {
    res.json(
      demoWeatherResponse({
        mode: "subly-private-x402",
        providerId: req.subly402?.providerId || "derived-open-seller",
      })
    );
  });

  const server = await listen(app, host, port);
  const address = server.address();
  const url = `http://${host}:${address.port}${DEMO_ROUTE_PATH}`;

  printHeader("Subly402 Seller");
  logKV(
    "Docs pattern",
    "subly402-express paymentMiddleware + Subly402ExactScheme"
  );
  logKV("URL", url);
  logKV("Route", `GET ${DEMO_ROUTE_PATH}`);
  logKV("Network", network);
  logKV("Facilitator", facilitatorUrl);
  logKV(
    "Provider mode",
    "open seller; no pre-registration or provider API key"
  );
  logKV("Price", formatUsdcAtomic(paymentAmount));
  logKV("Seller wallet", sellerWallet);
  logKV("Seller token account", associatedTokenAccount);
  logKV(
    "Provider id",
    "derived from network + asset mint + seller token account"
  );
  logKV("Provider auth", "none");
  logKV("Explorer", explorerAddress(associatedTokenAccount));
  console.log("");
  console.log("Run the paired buyer in another terminal:");
  console.log(`  SUBLY402_SUBLY_SELLER_URL='${url}' yarn demo:subly-buyer`);
  console.log("");
  console.log("Privacy note:");
  console.log(
    `  Buyer pays ${shortKey(
      requireEnv("SUBLY402_VAULT_TOKEN_ACCOUNT")
    )} first; seller payout is batched later.`
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
