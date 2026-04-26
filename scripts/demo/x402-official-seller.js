#!/usr/bin/env node

const express = require("express");
const { paymentMiddleware, x402ResourceServer } = require("@x402/express");
const { HTTPFacilitatorClient } = require("@x402/core/server");
const {
  ExactSvmScheme: SellerExactSvmScheme,
} = require("@x402/svm/exact/server");

const {
  DEFAULT_X402_FACILITATOR_URL,
  DEFAULT_X402_NETWORK,
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

  const usdcMint = requireEnv("SUBLY402_USDC_MINT");
  const network = process.env.SUBLY402_X402_NETWORK || DEFAULT_X402_NETWORK;
  const facilitatorUrl =
    process.env.SUBLY402_X402_FACILITATOR_URL || DEFAULT_X402_FACILITATOR_URL;
  const host = process.env.SUBLY402_X402_SELLER_HOST || "127.0.0.1";
  const port = Number(process.env.SUBLY402_X402_SELLER_PORT || 4021);
  const paymentAmount = demoPaymentAmount();
  const price = {
    asset: usdcMint,
    amount: paymentAmount.toString(),
  };
  const { sellerWallet, associatedTokenAccount } = await resolveDemoSeller();

  const app = express();
  app.use(express.json());

  const facilitatorClient = new HTTPFacilitatorClient({
    url: facilitatorUrl,
  });
  const resourceServer = new x402ResourceServer(facilitatorClient).register(
    network,
    new SellerExactSvmScheme()
  );

  app.use(
    paymentMiddleware(
      {
        [`GET ${DEMO_ROUTE_PATH}`]: {
          accepts: [
            {
              scheme: "exact",
              price,
              network,
              payTo: sellerWallet,
              maxTimeoutSeconds: 120,
            },
          ],
          description: DEMO_DESCRIPTION,
          mimeType: DEMO_MIME_TYPE,
        },
      },
      resourceServer,
      {
        appName: "Subly side-by-side official x402 seller",
        testnet: true,
      }
    )
  );

  app.get(DEMO_ROUTE_PATH, (_req, res) => {
    res.json(
      demoWeatherResponse({
        mode: "official-x402-direct",
        providerId: "official-x402-weather",
      })
    );
  });

  const server = await listen(app, host, port);
  const address = server.address();
  const url = `http://${host}:${address.port}${DEMO_ROUTE_PATH}`;

  printHeader("Official x402 Seller");
  logKV("Docs pattern", "@x402/express paymentMiddleware + ExactSvmScheme");
  logKV("URL", url);
  logKV("Route", `GET ${DEMO_ROUTE_PATH}`);
  logKV("Network", network);
  logKV("Facilitator", facilitatorUrl);
  logKV("Price", formatUsdcAtomic(paymentAmount));
  logKV("Seller wallet", sellerWallet);
  logKV("Seller token account", associatedTokenAccount);
  logKV("Explorer", explorerAddress(associatedTokenAccount));
  console.log("");
  console.log("Run the paired buyer in another terminal:");
  console.log(`  SUBLY402_X402_SELLER_URL='${url}' yarn demo:x402-buyer`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
