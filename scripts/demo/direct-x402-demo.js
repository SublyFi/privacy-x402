#!/usr/bin/env node

const express = require("express");
const { paymentMiddleware, x402ResourceServer } = require("@x402/express");
const { x402Client, x402HTTPClient } = require("@x402/core/client");
const { HTTPFacilitatorClient } = require("@x402/core/server");
const { wrapFetchWithPayment } = require("@x402/fetch");
const {
  ExactSvmScheme: BuyerExactSvmScheme,
} = require("@x402/svm/exact/client");
const {
  ExactSvmScheme: SellerExactSvmScheme,
} = require("@x402/svm/exact/server");

const {
  formatUsdcAtomic,
  loadDemoProviders,
  loadNitroEnv,
  logKV,
  logStep,
  printHeader,
  readPositiveIntEnv,
  requireDemoConfirmation,
  requireEnv,
  selectDemoProviders,
  shortKey,
  waitForEndpoint,
} = require("./common");
const {
  DEMO_DESCRIPTION,
  DEMO_MIME_TYPE,
  DEMO_ROUTE_PATH,
  buildDemoResponse,
  requestSummary,
} = require("./scenario");
const {
  createAssociatedTokenAccount,
  createDemoRpc,
  createDemoSigner,
  fetchTokenAmount,
  fetchTokenOwner,
  fundAddressWithSol,
  loadFeePayerSigner,
  loadMintAuthoritySigner,
  mintTokens,
  rpcUrlFromEnv,
} = require("./solana-kit");

const DEFAULT_X402_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const DEFAULT_X402_FACILITATOR_URL = "https://x402.org/facilitator";

function buildX402Price(usdcMint, paymentAmount) {
  if (process.env.A402_X402_PRICE) {
    return process.env.A402_X402_PRICE;
  }
  return {
    asset: process.env.A402_X402_ASSET_MINT || usdcMint,
    amount: paymentAmount.toString(),
  };
}

function listen(app, port) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, "127.0.0.1");
    server.once("listening", () => resolve(server));
    server.once("error", reject);
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function startOfficialX402Seller({
  facilitatorUrl,
  network,
  path,
  payTo,
  port,
  price,
  providerId,
}) {
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
        [`GET ${path}`]: {
          accepts: [
            {
              scheme: "exact",
              price,
              network,
              payTo,
              maxTimeoutSeconds: 120,
            },
          ],
          description: DEMO_DESCRIPTION,
          mimeType: DEMO_MIME_TYPE,
        },
      },
      resourceServer,
      {
        appName: "Subly direct x402 comparison demo",
        testnet: true,
      }
    )
  );

  app.get(path, (_req, res) => {
    res.json({
      ok: true,
      ...buildDemoResponse({
        providerId,
        settlementMode: "official-x402-direct",
      }),
    });
  });

  const server = await listen(app, port);
  const addressInfo = server.address();
  return {
    server,
    url: `http://127.0.0.1:${addressInfo.port}${path}`,
  };
}

async function main() {
  loadNitroEnv();

  const usdcMint = requireEnv("A402_USDC_MINT");
  const selectedProviders = selectDemoProviders(loadDemoProviders());
  if (selectedProviders.length !== 1) {
    throw new Error(
      "Official x402 direct demo supports one provider. Unset A402_DEMO_ALL_PROVIDERS or set A402_DEMO_PROVIDER_INDEX."
    );
  }
  const [demoProvider] = selectedProviders;
  const providerIndex = demoProvider.index;

  const paymentAmount = Number(
    readPositiveIntEnv(
      "A402_DEMO_PAYMENT_AMOUNT",
      readPositiveIntEnv("A402_NITRO_E2E_PAYMENT_AMOUNT", 1100000)
    )
  );
  const clientSolLamports = Number(
    readPositiveIntEnv(
      "A402_DEMO_CLIENT_SOL_LAMPORTS",
      readPositiveIntEnv("A402_NITRO_E2E_CLIENT_SOL_LAMPORTS", 50000000)
    )
  );
  const x402Network = process.env.A402_X402_NETWORK || DEFAULT_X402_NETWORK;
  const facilitatorUrl =
    process.env.A402_X402_FACILITATOR_URL || DEFAULT_X402_FACILITATOR_URL;
  const sellerPort = Number(process.env.A402_X402_DEMO_PORT || 0);
  const price = buildX402Price(usdcMint, paymentAmount);

  const plan = {
    mode: "official-x402-direct",
    docs: {
      buyer: "https://docs.x402.org/getting-started/quickstart-for-buyers",
      seller: "https://docs.x402.org/getting-started/quickstart-for-sellers",
    },
    cluster: rpcUrlFromEnv(),
    feePayerWallet: process.env.ANCHOR_WALLET || null,
    facilitatorUrl,
    x402Network,
    usdcMint,
    route: `GET ${DEMO_ROUTE_PATH}`,
    price,
    providerId: demoProvider.id,
    providerConfiguredTokenAccount: demoProvider.tokenAccount,
    note: "Uses official @x402/express seller middleware and @x402/fetch buyer wrapper. Seller payTo is the provider wallet owner, not a token account.",
  };
  requireDemoConfirmation(plan);

  const rpc = createDemoRpc();
  const { signer: feePayer } = await loadFeePayerSigner();
  const mintAuthority = await loadMintAuthoritySigner(rpc, usdcMint, feePayer);
  if (!mintAuthority) {
    throw new Error(
      "Mint authority is required for this devnet demo. Set A402_USDC_MINT_AUTHORITY_WALLET."
    );
  }

  printHeader("Official x402 direct: buyer fetch + seller middleware");
  logStep(1, requestSummary());
  logKV("Buyer SDK", "@x402/fetch wrapFetchWithPayment");
  logKV("Seller SDK", "@x402/express paymentMiddleware");
  logKV("Facilitator", facilitatorUrl);

  const providerWallet =
    process.env[`A402_DEMO_PROVIDER_${providerIndex}_WALLET`] ||
    (await fetchTokenOwner(rpc, demoProvider.tokenAccount));
  const officialProviderTokenAccount = await createAssociatedTokenAccount(
    rpc,
    feePayer,
    providerWallet,
    usdcMint
  );
  const providerBefore = await fetchTokenAmount(
    rpc,
    officialProviderTokenAccount
  );

  const { signer: client } = await createDemoSigner();
  const clientTokenAccount = await createAssociatedTokenAccount(
    rpc,
    feePayer,
    client.address,
    usdcMint
  );
  await fundAddressWithSol(rpc, feePayer, client.address, clientSolLamports);
  await mintTokens(
    rpc,
    feePayer,
    usdcMint,
    clientTokenAccount,
    mintAuthority,
    paymentAmount
  );

  const seller = await startOfficialX402Seller({
    facilitatorUrl,
    network: x402Network,
    path: DEMO_ROUTE_PATH,
    payTo: providerWallet,
    port: sellerPort,
    price,
    providerId: demoProvider.id,
  });

  try {
    logStep(2, "Agent calls paid API through official x402 fetch wrapper");
    const buyerClient = new x402Client().register(
      x402Network,
      new BuyerExactSvmScheme(client, { rpcUrl: rpcUrlFromEnv() })
    );
    const fetchWithPayment = wrapFetchWithPayment(fetch, buyerClient);
    const response = await fetchWithPayment(seller.url, { method: "GET" });
    const responseText = await response.text();
    if (!response.ok) {
      throw new Error(
        `official x402 request failed: ${response.status} ${responseText}`
      );
    }
    const body = responseText ? JSON.parse(responseText) : null;
    const httpClient = new x402HTTPClient(buyerClient);
    const paymentResponse = httpClient.getPaymentSettleResponse((name) =>
      response.headers.get(name)
    );

    logStep(3, "Provider returns paid API response after settlement");
    logKV("Result", JSON.stringify(body.report));
    logKV("Settlement tx", paymentResponse.transaction);

    const providerAfter = await waitForEndpoint(
      "official x402 provider token balance",
      async () => {
        const balance = await fetchTokenAmount(
          rpc,
          officialProviderTokenAccount
        );
        return balance >= providerBefore + BigInt(paymentAmount)
          ? balance
          : null;
      },
      60,
      1000
    );

    printHeader("Public chain observer view");
    logKV("Buyer wallet", shortKey(client.address));
    logKV("Buyer token account", shortKey(clientTokenAccount));
    logKV("Provider wallet", shortKey(providerWallet));
    logKV("Provider token account", shortKey(officialProviderTokenAccount));
    if (officialProviderTokenAccount !== demoProvider.tokenAccount) {
      logKV(
        "Configured Subly token account",
        shortKey(demoProvider.tokenAccount)
      );
    }
    logKV("Amount", formatUsdcAtomic(paymentAmount));
    logKV(
      "Provider balance",
      `${formatUsdcAtomic(providerBefore)} -> ${formatUsdcAtomic(
        providerAfter
      )}`
    );
    logKV(
      "Privacy note",
      "Official x402 settles directly from buyer ATA to provider ATA."
    );

    console.log(
      JSON.stringify(
        {
          ok: true,
          mode: "official-x402-direct",
          client: client.address,
          clientTokenAccount,
          providerId: demoProvider.id,
          providerWallet,
          providerTokenAccount: officialProviderTokenAccount,
          configuredSublyProviderTokenAccount: demoProvider.tokenAccount,
          amount: paymentAmount,
          response: body,
          paymentResponse,
          providerTokenBefore: providerBefore.toString(),
          providerTokenAfter: providerAfter.toString(),
        },
        null,
        2
      )
    );
  } finally {
    await closeServer(seller.server);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
