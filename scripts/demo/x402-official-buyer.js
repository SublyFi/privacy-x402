#!/usr/bin/env node

const { x402Client, x402HTTPClient } = require("@x402/core/client");
const { wrapFetchWithPayment } = require("@x402/fetch");
const {
  ExactSvmScheme: BuyerExactSvmScheme,
} = require("@x402/svm/exact/client");

const {
  DEFAULT_X402_NETWORK,
  DEMO_ROUTE_PATH,
  deriveTokenAccount,
  demoPaymentAmount,
  ensureAssociatedTokenAccount,
  explorerAddress,
  explorerTx,
  fetchTokenAmount,
  formatUsdcAtomic,
  fundBuyerTokenAccount,
  loadFourWayDemoEnv,
  logKV,
  paymentResponseFromHeaders,
  paymentRequiredFromResponse,
  printHeader,
  requireEnv,
  rpcUrlFromEnv,
  shortKey,
  waitForEndpoint,
} = require("./four-way-common");

function selectOfficialX402Details(paymentRequired, network) {
  return paymentRequired?.accepts?.find((accept) => {
    return (
      accept.scheme === "exact" && (!network || accept.network === network)
    );
  });
}

async function main() {
  loadFourWayDemoEnv();

  const sellerUrl =
    process.env.SUBLY402_X402_SELLER_URL ||
    `http://127.0.0.1:${
      process.env.SUBLY402_X402_SELLER_PORT || 4021
    }${DEMO_ROUTE_PATH}`;
  const network = process.env.SUBLY402_X402_NETWORK || DEFAULT_X402_NETWORK;
  const usdcMint = requireEnv("SUBLY402_USDC_MINT");

  const preflight = await fetch(sellerUrl, { method: "GET" });
  if (preflight.status !== 402) {
    throw new Error(
      `Expected x402 seller to return 402 before payment, got ${preflight.status}`
    );
  }
  const paymentRequired = paymentRequiredFromResponse(preflight);
  const discoveredDetails = selectOfficialX402Details(paymentRequired, network);
  if (!discoveredDetails?.payTo) {
    throw new Error("x402 402 response did not include a Solana payTo wallet");
  }
  const discoveredMint = discoveredDetails.asset || usdcMint;
  if (discoveredMint !== usdcMint) {
    throw new Error(
      `Seller requires asset ${discoveredMint}, but SUBLY402_USDC_MINT is ${usdcMint}`
    );
  }
  const paymentAmount =
    discoveredDetails.amount ||
    discoveredDetails.maxAmountRequired ||
    demoPaymentAmount();

  const { rpc, feePayer, buyer, buyerTokenAccount, fundingTx } =
    await fundBuyerTokenAccount({
      amount: paymentAmount,
    });
  const sellerWallet = discoveredDetails.payTo;
  const derivedSellerTokenAccount = await deriveTokenAccount(
    sellerWallet,
    usdcMint
  );
  const sellerTokenAccount = await ensureAssociatedTokenAccount(
    rpc,
    feePayer,
    sellerWallet,
    usdcMint
  );
  if (sellerTokenAccount !== derivedSellerTokenAccount) {
    throw new Error("Derived x402 seller token account mismatch");
  }
  const sellerBefore = await fetchTokenAmount(rpc, sellerTokenAccount);

  printHeader("Official x402 Buyer");
  logKV("Docs pattern", "@x402/fetch wrapFetchWithPayment + ExactSvmScheme");
  logKV("Seller URL", sellerUrl);
  logKV("Network", network);
  logKV("Buyer wallet", buyer.address);
  logKV("Buyer token account", buyerTokenAccount);
  logKV("Buyer funding tx", fundingTx);
  logKV("Discovered amount", formatUsdcAtomic(paymentAmount));
  logKV("Seller wallet", sellerWallet);
  logKV("Seller token account", sellerTokenAccount);

  const buyerClient = new x402Client().register(
    network,
    new BuyerExactSvmScheme(buyer, { rpcUrl: rpcUrlFromEnv() })
  );
  const fetchWithPayment = wrapFetchWithPayment(fetch, buyerClient);

  const response = await fetchWithPayment(sellerUrl, { method: "GET" });
  const responseText = await response.text();
  if (!response.ok) {
    throw new Error(
      `official x402 request failed: ${response.status} ${responseText}`
    );
  }
  const body = responseText ? JSON.parse(responseText) : null;
  const httpClient = new x402HTTPClient(buyerClient);
  const settleResponse = httpClient.getPaymentSettleResponse((name) =>
    response.headers.get(name)
  );
  const rawPaymentResponse = paymentResponseFromHeaders(response.headers);

  const sellerAfter = await waitForEndpoint(
    "official x402 seller token balance",
    async () => {
      const balance = await fetchTokenAmount(rpc, sellerTokenAccount);
      return balance >= sellerBefore + BigInt(paymentAmount) ? balance : null;
    },
    60,
    1000
  );

  printHeader("Official x402 Result");
  logKV("Paid API response", JSON.stringify(body));
  logKV("Settlement tx", settleResponse?.transaction || "n/a");
  if (settleResponse?.transaction) {
    logKV("Explorer", explorerTx(settleResponse.transaction));
  }
  logKV(
    "Payment response",
    JSON.stringify(rawPaymentResponse || settleResponse)
  );

  printHeader("Public Chain View");
  logKV("Buyer token account", shortKey(buyerTokenAccount));
  logKV("Seller token account", shortKey(sellerTokenAccount));
  logKV("Direct edge", "buyer token account -> seller token account");
  logKV("Amount", formatUsdcAtomic(paymentAmount));
  logKV(
    "Seller balance",
    `${formatUsdcAtomic(sellerBefore)} -> ${formatUsdcAtomic(sellerAfter)}`
  );
  logKV("Buyer explorer", explorerAddress(buyerTokenAccount));
  logKV("Seller explorer", explorerAddress(sellerTokenAccount));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
