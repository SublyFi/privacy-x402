#!/usr/bin/env node

const {
  Subly402Client,
  Subly402ExactScheme,
  wrapFetchWithPayment,
} = require("../../sdk/dist");

const {
  DEFAULT_SUBLY_NETWORK,
  DEMO_ROUTE_PATH,
  buildSublyClientAttestationOptions,
  demoDepositAmount,
  demoPaymentAmount,
  depositIntoSublyVault,
  ensureAssociatedTokenAccount,
  explorerAddress,
  explorerTx,
  fetchPublicSellerMetadata,
  fetchTokenAmount,
  fetchTokenAmountOrNull,
  formatUsdcAtomic,
  fundBuyerTokenAccount,
  getSettlementStatus,
  loadFourWayDemoEnv,
  logKV,
  paymentRequiredFromResponse,
  paymentResponseFromHeaders,
  printHeader,
  requireEnv,
  shortKey,
  waitForEndpoint,
  waitForSublyBalance,
} = require("./four-way-common");

function selectSubly402Details(paymentRequired, network) {
  return paymentRequired?.accepts?.find((accept) => {
    return (
      accept.scheme === "subly402-svm-v1" &&
      (!network || accept.network === network)
    );
  });
}

async function main() {
  loadFourWayDemoEnv();

  const facilitatorUrl = requireEnv("SUBLY402_PUBLIC_ENCLAVE_URL").replace(
    /\/$/,
    ""
  );
  const sellerUrl =
    process.env.SUBLY402_SUBLY_SELLER_URL ||
    `http://127.0.0.1:${
      process.env.SUBLY402_SUBLY_SELLER_PORT || 4022
    }${DEMO_ROUTE_PATH}`;
  const network = process.env.SUBLY402_NETWORK || DEFAULT_SUBLY_NETWORK;
  const preflight = await fetch(sellerUrl, { method: "GET" });
  if (preflight.status !== 402) {
    throw new Error(
      `Expected Subly402 seller to return 402 before payment, got ${preflight.status}`
    );
  }
  const preflightRequired = paymentRequiredFromResponse(preflight);
  const preflightDetails = selectSubly402Details(preflightRequired, network);
  if (!preflightDetails?.payTo) {
    throw new Error(
      "Subly402 402 response did not include a payTo token account"
    );
  }
  const paymentAmount = preflightDetails.amount || demoPaymentAmount();
  const depositAmount =
    BigInt(demoDepositAmount()) > BigInt(paymentAmount)
      ? demoDepositAmount()
      : paymentAmount;

  const { rpc, feePayer, buyer, buyerTokenAccount, fundingTx } =
    await fundBuyerTokenAccount({
      amount: depositAmount,
    });
  let discoveredDetails = preflightDetails;
  let sellerTokenAccount = preflightDetails.payTo;
  const sellerMetadata = await fetchPublicSellerMetadata(sellerUrl);
  if (
    sellerMetadata?.sellerWallet &&
    sellerMetadata.sellerTokenAccount === sellerTokenAccount
  ) {
    await ensureAssociatedTokenAccount(
      rpc,
      feePayer,
      sellerMetadata.sellerWallet,
      preflightDetails.asset.mint
    );
  }
  let sellerBefore = await fetchTokenAmountOrNull(rpc, sellerTokenAccount);

  const deposits = [];
  const recordingFetch = async (input, init) => {
    const response = await fetch(input, init);
    if (response.status === 402) {
      const paymentRequired = paymentRequiredFromResponse(response);
      const details = paymentRequired?.accepts?.find(
        (accept) => accept.scheme === "subly402-svm-v1"
      );
      if (details) {
        discoveredDetails = details;
        sellerTokenAccount = details.payTo;
        if (sellerBefore === null) {
          sellerBefore = await fetchTokenAmountOrNull(rpc, sellerTokenAccount);
        }
      }
    }
    return response;
  };

  printHeader("Subly402 Buyer");
  logKV(
    "Docs pattern",
    "subly402-sdk wrapFetchWithPayment + Subly402ExactScheme"
  );
  logKV("Seller URL", sellerUrl);
  logKV("Facilitator", facilitatorUrl);
  logKV("Network", network);
  logKV("Buyer wallet", buyer.address);
  logKV("Buyer token account", buyerTokenAccount);
  logKV("Buyer funding tx", fundingTx);
  logKV("Discovered amount", formatUsdcAtomic(paymentAmount));
  logKV("Vault token account", requireEnv("SUBLY402_VAULT_TOKEN_ACCOUNT"));

  const client = new Subly402Client({
    trustedFacilitators: [facilitatorUrl],
    policy: {
      maxPaymentPerRequest: paymentAmount.toString(),
    },
    autoDeposit: {
      maxDepositPerRequest: depositAmount.toString(),
      deposit: async ({ amountAtomic, details, reason }) => {
        logKV(
          "Auto deposit trigger",
          `${reason}; depositing ${formatUsdcAtomic(
            amountAtomic
          )} into Subly vault`
        );
        const depositTx = await depositIntoSublyVault({
          rpc,
          feePayer,
          client: buyer,
          clientTokenAccount: buyerTokenAccount,
          amount: amountAtomic,
        });
        await waitForSublyBalance(facilitatorUrl, buyer, amountAtomic);
        deposits.push({
          amountAtomic: amountAtomic.toString(),
          depositTx,
          details,
        });
        logKV("Vault deposit tx", depositTx);
      },
    },
    ...buildSublyClientAttestationOptions(),
  }).register("solana:*", new Subly402ExactScheme(buyer));

  const fetchWithPayment = wrapFetchWithPayment(recordingFetch, client);
  const response = await fetchWithPayment(sellerUrl, { method: "GET" });
  const responseText = await response.text();
  if (!response.ok) {
    throw new Error(
      `Subly402 request failed: ${response.status} ${responseText}`
    );
  }
  const body = responseText ? JSON.parse(responseText) : null;
  const paymentResponse = paymentResponseFromHeaders(response.headers);

  printHeader("Subly402 Result");
  logKV("Paid API response", JSON.stringify(body));
  logKV(
    "Discovered provider",
    discoveredDetails?.providerId || body?.providerId
  );
  logKV("Payment response", JSON.stringify(paymentResponse));
  for (const deposit of deposits) {
    logKV(
      "Visible deposit",
      `${deposit.depositTx} (${explorerTx(deposit.depositTx)})`
    );
  }

  const settlementId = paymentResponse?.settlementId;
  const providerId = discoveredDetails?.providerId || body?.providerId;
  let settlementStatus = null;

  if (
    settlementId &&
    providerId &&
    process.env.SUBLY402_DEMO_SKIP_BATCH_WAIT !== "1"
  ) {
    settlementStatus = await waitForEndpoint(
      "Subly batched provider payout",
      async () => {
        const status = await getSettlementStatus(
          facilitatorUrl,
          settlementId,
          providerId
        );
        return status.txSignature ? status : null;
      },
      Number(process.env.SUBLY402_DEMO_BATCH_WAIT_ATTEMPTS || 72),
      Number(process.env.SUBLY402_DEMO_BATCH_WAIT_DELAY_MS || 5000)
    ).catch((error) => ({
      ok: false,
      settlementId,
      status: "pending_or_timeout",
      message: error.message,
    }));
  }

  const sellerAfter =
    sellerTokenAccount && settlementStatus?.txSignature
      ? await fetchTokenAmount(rpc, sellerTokenAccount)
      : null;

  printHeader("Public Chain View");
  logKV("Buyer token account", shortKey(buyerTokenAccount));
  logKV(
    "Vault token account",
    shortKey(requireEnv("SUBLY402_VAULT_TOKEN_ACCOUNT"))
  );
  logKV("Seller token account", shortKey(sellerTokenAccount));
  logKV("Visible now", "buyer token account -> Subly vault deposit");
  logKV("Hidden", "direct buyer token account -> seller token account edge");
  if (settlementStatus?.txSignature) {
    logKV("Batched payout tx", settlementStatus.txSignature);
    logKV("Payout explorer", explorerTx(settlementStatus.txSignature));
  } else {
    logKV(
      "Batched payout tx",
      "pending; settlement can land after the batch window"
    );
  }
  if (sellerBefore !== null && sellerAfter !== null) {
    logKV(
      "Seller balance",
      `${formatUsdcAtomic(sellerBefore)} -> ${formatUsdcAtomic(sellerAfter)}`
    );
  } else if (sellerAfter !== null) {
    logKV("Seller balance", `after payout ${formatUsdcAtomic(sellerAfter)}`);
  }
  logKV("Buyer explorer", explorerAddress(buyerTokenAccount));
  logKV(
    "Vault explorer",
    explorerAddress(requireEnv("SUBLY402_VAULT_TOKEN_ACCOUNT"))
  );
  if (sellerTokenAccount) {
    logKV("Seller explorer", explorerAddress(sellerTokenAccount));
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
