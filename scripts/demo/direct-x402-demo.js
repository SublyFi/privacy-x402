#!/usr/bin/env node

const anchor = require("@coral-xyz/anchor");
const {
  createAccount,
  getAccount,
  getMint,
  mintTo,
  transfer,
} = require("@solana/spl-token");
const { Keypair, PublicKey } = require("@solana/web3.js");

const { fundAccount, loadProvider } = require("../devnet/common");
const {
  formatUsdcAtomic,
  loadDemoProviders,
  loadMintAuthority,
  loadNitroEnv,
  logKV,
  logStep,
  printHeader,
  readPositiveIntEnv,
  requireDemoConfirmation,
  requireEnv,
  shortKey,
} = require("./common");

async function main() {
  loadNitroEnv();

  const usdcMint = requireEnv("A402_USDC_MINT");
  const providers = loadDemoProviders();
  const providerIndex = readPositiveIntEnv("A402_DEMO_PROVIDER_INDEX", 1);
  const demoProvider = providers.find(
    (provider) => provider.index === providerIndex
  );
  if (!demoProvider) {
    throw new Error(
      `A402_DEMO_PROVIDER_INDEX=${providerIndex} is not configured`
    );
  }

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

  const plan = {
    mode: "direct-x402-style-baseline",
    cluster: process.env.ANCHOR_PROVIDER_URL || process.env.A402_SOLANA_RPC_URL,
    anchorWallet: process.env.ANCHOR_WALLET || null,
    usdcMint,
    providerId: demoProvider.id,
    providerTokenAccount: demoProvider.tokenAccount,
    paymentAmount,
    note: "This is a direct on-chain settlement baseline for comparison with Subly.",
  };
  requireDemoConfirmation(plan);

  const provider = loadProvider();
  anchor.setProvider(provider);
  const mint = await getMint(provider.connection, new PublicKey(usdcMint));
  const mintAuthority = loadMintAuthority(provider, mint.mintAuthority);
  if (!mintAuthority) {
    throw new Error(
      "Mint authority is required for this devnet direct baseline. Set A402_USDC_MINT_AUTHORITY_WALLET."
    );
  }

  printHeader("Direct x402-style baseline: public on-chain payment edge");
  logStep(1, 'AI agent requests: "summarize private market data"');
  logKV("Provider response", "402 Payment Required");
  logKV("Settlement path", "agent token account -> provider token account");

  const client = Keypair.generate();
  const clientTokenAccount = await createAccount(
    provider.connection,
    provider.wallet.payer,
    new PublicKey(usdcMint),
    client.publicKey
  );
  await fundAccount(provider, client.publicKey, clientSolLamports);
  await mintTo(
    provider.connection,
    provider.wallet.payer,
    new PublicKey(usdcMint),
    clientTokenAccount,
    mintAuthority,
    paymentAmount
  );

  const providerBefore = await getAccount(
    provider.connection,
    new PublicKey(demoProvider.tokenAccount)
  );

  logStep(2, "Agent pays provider directly on devnet");
  const transferSig = await transfer(
    provider.connection,
    provider.wallet.payer,
    clientTokenAccount,
    new PublicKey(demoProvider.tokenAccount),
    client,
    paymentAmount
  );

  const providerAfter = await getAccount(
    provider.connection,
    new PublicKey(demoProvider.tokenAccount)
  );

  logStep(3, "Provider returns paid API response");
  logKV("Result", "private market data summary");

  printHeader("Public chain observer view");
  logKV("Buyer wallet", shortKey(client.publicKey.toBase58()));
  logKV("Buyer token account", shortKey(clientTokenAccount.toBase58()));
  logKV("Provider token account", shortKey(demoProvider.tokenAccount));
  logKV("Amount", formatUsdcAtomic(paymentAmount));
  logKV("Transfer signature", transferSig);
  logKV(
    "Provider balance",
    `${formatUsdcAtomic(providerBefore.amount)} -> ${formatUsdcAtomic(
      providerAfter.amount
    )}`
  );
  logKV("Privacy note", "The direct payment edge is visible on-chain.");

  console.log(
    JSON.stringify(
      {
        ok: true,
        mode: "direct-x402-style-baseline",
        client: client.publicKey.toBase58(),
        clientTokenAccount: clientTokenAccount.toBase58(),
        providerId: demoProvider.id,
        providerTokenAccount: demoProvider.tokenAccount,
        amount: paymentAmount,
        transferSig,
        providerTokenBefore: providerBefore.amount.toString(),
        providerTokenAfter: providerAfter.amount.toString(),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
