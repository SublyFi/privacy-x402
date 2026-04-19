#!/usr/bin/env node

const anchor = require("@coral-xyz/anchor");
const {
  createAccount,
  getAccount,
  getMint,
  mintTo,
  TOKEN_PROGRAM_ID,
  transfer,
} = require("@solana/spl-token");
const { Keypair, PublicKey } = require("@solana/web3.js");

const {
  fundAccount,
  loadProgram,
  loadProvider,
  postJson,
  sha256hex,
  waitForEndpoint,
} = require("../devnet/common");
const {
  assertFinalRoutes,
  buildClientRequestAuth,
  buildPayment,
  fetchJson,
  formatUsdcAtomic,
  loadDemoProviders,
  loadKeypairFromFile,
  loadMintAuthority,
  loadNitroEnv,
  logKV,
  logStep,
  postOrThrow,
  printHeader,
  readPositiveIntEnv,
  requireDemoConfirmation,
  requireEnv,
  shortKey,
} = require("./common");

async function getProviderBalances(connection, providers) {
  const balances = [];
  for (const provider of providers) {
    const account = await getAccount(
      connection,
      new PublicKey(provider.tokenAccount)
    );
    balances.push(BigInt(account.amount.toString()));
  }
  return balances;
}

async function getSettlementStatuses(enclaveUrl, settlements, providers) {
  const statuses = [];
  for (const settlement of settlements) {
    const demoProvider = providers.find(
      (provider) => provider.id === settlement.providerId
    );
    const response = await postJson(
      enclaveUrl,
      "/v1/settlement/status",
      { settlementId: settlement.settleBody.settlementId },
      {
        Authorization: `Bearer ${demoProvider.apiKey}`,
        "x-a402-provider-id": demoProvider.id,
      }
    );
    statuses.push({
      providerId: settlement.providerId,
      settlementId: settlement.settleBody.settlementId,
      httpStatus: response.status,
      body: response.ok ? await response.json() : await response.text(),
    });
  }
  return statuses;
}

async function main() {
  loadNitroEnv();

  if (process.env.A402_NITRO_ALLOW_SELF_SIGNED_TLS !== "0") {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

  const enclaveUrl = requireEnv("A402_PUBLIC_ENCLAVE_URL").replace(/\/$/, "");
  const vaultConfig = requireEnv("A402_VAULT_CONFIG");
  const vaultTokenAccount = requireEnv("A402_VAULT_TOKEN_ACCOUNT");
  const usdcMint = requireEnv("A402_USDC_MINT");
  const expectedPolicyHash = requireEnv("A402_ATTESTATION_POLICY_HASH_HEX");
  const requestOrigin =
    process.env.A402_REQUEST_ORIGIN || "https://demo.subly.dev";
  const network = process.env.A402_NETWORK || "solana:devnet";
  const depositAmount = Number(
    process.env.A402_DEMO_DEPOSIT_AMOUNT ||
      process.env.A402_NITRO_E2E_DEPOSIT_AMOUNT ||
      "3000000"
  );
  const paymentAmount = Number(
    process.env.A402_DEMO_PAYMENT_AMOUNT ||
      process.env.A402_NITRO_E2E_PAYMENT_AMOUNT ||
      "1100000"
  );
  const clientSolLamports = Number(
    process.env.A402_DEMO_CLIENT_SOL_LAMPORTS ||
      process.env.A402_NITRO_E2E_CLIENT_SOL_LAMPORTS ||
      "50000000"
  );
  const batchWaitAttempts = readPositiveIntEnv(
    "A402_DEMO_BATCH_WAIT_ATTEMPTS",
    readPositiveIntEnv("A402_NITRO_E2E_BATCH_WAIT_ATTEMPTS", 72)
  );
  const batchWaitDelayMs = readPositiveIntEnv(
    "A402_DEMO_BATCH_WAIT_DELAY_MS",
    readPositiveIntEnv("A402_NITRO_E2E_BATCH_WAIT_DELAY_MS", 5000)
  );
  const providers = loadDemoProviders();

  if (depositAmount < paymentAmount * providers.length) {
    throw new Error("deposit amount must cover all provider payment amounts");
  }

  const provider = loadProvider();
  anchor.setProvider(provider);
  const program = loadProgram(provider);
  const mint = await getMint(provider.connection, new PublicKey(usdcMint));
  const mintAuthority = loadMintAuthority(provider, mint.mintAuthority);

  const plan = {
    mode: "subly-private-x402",
    cluster: process.env.ANCHOR_PROVIDER_URL || process.env.A402_SOLANA_RPC_URL,
    feePayer: provider.wallet.publicKey.toBase58(),
    enclaveUrl,
    vaultConfig,
    vaultTokenAccount,
    usdcMint,
    expectedPolicyHash,
    depositAmount,
    paymentAmountPerProvider: paymentAmount,
    providers: providers.map(({ id, tokenAccount }) => ({ id, tokenAccount })),
    batchWaitAttempts,
    batchWaitDelayMs,
  };
  requireDemoConfirmation(plan);

  printHeader("Subly privacy-first x402: private vault + batched settlement");
  logStep(1, 'AI agent requests: "summarize private market data"');
  logKV("Payment path", "agent -> Subly vault -> providers");
  logKV("Public URL", enclaveUrl);

  const attestation = await fetchJson(enclaveUrl, "/v1/attestation");
  if (attestation.vaultConfig !== vaultConfig) {
    throw new Error("attestation vaultConfig mismatch");
  }
  if (
    attestation.attestationPolicyHash.toLowerCase() !==
    expectedPolicyHash.toLowerCase()
  ) {
    throw new Error("attestation policy hash mismatch");
  }
  await assertFinalRoutes(enclaveUrl);
  logStep(2, "Verified live Nitro attestation and final-only API surface");
  logKV("Attestation hash", attestation.attestationPolicyHash);
  logKV("Snapshot seqno", attestation.snapshotSeqno);
  logKV("Admin API", "closed");

  const providerTokenBefore = await getProviderBalances(
    provider.connection,
    providers
  );

  const client = Keypair.generate();
  const clientTokenAccount = await createAccount(
    provider.connection,
    provider.wallet.payer,
    new PublicKey(usdcMint),
    client.publicKey
  );
  await fundAccount(provider, client.publicKey, clientSolLamports);

  if (mintAuthority) {
    await mintTo(
      provider.connection,
      provider.wallet.payer,
      new PublicKey(usdcMint),
      clientTokenAccount,
      mintAuthority,
      depositAmount
    );
  } else if (process.env.A402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT) {
    const sourceOwner = process.env.A402_NITRO_E2E_SOURCE_TOKEN_OWNER_WALLET
      ? loadKeypairFromFile(
          process.env.A402_NITRO_E2E_SOURCE_TOKEN_OWNER_WALLET
        )
      : provider.wallet.payer;
    await transfer(
      provider.connection,
      provider.wallet.payer,
      new PublicKey(process.env.A402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT),
      clientTokenAccount,
      sourceOwner,
      depositAmount
    );
  } else {
    throw new Error(
      "Demo needs test USDC funding. Set A402_USDC_MINT_AUTHORITY_WALLET or A402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT."
    );
  }

  logStep(3, "Agent pre-funds the private vault");
  const depositSig = await program.methods
    .deposit(new anchor.BN(depositAmount))
    .accountsPartial({
      client: client.publicKey,
      vaultConfig: new PublicKey(vaultConfig),
      clientTokenAccount,
      vaultTokenAccount: new PublicKey(vaultTokenAccount),
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .signers([client])
    .rpc();
  logKV("Agent", shortKey(client.publicKey.toBase58()));
  logKV("Deposit", formatUsdcAtomic(depositAmount));
  logKV("Deposit tx", depositSig);

  const depositedBalance = await waitForEndpoint(
    "client balance sync",
    async () => {
      const auth = buildClientRequestAuth(
        client,
        (issuedAt, expiresAt) =>
          `A402-CLIENT-BALANCE\n${client.publicKey.toBase58()}\n${issuedAt}\n${expiresAt}\n`
      );
      const response = await postJson(enclaveUrl, "/v1/balance", {
        client: client.publicKey.toBase58(),
        issuedAt: auth.issuedAt,
        expiresAt: auth.expiresAt,
        clientSig: auth.clientSig,
      });
      if (!response.ok) {
        return null;
      }
      const body = await response.json();
      return body.free === depositAmount ? body : null;
    },
    120,
    1000
  );
  logKV("Vault balance", `${formatUsdcAtomic(depositedBalance.free)} free`);

  logStep(4, "Agent buys from providers using private reservations");
  const settlements = [];
  for (let index = 0; index < providers.length; index += 1) {
    const demoProvider = providers[index];
    const built = buildPayment({
      attestation,
      client,
      enclaveUrl,
      provider: demoProvider,
      requestOrigin,
      network,
      usdcMint,
      vaultConfig,
      paymentAmount,
      nonce: index + 1,
    });
    const providerHeaders = {
      Authorization: `Bearer ${demoProvider.apiKey}`,
      "x-a402-provider-id": demoProvider.id,
    };

    const verifyBody = await postOrThrow(
      enclaveUrl,
      "/v1/verify",
      {
        paymentPayload: built.paymentPayload,
        paymentDetails: built.paymentDetails,
        requestContext: built.requestContext,
      },
      providerHeaders
    );
    const settleBody = await postOrThrow(
      enclaveUrl,
      "/v1/settle",
      {
        verificationId: verifyBody.verificationId,
        resultHash: sha256hex(`demo-subly-${demoProvider.id}`),
        statusCode: 200,
      },
      providerHeaders
    );
    settlements.push({ providerId: demoProvider.id, verifyBody, settleBody });

    logKV(
      demoProvider.id,
      `reserved ${formatUsdcAtomic(paymentAmount)}, settlement ${shortKey(
        settleBody.settlementId
      )}`
    );
  }

  logStep(5, "Waiting for batched on-chain provider payout");
  const providerTokenAfter = await waitForEndpoint(
    "automatic batch settlement",
    async () => {
      const balances = await getProviderBalances(
        provider.connection,
        providers
      );
      const allSettled = balances.every((balance, index) => {
        return balance >= providerTokenBefore[index] + BigInt(paymentAmount);
      });
      return allSettled ? balances : null;
    },
    batchWaitAttempts,
    batchWaitDelayMs
  );
  const settlementStatuses = await getSettlementStatuses(
    enclaveUrl,
    settlements,
    providers
  );

  const finalBalanceAuth = buildClientRequestAuth(
    client,
    (issuedAt, expiresAt) =>
      `A402-CLIENT-BALANCE\n${client.publicKey.toBase58()}\n${issuedAt}\n${expiresAt}\n`
  );
  const finalBalanceRes = await postJson(enclaveUrl, "/v1/balance", {
    client: client.publicKey.toBase58(),
    issuedAt: finalBalanceAuth.issuedAt,
    expiresAt: finalBalanceAuth.expiresAt,
    clientSig: finalBalanceAuth.clientSig,
  });
  const finalBalance = finalBalanceRes.ok ? await finalBalanceRes.json() : null;

  printHeader("Public chain observer view");
  logKV("Visible deposit", `agent token account -> vault (${depositSig})`);
  for (let index = 0; index < providers.length; index += 1) {
    logKV(
      `Provider ${index + 1} payout`,
      `${formatUsdcAtomic(providerTokenBefore[index])} -> ${formatUsdcAtomic(
        providerTokenAfter[index]
      )}`
    );
  }
  logKV(
    "Hidden from public chain",
    "request content, payment details, direct buyer->provider edge"
  );
  logKV(
    "Still visible",
    "vault deposits, provider payouts, timing/amount metadata"
  );

  console.log(
    JSON.stringify(
      {
        ok: true,
        mode: "subly-private-x402",
        client: client.publicKey.toBase58(),
        clientTokenAccount: clientTokenAccount.toBase58(),
        depositSig,
        attestation: {
          vaultConfig: attestation.vaultConfig,
          vaultSigner: attestation.vaultSigner,
          attestationPolicyHash: attestation.attestationPolicyHash,
          snapshotSeqno: attestation.snapshotSeqno,
        },
        settlements: settlements.map((settlement) => ({
          providerId: settlement.providerId,
          verificationId: settlement.verifyBody.verificationId,
          settlementId: settlement.settleBody.settlementId,
        })),
        settlementStatuses,
        providerTokenBefore: providerTokenBefore.map((value) =>
          value.toString()
        ),
        providerTokenAfter: providerTokenAfter.map((value) => value.toString()),
        finalBalance,
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
