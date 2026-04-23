#!/usr/bin/env node

const crypto = require("crypto");
const { AccountRole, address } = require("@solana/kit");
const { TOKEN_PROGRAM_ADDRESS } = require("@solana-program/token");

const {
  assertFinalRoutes,
  buildClientRequestAuth,
  buildPayment,
  fetchJson,
  formatUsdcAtomic,
  loadDemoProviders,
  loadNitroEnv,
  logKV,
  logStep,
  postJson,
  postOrThrow,
  printHeader,
  readPositiveIntEnv,
  requireDemoConfirmation,
  requireEnv,
  selectDemoProviders,
  sha256hex,
  shortKey,
  waitForEndpoint,
} = require("./common");
const {
  DEMO_HTTP_METHOD,
  DEMO_ROUTE_PATH,
  buildDemoRequest,
  buildDemoResponse,
  requestSummary,
} = require("./scenario");
const {
  createAssociatedTokenAccount,
  createDemoRpc,
  createDemoSigner,
  fetchTokenAmount,
  fundAddressWithSol,
  loadFeePayerSigner,
  loadMintAuthoritySigner,
  loadSignerFromFile,
  mintTokens,
  rpcUrlFromEnv,
  sendKitInstructions,
  transferTokens,
} = require("./solana-kit");

const DEPOSIT_DISCRIMINATOR = crypto
  .createHash("sha256")
  .update("global:deposit")
  .digest()
  .subarray(0, 8);

function u64Le(value) {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(value));
  return buffer;
}

function buildDepositInstruction({
  programId,
  client,
  vaultConfig,
  clientTokenAccount,
  vaultTokenAccount,
  amount,
}) {
  return {
    programAddress: address(programId),
    accounts: [
      {
        address: client.address,
        role: AccountRole.WRITABLE_SIGNER,
        signer: client,
      },
      { address: address(vaultConfig), role: AccountRole.WRITABLE },
      { address: address(clientTokenAccount), role: AccountRole.WRITABLE },
      { address: address(vaultTokenAccount), role: AccountRole.WRITABLE },
      { address: TOKEN_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    ],
    data: Buffer.concat([DEPOSIT_DISCRIMINATOR, u64Le(amount)]),
  };
}

async function getProviderBalances(rpc, providers) {
  const balances = [];
  for (const provider of providers) {
    balances.push(await fetchTokenAmount(rpc, provider.tokenAccount));
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
        "x-subly402-provider-id": demoProvider.id,
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

  if (process.env.SUBLY402_NITRO_ALLOW_SELF_SIGNED_TLS !== "0") {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

  const enclaveUrl = requireEnv("SUBLY402_PUBLIC_ENCLAVE_URL").replace(
    /\/$/,
    ""
  );
  const programId = requireEnv("SUBLY402_PROGRAM_ID");
  const vaultConfig = requireEnv("SUBLY402_VAULT_CONFIG");
  const vaultTokenAccount = requireEnv("SUBLY402_VAULT_TOKEN_ACCOUNT");
  const usdcMint = requireEnv("SUBLY402_USDC_MINT");
  const expectedPolicyHash = requireEnv("SUBLY402_ATTESTATION_POLICY_HASH_HEX");
  const requestOrigin =
    process.env.SUBLY402_REQUEST_ORIGIN || "https://demo.subly.dev";
  const network = process.env.SUBLY402_NETWORK || "solana:devnet";
  const depositAmount = Number(
    readPositiveIntEnv(
      "SUBLY402_DEMO_DEPOSIT_AMOUNT",
      readPositiveIntEnv("SUBLY402_NITRO_E2E_DEPOSIT_AMOUNT", 3000000)
    )
  );
  const paymentAmount = Number(
    readPositiveIntEnv(
      "SUBLY402_DEMO_PAYMENT_AMOUNT",
      readPositiveIntEnv("SUBLY402_NITRO_E2E_PAYMENT_AMOUNT", 1100000)
    )
  );
  const clientSolLamports = Number(
    readPositiveIntEnv(
      "SUBLY402_DEMO_CLIENT_SOL_LAMPORTS",
      readPositiveIntEnv("SUBLY402_NITRO_E2E_CLIENT_SOL_LAMPORTS", 50000000)
    )
  );
  const batchWaitAttempts = readPositiveIntEnv(
    "SUBLY402_DEMO_BATCH_WAIT_ATTEMPTS",
    readPositiveIntEnv("SUBLY402_NITRO_E2E_BATCH_WAIT_ATTEMPTS", 72)
  );
  const batchWaitDelayMs = readPositiveIntEnv(
    "SUBLY402_DEMO_BATCH_WAIT_DELAY_MS",
    readPositiveIntEnv("SUBLY402_NITRO_E2E_BATCH_WAIT_DELAY_MS", 5000)
  );
  const providers = selectDemoProviders(loadDemoProviders());
  const requestBody = buildDemoRequest();

  if (depositAmount < paymentAmount * providers.length) {
    throw new Error("deposit amount must cover all provider payment amounts");
  }

  const plan = {
    mode: "subly-private-x402",
    cluster: rpcUrlFromEnv(),
    feePayerWallet: process.env.ANCHOR_WALLET || null,
    enclaveUrl,
    programId,
    vaultConfig,
    vaultTokenAccount,
    usdcMint,
    expectedPolicyHash,
    route: `${DEMO_HTTP_METHOD} ${DEMO_ROUTE_PATH}`,
    requestBody,
    depositAmount,
    paymentAmountPerProvider: paymentAmount,
    providers: providers.map(({ id, tokenAccount }) => ({ id, tokenAccount })),
    batching: providers.length > 1 ? "multi-provider" : "single-provider",
    batchWaitAttempts,
    batchWaitDelayMs,
  };
  requireDemoConfirmation(plan);

  const rpc = createDemoRpc();
  const { signer: feePayer } = await loadFeePayerSigner();
  const mintAuthority = await loadMintAuthoritySigner(rpc, usdcMint, feePayer);

  printHeader("Subly privacy-first x402: private vault + batched settlement");
  logStep(1, requestSummary());
  logKV("Payment path", "agent -> Subly vault -> provider payout");
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

  const providerTokenBefore = await getProviderBalances(rpc, providers);

  const { signer: client } = await createDemoSigner();
  const clientTokenAccount = await createAssociatedTokenAccount(
    rpc,
    feePayer,
    client.address,
    usdcMint
  );
  await fundAddressWithSol(rpc, feePayer, client.address, clientSolLamports);

  if (mintAuthority) {
    await mintTokens(
      rpc,
      feePayer,
      usdcMint,
      clientTokenAccount,
      mintAuthority,
      depositAmount
    );
  } else if (process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT) {
    const sourceOwner = process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_OWNER_WALLET
      ? (
          await loadSignerFromFile(
            process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_OWNER_WALLET
          )
        ).signer
      : feePayer;
    await transferTokens(
      rpc,
      feePayer,
      process.env.SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT,
      clientTokenAccount,
      sourceOwner,
      depositAmount
    );
  } else {
    throw new Error(
      "Demo needs test USDC funding. Set SUBLY402_USDC_MINT_AUTHORITY_WALLET or SUBLY402_NITRO_E2E_SOURCE_TOKEN_ACCOUNT."
    );
  }

  logStep(3, "Agent pre-funds the private vault");
  const depositSig = await sendKitInstructions(rpc, feePayer, [
    buildDepositInstruction({
      programId,
      client,
      vaultConfig,
      clientTokenAccount,
      vaultTokenAccount,
      amount: depositAmount,
    }),
  ]);
  logKV("Agent", shortKey(client.address));
  logKV("Deposit", formatUsdcAtomic(depositAmount));
  logKV("Deposit tx", depositSig);

  const depositedBalance = await waitForEndpoint(
    "client balance sync",
    async () => {
      const auth = await buildClientRequestAuth(
        client,
        (issuedAt, expiresAt) =>
          `SUBLY402-CLIENT-BALANCE\n${client.address}\n${issuedAt}\n${expiresAt}\n`
      );
      const response = await postJson(enclaveUrl, "/v1/balance", {
        client: client.address,
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
    const built = await buildPayment({
      attestation,
      clientSigner: client,
      enclaveUrl,
      provider: demoProvider,
      requestOrigin,
      network,
      usdcMint,
      vaultConfig,
      paymentAmount,
      nonce: index + 1,
      requestMethod: DEMO_HTTP_METHOD,
      routePath: DEMO_ROUTE_PATH,
      requestBody,
    });
    const providerHeaders = {
      Authorization: `Bearer ${demoProvider.apiKey}`,
      "x-subly402-provider-id": demoProvider.id,
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
    const providerResponse = buildDemoResponse({
      providerId: demoProvider.id,
      settlementMode: "subly-private-x402",
    });
    const settleBody = await postOrThrow(
      enclaveUrl,
      "/v1/settle",
      {
        verificationId: verifyBody.verificationId,
        resultHash: sha256hex(JSON.stringify(providerResponse)),
        statusCode: 200,
      },
      providerHeaders
    );
    settlements.push({
      providerId: demoProvider.id,
      verifyBody,
      settleBody,
      providerResponse,
    });

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
      const balances = await getProviderBalances(rpc, providers);
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
  const pendingStatuses = settlementStatuses.filter((settlement) => {
    const body = settlement.body;
    return (
      settlement.httpStatus !== 200 ||
      !body ||
      body.status !== "BatchedOnchain" ||
      !body.batchId ||
      !body.txSignature
    );
  });
  if (pendingStatuses.length > 0) {
    throw new Error(
      `settlement status did not reach BatchedOnchain: ${JSON.stringify(
        pendingStatuses,
        null,
        2
      )}`
    );
  }

  const finalBalanceAuth = await buildClientRequestAuth(
    client,
    (issuedAt, expiresAt) =>
      `SUBLY402-CLIENT-BALANCE\n${client.address}\n${issuedAt}\n${expiresAt}\n`
  );
  const finalBalanceRes = await postJson(enclaveUrl, "/v1/balance", {
    client: client.address,
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
        client: client.address,
        clientTokenAccount,
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
          response: settlement.providerResponse,
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
