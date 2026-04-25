const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const {
  address,
  appendTransactionMessageInstructions,
  createSolanaRpc,
  createTransactionMessage,
  generateKeyPairSigner,
  getBase64EncodedWireTransaction,
  getSignatureFromTransaction,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
  writeKeyPairSigner,
  createKeyPairSignerFromBytes,
} = require("@solana/kit");
const { getTransferSolInstruction } = require("@solana-program/system");
const {
  TOKEN_PROGRAM_ADDRESS,
  fetchMint,
  fetchToken,
  findAssociatedTokenPda,
  getCreateAssociatedTokenIdempotentInstructionAsync,
  getMintToInstruction,
  getTransferInstruction,
} = require("@solana-program/token");

const CONFIRMATION_ATTEMPTS = 60;
const CONFIRMATION_DELAY_MS = 1000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function rpcUrlFromEnv() {
  const rpcUrl =
    process.env.ANCHOR_PROVIDER_URL || process.env.SUBLY402_SOLANA_RPC_URL;
  if (!rpcUrl) {
    throw new Error(
      "ANCHOR_PROVIDER_URL or SUBLY402_SOLANA_RPC_URL is required"
    );
  }
  return rpcUrl;
}

function createDemoRpc() {
  return createSolanaRpc(rpcUrlFromEnv());
}

function readKeypairBytes(filePath) {
  return Uint8Array.from(JSON.parse(fs.readFileSync(filePath, "utf8")));
}

async function loadSignerFromFile(filePath) {
  const secretKeyBytes = readKeypairBytes(filePath);
  return {
    signer: await createKeyPairSignerFromBytes(secretKeyBytes, true),
    secretKeyBytes,
  };
}

async function loadFeePayerSigner() {
  const walletPath = process.env.ANCHOR_WALLET;
  if (!walletPath) {
    throw new Error("ANCHOR_WALLET is required");
  }
  return loadSignerFromFile(walletPath);
}

async function createDemoSigner() {
  const signer = await generateKeyPairSigner(true);
  const tmpPath = path.join(
    os.tmpdir(),
    `subly402-demo-${process.pid}-${crypto.randomUUID()}.json`
  );
  await writeKeyPairSigner(signer, tmpPath);
  const secretKeyBytes = readKeypairBytes(tmpPath);
  fs.rmSync(tmpPath, { force: true });
  return { signer, secretKeyBytes };
}

function optionAddressValue(option) {
  if (!option || option.__option === "None") {
    return null;
  }
  if (option.__option === "Some") {
    return option.value;
  }
  return option;
}

async function loadMintAuthoritySigner(rpc, mintAddress, fallbackSigner) {
  const mint = await fetchMint(rpc, address(mintAddress));
  const mintAuthority = optionAddressValue(mint.data.mintAuthority);
  if (!mintAuthority) {
    return null;
  }

  const walletPath = process.env.SUBLY402_USDC_MINT_AUTHORITY_WALLET;
  if (walletPath) {
    const loaded = await loadSignerFromFile(walletPath);
    if (loaded.signer.address !== mintAuthority) {
      throw new Error(
        `SUBLY402_USDC_MINT_AUTHORITY_WALLET public key ${loaded.signer.address} does not match mint authority ${mintAuthority}`
      );
    }
    return loaded.signer;
  }

  if (fallbackSigner && fallbackSigner.address === mintAuthority) {
    return fallbackSigner;
  }
  return null;
}

async function waitForSignature(rpc, signature) {
  for (let attempt = 0; attempt < CONFIRMATION_ATTEMPTS; attempt += 1) {
    const response = await rpc.getSignatureStatuses([signature]).send();
    const [status] = Array.isArray(response) ? response : response.value;
    if (status?.err) {
      throw new Error(
        `transaction ${signature} failed: ${JSON.stringify(status.err)}`
      );
    }
    if (
      status?.confirmationStatus === "confirmed" ||
      status?.confirmationStatus === "finalized"
    ) {
      return status;
    }
    await sleep(CONFIRMATION_DELAY_MS);
  }
  throw new Error(`timed out waiting for transaction ${signature}`);
}

async function sendKitInstructions(rpc, feePayer, instructions) {
  const latestBlockhash = await rpc
    .getLatestBlockhash({ commitment: "confirmed" })
    .send();
  const transactionMessage = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayerSigner(feePayer, tx),
    (tx) =>
      setTransactionMessageLifetimeUsingBlockhash(latestBlockhash.value, tx),
    (tx) => appendTransactionMessageInstructions(instructions, tx)
  );
  const signedTransaction = await signTransactionMessageWithSigners(
    transactionMessage
  );
  const signature = await rpc
    .sendTransaction(getBase64EncodedWireTransaction(signedTransaction), {
      encoding: "base64",
      preflightCommitment: "confirmed",
    })
    .send();
  await waitForSignature(rpc, signature);
  return signature || getSignatureFromTransaction(signedTransaction);
}

async function fundAddressWithSol(rpc, feePayer, recipient, lamports) {
  return sendKitInstructions(rpc, feePayer, [
    getTransferSolInstruction({
      source: feePayer,
      destination: address(recipient),
      amount: BigInt(lamports),
    }),
  ]);
}

async function createAssociatedTokenAccount(rpc, feePayer, owner, mint) {
  const ownerAddress = address(owner);
  const mintAddress = address(mint);
  const [ata] = await findAssociatedTokenPda({
    mint: mintAddress,
    owner: ownerAddress,
    tokenProgram: TOKEN_PROGRAM_ADDRESS,
  });
  const createAtaIx = await getCreateAssociatedTokenIdempotentInstructionAsync({
    payer: feePayer,
    owner: ownerAddress,
    mint: mintAddress,
  });
  await sendKitInstructions(rpc, feePayer, [createAtaIx]);
  return ata;
}

async function mintTokens(
  rpc,
  feePayer,
  mint,
  destination,
  mintAuthority,
  amount
) {
  return sendKitInstructions(rpc, feePayer, [
    getMintToInstruction({
      mint: address(mint),
      token: address(destination),
      mintAuthority,
      amount: BigInt(amount),
    }),
  ]);
}

async function transferTokens(
  rpc,
  feePayer,
  source,
  destination,
  authority,
  amount
) {
  return sendKitInstructions(rpc, feePayer, [
    getTransferInstruction({
      source: address(source),
      destination: address(destination),
      authority,
      amount: BigInt(amount),
    }),
  ]);
}

async function fetchTokenAmount(rpc, tokenAccount) {
  const account = await fetchToken(rpc, address(tokenAccount));
  return BigInt(account.data.amount.toString());
}

async function fetchTokenOwner(rpc, tokenAccount) {
  const account = await fetchToken(rpc, address(tokenAccount));
  return account.data.owner;
}

module.exports = {
  createAssociatedTokenAccount,
  createDemoRpc,
  createDemoSigner,
  fetchTokenAmount,
  fetchTokenOwner,
  fundAddressWithSol,
  loadFeePayerSigner,
  loadMintAuthoritySigner,
  loadSignerFromFile,
  mintTokens,
  rpcUrlFromEnv,
  sendKitInstructions,
  transferTokens,
};
