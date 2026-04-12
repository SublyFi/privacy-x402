import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  createAccount,
  createMint,
  getAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import {
  ChildProcessWithoutNullStreams,
  spawn,
} from "child_process";
import { randomBytes, randomUUID, createHash } from "crypto";
import { once } from "events";
import { homedir } from "os";
import { existsSync, readFileSync, rmSync } from "fs";
import { expect } from "chai";
import BN from "bn.js";
import nacl from "tweetnacl";
import { Keypair, PublicKey } from "@solana/web3.js";

import { AuditTool } from "../sdk/src/audit";
import { A402Vault } from "../target/types/a402_vault";

const RPC_URL = process.env.ANCHOR_PROVIDER_URL || "http://127.0.0.1:8899";
const ENCLAVE_URL = "http://127.0.0.1:3100";

type RequestContext = {
  method: string;
  origin: string;
  pathAndQuery: string;
  bodySha256: string;
};

type PaymentPayload = {
  version: number;
  scheme: string;
  paymentId: string;
  client: string;
  vault: string;
  providerId: string;
  payTo: string;
  network: string;
  assetMint: string;
  amount: string;
  requestHash: string;
  paymentDetailsHash: string;
  expiresAt: string;
  nonce: string;
  clientSig: string;
};

function sha256Hex(input: string): string {
  const hash = createHash("sha256");
  hash.update(input);
  return hash.digest("hex");
}

function computeRequestHash(
  ctx: RequestContext,
  paymentDetailsHash: string
): string {
  const hash = createHash("sha256");
  hash.update("A402-SVM-V1-REQ\n");
  hash.update(ctx.method);
  hash.update("\n");
  hash.update(ctx.origin);
  hash.update("\n");
  hash.update(ctx.pathAndQuery);
  hash.update("\n");
  hash.update(ctx.bodySha256);
  hash.update("\n");
  hash.update(paymentDetailsHash);
  hash.update("\n");
  return hash.digest("hex");
}

function signPaymentPayload(
  client: Keypair,
  payload: Omit<PaymentPayload, "clientSig">
): string {
  const message =
    "A402-SVM-V1-AUTH\n" +
    `${payload.version}\n` +
    `${payload.scheme}\n` +
    `${payload.paymentId}\n` +
    `${payload.client}\n` +
    `${payload.vault}\n` +
    `${payload.providerId}\n` +
    `${payload.payTo}\n` +
    `${payload.network}\n` +
    `${payload.assetMint}\n` +
    `${payload.amount}\n` +
    `${payload.requestHash}\n` +
    `${payload.paymentDetailsHash}\n` +
    `${payload.expiresAt}\n` +
    `${payload.nonce}\n`;

  return Buffer.from(
    nacl.sign.detached(Buffer.from(message), client.secretKey)
  ).toString("base64");
}

async function postJson(path: string, body: unknown) {
  return fetch(`${ENCLAVE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function waitForAttestation(maxAttempts = 120) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const response = await fetch(`${ENCLAVE_URL}/v1/attestation`);
      if (response.ok) {
        return response.json();
      }
    } catch (_error) {
      // Server not ready yet.
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error("Timed out waiting for enclave attestation endpoint");
}

async function waitForClientBalance(
  client: PublicKey,
  expectedFree: number,
  maxAttempts = 90
) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const response = await postJson("/v1/balance", { client: client.toBase58() });
    if (response.ok) {
      const body = await response.json();
      if (body.free === expectedFree) {
        return body;
      }
    }

    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  throw new Error(
    `Timed out waiting for enclave balance ${expectedFree} for ${client.toBase58()}`
  );
}

function loadWallet(): anchor.Wallet {
  const walletPath =
    process.env.ANCHOR_WALLET || `${homedir()}/.config/solana/id.json`;
  const secretKey = Uint8Array.from(
    JSON.parse(readFileSync(walletPath, "utf8")) as number[]
  );

  return new anchor.Wallet(Keypair.fromSecretKey(secretKey));
}

describe("enclave_surfpool_e2e", function () {
  this.timeout(180_000);

  const provider = new anchor.AnchorProvider(
    new anchor.web3.Connection(RPC_URL, {
      commitment: "confirmed",
    }),
    loadWallet(),
    {
      commitment: "confirmed",
      preflightCommitment: "confirmed",
    }
  );
  anchor.setProvider(provider);

  const idl = JSON.parse(
    readFileSync("target/idl/a402_vault.json", "utf8")
  ) as A402Vault;
  const program = new Program<A402Vault>(idl as any, provider);
  const governance = provider.wallet as anchor.Wallet;

  let enclaveProcess: ChildProcessWithoutNullStreams | undefined;
  let enclaveLogs = "";
  let walPath = "";

  after(async () => {
    if (enclaveProcess && !enclaveProcess.killed) {
      enclaveProcess.kill("SIGINT");
      await once(enclaveProcess, "exit").catch(() => undefined);
    }
    if (walPath && existsSync(walPath)) {
      rmSync(walPath, { force: true });
    }
  });

  it("runs verify -> settle -> on-chain batch submit on surfpool and decrypts the audit record", async () => {
    try {
      await provider.connection.getVersion();

      const programInfo = await provider.connection.getAccountInfo(program.programId);
      if (!programInfo) {
        throw new Error(
          `Program ${program.programId.toBase58()} is not deployed. Run 'NO_DNA=1 anchor deploy --provider.cluster localnet' first.`
        );
      }

      const vaultId = new BN(Date.now());
      const paymentAmount = 600_000;
      const depositAmount = 2_000_000;
      const auditorMasterSecret = new Uint8Array(32);
      const attestationPolicyHash = new Array(32).fill(0);
      const auditorMasterPubkey = new Array(32).fill(0);

      const enclaveSignerSeed = randomBytes(32);
      const enclaveSigner = Keypair.fromSeed(enclaveSignerSeed);

      const usdcMint = await createMint(
        provider.connection,
        (governance as any).payer,
        governance.publicKey,
        null,
        6
      );

      const [vaultConfigPda] = PublicKey.findProgramAddressSync(
        [
          Buffer.from("vault_config"),
          governance.publicKey.toBuffer(),
          vaultId.toArrayLike(Buffer, "le", 8),
        ],
        program.programId
      );
      const [vaultTokenAccountPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("vault_token"), vaultConfigPda.toBuffer()],
        program.programId
      );

      walPath = `data/wal-surfpool-e2e-${randomUUID()}.jsonl`;
      enclaveLogs = "";
      enclaveProcess = spawn("cargo", ["run", "-p", "a402-enclave"], {
        cwd: process.cwd(),
        env: {
          ...process.env,
          A402_VAULT_SIGNER_SECRET_KEY_B64:
            enclaveSignerSeed.toString("base64"),
          A402_PROGRAM_ID: program.programId.toBase58(),
          A402_VAULT_CONFIG: vaultConfigPda.toBase58(),
          A402_VAULT_TOKEN_ACCOUNT: vaultTokenAccountPda.toBase58(),
          A402_USDC_MINT: usdcMint.toBase58(),
          A402_SOLANA_RPC_URL: RPC_URL,
          A402_SOLANA_WS_URL: "ws://127.0.0.1:8900",
          A402_WAL_PATH: walPath,
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      enclaveProcess.stdout.on("data", (chunk) => {
        enclaveLogs += chunk.toString();
      });
      enclaveProcess.stderr.on("data", (chunk) => {
        enclaveLogs += chunk.toString();
      });

      const attestation = await waitForAttestation();
      expect(attestation.vaultConfig).to.equal(vaultConfigPda.toBase58());
      expect(attestation.vaultSigner).to.equal(enclaveSigner.publicKey.toBase58());

      const signerAirdrop = await provider.connection.requestAirdrop(
        enclaveSigner.publicKey,
        2 * anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(signerAirdrop, "confirmed");

      await program.methods
        .initializeVault(
          vaultId,
          enclaveSigner.publicKey,
          auditorMasterPubkey,
          attestationPolicyHash
        )
        .accounts({
          governance: governance.publicKey,
          vaultConfig: vaultConfigPda,
          usdcMint,
          vaultTokenAccount: vaultTokenAccountPda,
          systemProgram: anchor.web3.SystemProgram.programId,
          tokenProgram: TOKEN_PROGRAM_ID,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();

      const client = Keypair.generate();
      const clientAirdrop = await provider.connection.requestAirdrop(
        client.publicKey,
        anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(clientAirdrop, "confirmed");

      const clientTokenAccount = await createAccount(
        provider.connection,
        client,
        usdcMint,
        client.publicKey
      );
      await mintTo(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        clientTokenAccount,
        governance.publicKey,
        depositAmount
      );

      await program.methods
        .deposit(new BN(depositAmount))
        .accounts({
          client: client.publicKey,
          vaultConfig: vaultConfigPda,
          clientTokenAccount,
          vaultTokenAccount: vaultTokenAccountPda,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([client])
        .rpc();

      const providerOwner = Keypair.generate();
      const providerOwnerAirdrop = await provider.connection.requestAirdrop(
        providerOwner.publicKey,
        anchor.web3.LAMPORTS_PER_SOL
      );
      await provider.connection.confirmTransaction(providerOwnerAirdrop, "confirmed");

      const providerTokenAccount = await createAccount(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        providerOwner.publicKey
      );

      const providerId = `prov_${randomUUID()}`;
      const registerRes = await postJson("/v1/provider/register", {
        providerId,
        displayName: "Surfpool E2E Provider",
        settlementTokenAccount: providerTokenAccount.toBase58(),
        network: "solana:localnet",
        assetMint: usdcMint.toBase58(),
        allowedOrigins: ["http://localhost"],
        authMode: "none",
        apiKeyHash: "00".repeat(32),
      });
      expect(registerRes.status).to.equal(200);

      const syncedBalance = await waitForClientBalance(
        client.publicKey,
        depositAmount
      );
      expect(syncedBalance.totalDeposited).to.equal(depositAmount);

      const requestContext: RequestContext = {
        method: "POST",
        origin: "http://localhost",
        pathAndQuery: "/surfpool-e2e",
        bodySha256: sha256Hex(JSON.stringify({ ok: true })),
      };
      const paymentDetailsHash = sha256Hex("surfpool-e2e-payment");
      const requestHash = computeRequestHash(requestContext, paymentDetailsHash);
      const unsignedPayload: Omit<PaymentPayload, "clientSig"> = {
        version: 1,
        scheme: "a402-svm-v1",
        paymentId: `pay_${randomUUID()}`,
        client: client.publicKey.toBase58(),
        vault: vaultConfigPda.toBase58(),
        providerId,
        payTo: providerTokenAccount.toBase58(),
        network: "solana:localnet",
        assetMint: usdcMint.toBase58(),
        amount: paymentAmount.toString(),
        requestHash,
        paymentDetailsHash,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        nonce: "1",
      };
      const paymentPayload: PaymentPayload = {
        ...unsignedPayload,
        clientSig: signPaymentPayload(client, unsignedPayload),
      };

      const verifyRes = await postJson("/v1/verify", {
        paymentPayload,
        requestContext,
      });
      expect(verifyRes.status).to.equal(200);
      const verifyBody = await verifyRes.json();
      expect(verifyBody.ok).to.equal(true);

      const settleRes = await postJson("/v1/settle", {
        verificationId: verifyBody.verificationId,
        resultHash: "ab".repeat(32),
        statusCode: 200,
      });
      expect(settleRes.status).to.equal(200);
      const settleBody = await settleRes.json();
      expect(settleBody.ok).to.equal(true);

      const fireBatchRes = await postJson("/v1/admin/fire-batch", {});
      expect(fireBatchRes.status).to.equal(200);
      const fireBatchBody = await fireBatchRes.json();
      expect(fireBatchBody.ok).to.equal(true);
      expect(fireBatchBody.submitted).to.equal(true);
      expect(fireBatchBody.batchId).to.be.a("number");
      expect(fireBatchBody.settlementCount).to.equal(1);
      expect(fireBatchBody.txSignatures).to.have.length(1);

      const providerAccount = await getAccount(provider.connection, providerTokenAccount);
      expect(Number(providerAccount.amount)).to.equal(paymentAmount);

      const vault = await program.account.vaultConfig.fetch(vaultConfigPda);
      expect(vault.lifetimeDeposited.toNumber()).to.equal(depositAmount);
      expect(vault.lifetimeSettled.toNumber()).to.equal(paymentAmount);

      const auditTool = new AuditTool(auditorMasterSecret);
      const decryptedRecords = await auditTool.decryptForProvider(
        vaultConfigPda,
        providerTokenAccount,
        provider.connection,
        program.programId
      );
      const matchingRecord = decryptedRecords.find(
        (record) =>
          record.sender.equals(client.publicKey) &&
          record.amount === paymentAmount
      );

      expect(matchingRecord, enclaveLogs).to.not.equal(undefined);
    } catch (error) {
      throw new Error(`${String(error)}\n\nEnclave logs:\n${enclaveLogs}`);
    }
  });
});
