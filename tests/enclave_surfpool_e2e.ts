import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  createAccount,
  createMint,
  getAccount,
  mintTo,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { ChildProcessWithoutNullStreams, spawn } from "child_process";
import { randomBytes, randomUUID, createHash } from "crypto";
import { once } from "events";
import { homedir } from "os";
import { existsSync, readFileSync, rmSync } from "fs";
import { expect } from "chai";
import BN from "bn.js";
import nacl from "tweetnacl";
import { Keypair, PublicKey } from "@solana/web3.js";

import { AuditTool } from "../sdk/src/audit";
import { computePaymentDetailsHash } from "../sdk/src/crypto";
import { decodeVerificationReceiptEnvelope } from "../sdk/src/receipt";
import { Subly402Vault } from "../target/types/subly402_vault";
import { buildTestProviderParticipantAttestation } from "./provider_attestation";
import {
  generateTlsFixture,
  requestJson,
  RequestTlsOptions,
  TestResponse,
  GeneratedTlsFixture,
} from "./live_transport";

const RPC_URL = process.env.ANCHOR_PROVIDER_URL || "http://127.0.0.1:8899";
const DEFAULT_ENCLAVE_URL = "http://127.0.0.1:3100";
const WATCHTOWER_URL = "http://127.0.0.1:3200";

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

type AttestationResponse = {
  vaultConfig: string;
  vaultSigner: string;
};

type BalanceResponse = {
  free: number;
  totalDeposited: number;
};

type VerifyResponse = {
  ok: boolean;
  verificationId: string;
  reservationId: string;
  verificationReceipt: string;
};

type SettleResponse = {
  ok: boolean;
  settlementId: string;
};

type FireBatchResponse = {
  ok: boolean;
  submitted: boolean;
  batchId: number;
  settlementCount: number;
  txSignatures: string[];
};

type SettlementStatusResponse = {
  ok: boolean;
  settlementId: string;
  verificationId: string;
  providerId: string;
  status: string;
  batchId: number | null;
  txSignature: string | null;
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
  hash.update("SUBLY402-SVM-V1-REQ\n");
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
    "SUBLY402-SVM-V1-AUTH\n" +
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

function signClientTextRequest(client: Keypair, message: string): string {
  return Buffer.from(
    nacl.sign.detached(Buffer.from(message), client.secretKey)
  ).toString("base64");
}

function buildClientRequestAuth(
  client: Keypair,
  buildMessage: (issuedAt: number, expiresAt: number) => string
) {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + 300;
  const clientSig = signClientTextRequest(
    client,
    buildMessage(issuedAt, expiresAt)
  );
  return { issuedAt, expiresAt, clientSig };
}

async function postJson(
  baseUrl: string,
  path: string,
  body: unknown,
  headers?: Record<string, string>,
  tls?: RequestTlsOptions
): Promise<TestResponse> {
  return requestJson(`${baseUrl}${path}`, {
    method: "POST",
    body,
    headers,
    tls,
  });
}

async function getJson(
  baseUrl: string,
  path: string,
  tls?: RequestTlsOptions
): Promise<TestResponse> {
  return requestJson(`${baseUrl}${path}`, {
    method: "GET",
    tls,
  });
}

async function readJson<T>(response: TestResponse): Promise<T> {
  return response.json<T>();
}

async function waitForAttestation(
  baseUrl: string,
  tls?: RequestTlsOptions,
  maxAttempts = 120
) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const response = await getJson(baseUrl, "/v1/attestation", tls);
      if (response.ok) {
        return readJson<AttestationResponse>(response);
      }
    } catch (_error) {
      // Server not ready yet.
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error("Timed out waiting for enclave attestation endpoint");
}

async function waitForWatchtower(maxAttempts = 120) {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const response = await fetch(`${WATCHTOWER_URL}/v1/status`);
      if (response.ok) {
        return;
      }
    } catch (_error) {
      // Server not ready yet.
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error("Timed out waiting for watchtower status endpoint");
}

async function waitForClientBalance(
  baseUrl: string,
  client: Keypair,
  expectedFree: number,
  tls?: RequestTlsOptions,
  maxAttempts = 90
): Promise<BalanceResponse> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const auth = buildClientRequestAuth(
      client,
      (issuedAt, expiresAt) =>
        `SUBLY402-CLIENT-BALANCE\n${client.publicKey.toBase58()}\n${issuedAt}\n${expiresAt}\n`
    );
    const response = await postJson(
      baseUrl,
      "/v1/balance",
      {
        client: client.publicKey.toBase58(),
        issuedAt: auth.issuedAt,
        expiresAt: auth.expiresAt,
        clientSig: auth.clientSig,
      },
      undefined,
      tls
    );
    if (response.ok) {
      const body = await readJson<BalanceResponse>(response);
      if (body.free === expectedFree) {
        return body;
      }
    }

    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  throw new Error(
    `Timed out waiting for enclave balance ${expectedFree} for ${client.publicKey.toBase58()}`
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
    readFileSync("target/idl/subly402_vault.json", "utf8")
  ) as Subly402Vault;
  const program = new Program<Subly402Vault>(idl as any, provider);
  const governance = provider.wallet as anchor.Wallet;

  let enclaveProcess: ChildProcessWithoutNullStreams | undefined;
  let watchtowerProcess: ChildProcessWithoutNullStreams | undefined;
  let enclaveLogs = "";
  let walPath = "";
  let watchtowerStorePath = "";
  let tlsFixture: GeneratedTlsFixture | undefined;

  async function terminateProcess(
    process: ChildProcessWithoutNullStreams | undefined
  ) {
    if (
      !process ||
      process.killed ||
      process.exitCode !== null ||
      process.signalCode !== null
    ) {
      return;
    }

    let exited = false;
    process.kill("SIGINT");
    await Promise.race([
      once(process, "exit")
        .then(() => {
          exited = true;
        })
        .catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, 5000)),
    ]);

    if (!exited) {
      process.kill("SIGKILL");
      if (process.exitCode === null && process.signalCode === null) {
        await Promise.race([
          once(process, "exit").catch(() => undefined),
          new Promise((resolve) => setTimeout(resolve, 5000)),
        ]);
      }
    }
  }

  async function stopLiveProcesses() {
    await terminateProcess(enclaveProcess);
    await terminateProcess(watchtowerProcess);
    if (walPath && existsSync(walPath)) {
      rmSync(walPath, { force: true });
    }
    if (watchtowerStorePath && existsSync(watchtowerStorePath)) {
      rmSync(watchtowerStorePath, { force: true });
    }
    if (tlsFixture) {
      tlsFixture.cleanup();
      tlsFixture = undefined;
    }
    enclaveProcess = undefined;
    watchtowerProcess = undefined;
    walPath = "";
    watchtowerStorePath = "";
  }

  afterEach(async () => {
    await stopLiveProcesses();
  });

  after(async () => {
    await stopLiveProcesses();
  });

  async function runSurfpoolFlow(options: {
    enclaveUrl: string;
    requestOrigin: string;
    authMode: "bearer" | "mtls";
    sharedTls?: RequestTlsOptions;
    providerTls?: RequestTlsOptions;
    enclaveExtraEnv?: Record<string, string>;
    mtlsFingerprintHex?: string;
  }) {
    try {
      await provider.connection.getVersion();

      const programInfo = await provider.connection.getAccountInfo(
        program.programId
      );
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
      watchtowerStorePath = `data/watchtower-surfpool-e2e-${randomUUID()}.json`;
      enclaveLogs = "";
      watchtowerProcess = spawn("cargo", ["run", "-p", "subly402-watchtower"], {
        cwd: process.cwd(),
        env: {
          ...process.env,
          SUBLY402_PROGRAM_ID: program.programId.toBase58(),
          SUBLY402_VAULT_CONFIG: vaultConfigPda.toBase58(),
          SUBLY402_SOLANA_RPC_URL: RPC_URL,
          SUBLY402_WATCHTOWER_STORE_PATH: watchtowerStorePath,
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      watchtowerProcess.stdout.on("data", (chunk) => {
        enclaveLogs += chunk.toString();
      });
      watchtowerProcess.stderr.on("data", (chunk) => {
        enclaveLogs += chunk.toString();
      });
      await waitForWatchtower();

      enclaveProcess = spawn("cargo", ["run", "-p", "subly402-enclave"], {
        cwd: process.cwd(),
        env: {
          ...process.env,
          SUBLY402_VAULT_SIGNER_SECRET_KEY_B64:
            enclaveSignerSeed.toString("base64"),
          SUBLY402_PROGRAM_ID: program.programId.toBase58(),
          SUBLY402_VAULT_CONFIG: vaultConfigPda.toBase58(),
          SUBLY402_VAULT_TOKEN_ACCOUNT: vaultTokenAccountPda.toBase58(),
          SUBLY402_USDC_MINT: usdcMint.toBase58(),
          SUBLY402_SOLANA_RPC_URL: RPC_URL,
          SUBLY402_SOLANA_WS_URL: "ws://127.0.0.1:8900",
          SUBLY402_WAL_PATH: walPath,
          SUBLY402_WATCHTOWER_URL: WATCHTOWER_URL,
          SUBLY402_ENABLE_PROVIDER_REGISTRATION_API: "1",
          SUBLY402_ENABLE_ADMIN_API: "1",
          ...(options.enclaveExtraEnv ?? {}),
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      enclaveProcess.stdout.on("data", (chunk) => {
        enclaveLogs += chunk.toString();
      });
      enclaveProcess.stderr.on("data", (chunk) => {
        enclaveLogs += chunk.toString();
      });

      const attestation = await waitForAttestation(
        options.enclaveUrl,
        options.sharedTls
      );
      expect(attestation.vaultConfig).to.equal(vaultConfigPda.toBase58());
      expect(attestation.vaultSigner).to.equal(
        enclaveSigner.publicKey.toBase58()
      );

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
        .accountsPartial({
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
        .accountsPartial({
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
      await provider.connection.confirmTransaction(
        providerOwnerAirdrop,
        "confirmed"
      );

      const providerTokenAccount = await createAccount(
        provider.connection,
        (governance as any).payer,
        usdcMint,
        providerOwner.publicKey
      );

      const providerId = `prov_${randomUUID()}`;
      const providerApiKey = `surfpool-provider-secret-${randomUUID()}`;
      const registerRes = await postJson(
        options.enclaveUrl,
        "/v1/provider/register",
        {
          providerId,
          displayName: "Surfpool E2E Provider",
          participantPubkey: providerOwner.publicKey.toBase58(),
          participantAttestation: buildTestProviderParticipantAttestation(
            providerId,
            providerOwner.publicKey.toBase58()
          ),
          settlementTokenAccount: providerTokenAccount.toBase58(),
          network: "solana:localnet",
          assetMint: usdcMint.toBase58(),
          allowedOrigins: [options.requestOrigin],
          authMode: options.authMode,
          apiKeyHash:
            options.authMode === "bearer" ? sha256Hex(providerApiKey) : "",
          mtlsCertFingerprint:
            options.authMode === "mtls"
              ? options.mtlsFingerprintHex
              : undefined,
        },
        undefined,
        options.sharedTls
      );
      expect(registerRes.status, await registerRes.text()).to.equal(200);

      const syncedBalance = await waitForClientBalance(
        options.enclaveUrl,
        client,
        depositAmount,
        options.sharedTls
      );
      expect(syncedBalance.totalDeposited).to.equal(depositAmount);

      const requestContext: RequestContext = {
        method: "POST",
        origin: options.requestOrigin,
        pathAndQuery: "/surfpool-e2e",
        bodySha256: sha256Hex(JSON.stringify({ ok: true })),
      };
      const paymentDetails = {
        scheme: "subly402-svm-v1",
        network: "solana:localnet",
        amount: paymentAmount.toString(),
        asset: {
          kind: "spl-token",
          mint: usdcMint.toBase58(),
          decimals: 6,
          symbol: "USDC",
        },
        payTo: providerTokenAccount.toBase58(),
        providerId,
        facilitatorUrl: options.enclaveUrl,
        vault: {
          config: vaultConfigPda.toBase58(),
          signer: enclaveSigner.publicKey.toBase58(),
          attestationPolicyHash: attestationPolicyHash
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join(""),
        },
        paymentDetailsId: `paydet_test_${providerId}`,
        verifyWindowSec: 60,
        maxSettlementDelaySec: 900,
        privacyMode: "vault-batched-v1",
      } as const;
      const paymentDetailsHash = computePaymentDetailsHash(paymentDetails);
      const requestHash = computeRequestHash(
        requestContext,
        paymentDetailsHash
      );
      const unsignedPayload: Omit<PaymentPayload, "clientSig"> = {
        version: 1,
        scheme: "subly402-svm-v1",
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

      const providerHeaders =
        options.authMode === "bearer"
          ? {
              Authorization: `Bearer ${providerApiKey}`,
              "x-subly402-provider-id": providerId,
            }
          : {
              "x-subly402-provider-id": providerId,
            };

      const verifyRes = await postJson(
        options.enclaveUrl,
        "/v1/verify",
        {
          paymentPayload,
          paymentDetails,
          requestContext,
        },
        providerHeaders,
        options.providerTls ?? options.sharedTls
      );
      expect(verifyRes.status, await verifyRes.text()).to.equal(200);
      const verifyBody = await readJson<VerifyResponse>(verifyRes);
      expect(verifyBody.ok).to.equal(true);
      const verificationReceipt = decodeVerificationReceiptEnvelope(
        verifyBody.verificationReceipt
      );
      expect(verificationReceipt.verificationId).to.equal(
        verifyBody.verificationId
      );
      expect(verificationReceipt.reservationId).to.equal(
        verifyBody.reservationId
      );
      expect(verificationReceipt.providerId).to.equal(providerId);
      expect(verificationReceipt.amount).to.equal(paymentAmount.toString());

      const settleRes = await postJson(
        options.enclaveUrl,
        "/v1/settle",
        {
          verificationId: verifyBody.verificationId,
          resultHash: "ab".repeat(32),
          statusCode: 200,
        },
        providerHeaders,
        options.providerTls ?? options.sharedTls
      );
      expect(settleRes.status, await settleRes.text()).to.equal(200);
      const settleBody = await readJson<SettleResponse>(settleRes);
      expect(settleBody.ok).to.equal(true);

      const fireBatchRes = await postJson(
        options.enclaveUrl,
        "/v1/admin/fire-batch",
        {},
        undefined,
        options.sharedTls
      );
      expect(fireBatchRes.status, await fireBatchRes.text()).to.equal(200);
      const fireBatchBody = await readJson<FireBatchResponse>(fireBatchRes);
      expect(fireBatchBody.ok).to.equal(true);
      expect(fireBatchBody.submitted).to.equal(true);
      expect(fireBatchBody.batchId).to.be.a("number");
      expect(fireBatchBody.settlementCount).to.equal(1);
      expect(fireBatchBody.txSignatures).to.have.length(1);

      const settlementStatusRes = await postJson(
        options.enclaveUrl,
        "/v1/settlement/status",
        {
          settlementId: settleBody.settlementId,
        },
        providerHeaders,
        options.providerTls ?? options.sharedTls
      );
      expect(
        settlementStatusRes.status,
        await settlementStatusRes.text()
      ).to.equal(200);
      const settlementStatusBody = await readJson<SettlementStatusResponse>(
        settlementStatusRes
      );
      expect(settlementStatusBody.ok).to.equal(true);
      expect(settlementStatusBody.settlementId).to.equal(
        settleBody.settlementId
      );
      expect(settlementStatusBody.verificationId).to.equal(
        verifyBody.verificationId
      );
      expect(settlementStatusBody.providerId).to.equal(providerId);
      expect(settlementStatusBody.status).to.equal("BatchedOnchain");
      expect(settlementStatusBody.batchId).to.equal(fireBatchBody.batchId);
      expect(settlementStatusBody.txSignature).to.equal(
        fireBatchBody.txSignatures[0]
      );

      const providerAccount = await getAccount(
        provider.connection,
        providerTokenAccount
      );
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
  }

  it("runs verify -> settle -> on-chain batch submit on surfpool and decrypts the audit record", async () => {
    await stopLiveProcesses();
    await runSurfpoolFlow({
      enclaveUrl: DEFAULT_ENCLAVE_URL,
      requestOrigin: "http://localhost",
      authMode: "bearer",
    });
  });

  it("runs the same surfpool flow over https + mtls", async () => {
    await stopLiveProcesses();
    tlsFixture = generateTlsFixture("subly402-surfpool-mtls");

    await runSurfpoolFlow({
      enclaveUrl: "https://127.0.0.1:3100",
      requestOrigin: "https://127.0.0.1",
      authMode: "mtls",
      sharedTls: {
        caPath: tlsFixture.caCertPath,
        serverName: "localhost",
      },
      providerTls: {
        caPath: tlsFixture.caCertPath,
        certPath: tlsFixture.clientCertPath,
        keyPath: tlsFixture.clientKeyPath,
        serverName: "localhost",
      },
      enclaveExtraEnv: {
        SUBLY402_ENCLAVE_TLS_CERT_PATH: tlsFixture.serverCertPath,
        SUBLY402_ENCLAVE_TLS_KEY_PATH: tlsFixture.serverKeyPath,
        SUBLY402_ENCLAVE_TLS_CLIENT_CA_PATH: tlsFixture.caCertPath,
      },
      mtlsFingerprintHex: tlsFixture.clientCertFingerprintHex,
    });
  });
});
