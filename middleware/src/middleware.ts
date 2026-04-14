import { createHash } from "crypto";
import type { Request, Response, NextFunction } from "express";
import {
  A402MiddlewareOptions,
  A402ProviderConfig,
  A402Request,
  SettlementStatusResponse,
} from "./types";
import { postFacilitatorJson } from "./facilitator";

/**
 * In-memory execution cache for the Provider Single-Execution Rule (§8.4).
 *
 * Key: verificationId
 * Value: { status, statusCode, body, paymentResponse }
 */
interface ExecutionEntry {
  status: "executing" | "served_success" | "served_error";
  statusCode?: number;
  body?: any;
  paymentResponse?: string;
  /** Waiters blocked on an in-flight execution */
  waiters: Array<{
    resolve: (entry: ExecutionEntry) => void;
  }>;
}

const executionCache = new Map<string, ExecutionEntry>();

/**
 * Express middleware implementing the a402-svm-v1 payment protocol.
 *
 * Flow (§4.2, §8):
 * 1. If no PAYMENT-SIGNATURE header → return 402 with payment details
 * 2. If PAYMENT-SIGNATURE present → verify → execute → settle → PAYMENT-RESPONSE → return
 */
export function a402Middleware(options: A402MiddlewareOptions) {
  const { config, pricing } = options;

  return async (req: A402Request, res: Response, next: NextFunction) => {
    // Check if payment is required
    const price = pricing(req);
    if (price === null) {
      return next();
    }

    const paymentSig = req.headers["payment-signature"] as string | undefined;
    const requestContext = buildRequestContext(req);

    if (!paymentSig) {
      // Return 402 Payment Required
      return send402(res, config, price, requestContext);
    }

    // Decode and verify payment
    try {
      const payloadJson = Buffer.from(paymentSig, "base64url").toString(
        "utf-8"
      );
      const payload = JSON.parse(payloadJson);

      // Build paymentDetails from config for this request (§8.2 requirement)
      const paymentDetails = buildPaymentDetails(config, price, requestContext);

      // Call facilitator /verify (C4: include paymentDetails)
      const verifyRes = await callFacilitator(
        `${config.facilitatorUrl}/v1/verify`,
        {
          paymentPayload: payload,
          paymentDetails,
          requestContext,
        },
        config
      );

      if (!verifyRes.ok) {
        return res.status(402).json({
          error: "payment_verification_failed",
          message: verifyRes.message || "Payment verification failed",
        });
      }

      const verificationId: string = verifyRes.verificationId;

      // C3: Single-Execution Rule (§8.4)
      const existing = executionCache.get(verificationId);
      if (existing) {
        if (existing.status === "executing") {
          // Wait for in-flight execution to complete
          const completed = await new Promise<ExecutionEntry>((resolve) => {
            existing.waiters.push({ resolve });
          });
          if (completed.paymentResponse) {
            res.setHeader("payment-response", completed.paymentResponse);
          }
          return res.status(completed.statusCode ?? 200).json(completed.body);
        }
        // Already served — return cached result (idempotent replay)
        if (existing.paymentResponse) {
          res.setHeader("payment-response", existing.paymentResponse);
        }
        return res.status(existing.statusCode ?? 200).json(existing.body);
      }

      // Mark as executing
      const entry: ExecutionEntry = { status: "executing", waiters: [] };
      executionCache.set(verificationId, entry);

      // Attach payment context to request
      req.a402 = {
        verificationId,
        paymentId: payload.paymentId,
        amount: payload.amount,
        providerId: payload.providerId,
      };

      // Capture the response body from the handler
      const originalJson = res.json;
      let capturedBody: any;
      let capturedStatus: number;

      res.json = function (this: Response, body: any) {
        capturedBody = body;
        capturedStatus = res.statusCode;
        // Don't send yet — we settle first
        return this;
      };

      // Execute handler via next(), then settle synchronously before responding
      await new Promise<void>((resolve, reject) => {
        const originalEnd = res.end;
        // Intercept end() to prevent premature send
        res.end = ((..._args: any[]) => {
          capturedStatus = capturedStatus ?? res.statusCode;
          resolve();
          return res;
        }) as any;

        // Run route handler
        next();

        // If handler calls res.json() it will set capturedBody and call our
        // patched end() via Express internals. For handlers that call next()
        // or don't respond, we need a timeout fallback.
        setTimeout(() => resolve(), 30000);
      });

      // C2: Settle BEFORE returning response (§8.3 WAL durability)
      let settleResult: any = null;
      try {
        settleResult = await settlePayment(
          config,
          verificationId,
          capturedStatus ?? 200
        );
      } catch (err: any) {
        console.error("Settlement failed:", err);
      }

      // C1: Build PAYMENT-RESPONSE header (§8.6)
      const paymentResponse = JSON.stringify({
        scheme: "a402-svm-v1",
        paymentId: payload.paymentId,
        verificationId,
        settlementId: settleResult?.settlementId ?? null,
        batchId: settleResult?.batchId ?? null,
        txSignature: null,
        participantReceipt: settleResult?.participantReceipt ?? null,
      });

      res.setHeader("payment-response", paymentResponse);

      // Update execution cache (C3)
      entry.status =
        (capturedStatus ?? 200) < 400 ? "served_success" : "served_error";
      entry.statusCode = capturedStatus ?? 200;
      entry.body = capturedBody;
      entry.paymentResponse = paymentResponse;

      // Notify waiters
      for (const waiter of entry.waiters) {
        waiter.resolve(entry);
      }
      entry.waiters = [];

      // Now send the actual response
      return originalJson.call(res, capturedBody);
    } catch (err: any) {
      return res.status(400).json({
        error: "invalid_payment_signature",
        message: err.message,
      });
    }
  };
}

/**
 * Express verify callback that preserves the exact request body bytes for
 * A402 request binding. Use with express.json({ verify: captureA402RawBody }).
 */
export function captureA402RawBody(
  req: Request,
  _res: Response,
  buf: Buffer
): void {
  (req as A402Request).rawBody = Buffer.from(buf);
}

function getRawRequestBody(req: A402Request): Buffer | string {
  if (req.rawBody !== undefined) {
    return req.rawBody;
  }
  if (typeof req.body === "string" || Buffer.isBuffer(req.body)) {
    return req.body;
  }
  if (req.body === undefined || req.body === null) {
    return "";
  }
  return JSON.stringify(req.body);
}

function buildRequestContext(req: Request): {
  method: string;
  origin: string;
  pathAndQuery: string;
  bodySha256: string;
} {
  const body = getRawRequestBody(req as A402Request);

  return {
    method: req.method.toUpperCase(),
    origin: `${req.protocol}://${req.get("host")}`,
    pathAndQuery: req.originalUrl,
    bodySha256: createHash("sha256").update(body).digest("hex"),
  };
}

function buildPaymentDetailsId(
  config: A402ProviderConfig,
  amount: string,
  requestContext: {
    method: string;
    origin: string;
    pathAndQuery: string;
    bodySha256: string;
  }
): string {
  const hash = createHash("sha256")
    .update("A402-SVM-V1-PAYDET\n")
    .update(config.providerId)
    .update("\n")
    .update(config.payTo)
    .update("\n")
    .update(config.network)
    .update("\n")
    .update(config.assetMint)
    .update("\n")
    .update(config.vaultConfig)
    .update("\n")
    .update(amount)
    .update("\n")
    .update(requestContext.method)
    .update("\n")
    .update(requestContext.origin)
    .update("\n")
    .update(requestContext.pathAndQuery)
    .update("\n")
    .update(requestContext.bodySha256)
    .update("\n")
    .digest("hex");

  return `paydet_${hash.slice(0, 32)}`;
}

/** Build payment details object (§5) */
function buildPaymentDetails(
  config: A402ProviderConfig,
  amount: string,
  requestContext: {
    method: string;
    origin: string;
    pathAndQuery: string;
    bodySha256: string;
  }
): Record<string, unknown> {
  return {
    scheme: "a402-svm-v1",
    network: config.network,
    amount,
    asset: {
      kind: "spl-token",
      mint: config.assetMint,
      decimals: config.assetDecimals,
      symbol: config.assetSymbol,
    },
    payTo: config.payTo,
    providerId: config.providerId,
    facilitatorUrl: config.facilitatorUrl,
    vault: {
      config: config.vaultConfig,
      signer: config.vaultSigner,
      attestationPolicyHash: config.attestationPolicyHash,
    },
    paymentDetailsId: buildPaymentDetailsId(config, amount, requestContext),
    verifyWindowSec: 60,
    maxSettlementDelaySec: 900,
    privacyMode: "vault-batched-v1",
  };
}

/** Send 402 Payment Required response */
function send402(
  res: Response,
  config: A402ProviderConfig,
  amount: string,
  requestContext: {
    method: string;
    origin: string;
    pathAndQuery: string;
    bodySha256: string;
  }
): void {
  res.status(402).json({
    accepts: [buildPaymentDetails(config, amount, requestContext)],
  });
}

/** Call facilitator API */
async function callFacilitator(
  url: string,
  body: any,
  config: A402ProviderConfig
): Promise<any> {
  return postFacilitatorJson(url, body, config);
}

export async function lookupSettlementStatus(
  config: A402ProviderConfig,
  settlementId: string
): Promise<SettlementStatusResponse> {
  return callFacilitator(
    `${config.facilitatorUrl}/v1/settlement/status`,
    { settlementId },
    config
  ) as Promise<SettlementStatusResponse>;
}

/** Settle payment with facilitator and return settle result (C2: synchronous) */
async function settlePayment(
  config: A402ProviderConfig,
  verificationId: string,
  statusCode: number
): Promise<{
  settlementId: string;
  batchId: number | null;
  participantReceipt: string;
}> {
  const resultHash = createHash("sha256")
    .update(`${verificationId}:${statusCode}`)
    .digest("hex");

  const res = await callFacilitator(
    `${config.facilitatorUrl}/v1/settle`,
    {
      verificationId,
      resultHash,
      statusCode,
    },
    config
  );

  if (!res.ok) {
    throw new Error(`Settlement failed: ${res.message}`);
  }

  return {
    settlementId: res.settlementId ?? "",
    batchId: res.batchId ?? null,
    participantReceipt: res.participantReceipt ?? "",
  };
}
