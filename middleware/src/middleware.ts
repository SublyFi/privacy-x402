import { createHash } from "crypto";
import type { Request, Response, NextFunction } from "express";
import {
  A402MiddlewareOptions,
  A402ProviderConfig,
  A402Request,
} from "./types";

/**
 * Express middleware implementing the a402-svm-v1 payment protocol.
 *
 * Flow:
 * 1. If no PAYMENT-SIGNATURE header → return 402 with payment details
 * 2. If PAYMENT-SIGNATURE present → verify with facilitator, execute handler, settle
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

    if (!paymentSig) {
      // Return 402 Payment Required
      return send402(res, config, price);
    }

    // Decode and verify payment
    try {
      const payloadJson = Buffer.from(paymentSig, "base64url").toString(
        "utf-8"
      );
      const payload = JSON.parse(payloadJson);

      // Build request context for facilitator
      const bodySha256 = createHash("sha256")
        .update(req.body ? JSON.stringify(req.body) : "")
        .digest("hex");

      const origin = `${req.protocol}://${req.get("host")}`;

      const requestContext = {
        method: req.method.toUpperCase(),
        origin,
        pathAndQuery: req.originalUrl,
        bodySha256,
      };

      // Call facilitator /verify
      const verifyRes = await callFacilitator(
        `${config.facilitatorUrl}/v1/verify`,
        {
          paymentPayload: payload,
          requestContext,
        },
        config.apiKey
      );

      if (!verifyRes.ok) {
        return res.status(402).json({
          error: "payment_verification_failed",
          message: verifyRes.message || "Payment verification failed",
        });
      }

      // Attach payment context to request
      req.a402 = {
        verificationId: verifyRes.verificationId,
        paymentId: payload.paymentId,
        amount: payload.amount,
        providerId: payload.providerId,
      };

      // Capture the response to settle after handler executes
      const originalEnd = res.end;
      const originalJson = res.json;
      let responseBody: any;
      let responseStatus: number;

      res.json = function (this: Response, body: any) {
        responseBody = body;
        responseStatus = res.statusCode;
        return originalJson.call(this, body);
      };

      const capturedEnd = originalEnd;
      res.end = ((...args: any[]) => {
        responseStatus = res.statusCode;

        // Settle payment asynchronously after response
        settlePayment(config, verifyRes.verificationId, responseStatus).catch(
          (err) => {
            console.error("Settlement failed:", err);
          }
        );

        return (capturedEnd as any).apply(res, args);
      }) as any;

      // Continue to route handler
      next();
    } catch (err: any) {
      return res.status(400).json({
        error: "invalid_payment_signature",
        message: err.message,
      });
    }
  };
}

/** Send 402 Payment Required response */
function send402(
  res: Response,
  config: A402ProviderConfig,
  amount: string
): void {
  const paymentDetailsId = `paydet_${crypto.randomUUID()}`;

  res.status(402).json({
    accepts: [
      {
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
        paymentDetailsId,
        verifyWindowSec: 60,
        maxSettlementDelaySec: 900,
        privacyMode: "vault-batched-v1",
      },
    ],
  });
}

/** Call facilitator API */
async function callFacilitator(
  url: string,
  body: any,
  apiKey: string
): Promise<any> {
  const res = await globalThis.fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });

  return res.json();
}

/** Settle payment with facilitator */
async function settlePayment(
  config: A402ProviderConfig,
  verificationId: string,
  statusCode: number
): Promise<void> {
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
    config.apiKey
  );

  if (!res.ok) {
    throw new Error(`Settlement failed: ${res.message}`);
  }
}
