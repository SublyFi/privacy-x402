#!/usr/bin/env node

const { printHeader, logKV } = require("./common");

const appCode = String.raw`import express from "express";
import { paidAgentRoute } from "./payment";

const app = express();

app.post(
  "/agent/research",
  paidAgentRoute({
    facilitatorUrl: process.env.PAYMENT_FACILITATOR_URL,
    providerId: process.env.PROVIDER_ID,
    providerApiKey: process.env.PROVIDER_API_KEY,
    providerTokenAccount: process.env.PROVIDER_TOKEN_ACCOUNT,
    price: "1100000",
  }),
  async (req, res) => {
    res.json({ ok: true, summary: await runAgent(req.body) });
  }
);`;

const clientCode = String.raw`import { createPaidFetch } from "./payment-client";

const paidFetch = createPaidFetch({
  facilitatorUrl: process.env.PAYMENT_FACILITATOR_URL,
});

const response = await paidFetch("https://api.example.com/agent/research", {
  method: "POST",
  body: JSON.stringify({
    prompt: "Find suppliers for private product launch",
  }),
});`;

const envDiff = String.raw`# direct x402-style settlement
- PAYMENT_FACILITATOR_URL=https://direct-x402.example.com

# Subly privacy-first settlement
+ PAYMENT_FACILITATOR_URL=https://a402-devnet-nlb-3e6035bc92639ed3.elb.us-east-1.amazonaws.com`;

printHeader("App-level diff: direct x402-style -> Subly");

console.log("[Provider app code]");
console.log(appCode);
console.log("");

console.log("[AI agent client code]");
console.log(clientCode);
console.log("");

console.log("[Diff to show in the demo]");
console.log(envDiff);
console.log("");

logKV("What changed in app code", "only the payment facilitator URL");
logKV(
  "What Subly changes underneath",
  "vault deposit, private reservation, batched provider payout"
);
logKV(
  "What must stay honest",
  "vault and attestation values still exist, but live in generated env/config, not product code"
);
