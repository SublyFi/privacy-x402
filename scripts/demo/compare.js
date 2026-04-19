#!/usr/bin/env node

const { printHeader, logKV } = require("./common");

printHeader("Demo narrative: direct x402-style vs Subly privacy-first x402");

console.log("[Direct x402-style baseline]");
logKV("Agent action", "Calls a paid API and settles directly to the provider");
logKV("Public chain view", "buyer token account -> provider token account");
logKV("What leaks", "provider, amount, timing, and a direct payment edge");
console.log("");

console.log("[Subly privacy-first x402]");
logKV(
  "Agent action",
  "Uses the same paid-API UX, but pays through a private vault"
);
logKV(
  "Public chain view",
  "buyer deposit -> vault, then vault -> provider batch payout"
);
logKV(
  "What is hidden",
  "request content, payment details, and direct buyer-provider edge"
);
logKV(
  "What remains visible",
  "vault deposits, provider payouts, timing/amount metadata"
);
console.log("");

console.log("Suggested voiceover:");
console.log(
  "x402 lets AI agents pay APIs. Subly keeps that UX, but removes the direct on-chain payment edge between the agent and provider by routing settlement through a private vault and batched payout."
);
console.log("");

console.log("Commands for recording:");
console.log("  A402_DEMO_CONFIRM=1 yarn demo:x402-direct");
console.log("  A402_DEMO_CONFIRM=1 yarn demo:subly-private");
