#!/usr/bin/env node

const { printHeader, logKV } = require("./common");

printHeader("Demo narrative: official x402 vs Subly privacy-first x402");

logKV("Shared demo request", 'AI agent calls paid "GET /weather" API');
logKV("Swap point", "payment client / settlement path only");
console.log("");

console.log("[Official x402 direct]");
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
  'Both demos request the same paid "/weather" API. Official x402 settles directly to the provider; Subly keeps the same app-level UX while routing payment through a private vault and batched payout.'
);
console.log("");

console.log("Commands for recording:");
console.log("  SUBLY402_DEMO_CONFIRM=1 yarn demo:x402-direct");
console.log("  SUBLY402_DEMO_CONFIRM=1 yarn demo:subly-private");
