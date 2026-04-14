---
name: Architecture Decision - TEE + Arcium Hybrid
description: Privacy x402 uses TEE for real-time payments, Arcium MPC for yield vault. ZK migration path for future.
type: project
---

Architecture decision made 2026-04-15 after evaluating TEE vs ZK vs Arcium for privacy x402.

**Decision:** TEE (Nitro Enclave) for x402 real-time payment privacy + Arcium MPC for yield vault balance privacy.

**Why TEE for x402 (not ZK):**
- Confidential Transfer not yet available on Solana, so ZK/proxy can't hide amounts
- Without amount hiding, batching alone is insufficient (amount correlation attacks)
- TEE provides full Level A privacy (hide from on-chain observers) today
- Phase 1-4 already implemented with 58 tests
- ZK is theoretically superior but produces same Level A outcome; HW trust difference doesn't affect PMF

**Why Arcium for yield vault (not TEE):**
- Vault operations are async/batch — fits Arcium's queue→compute→callback model
- Adds Level B privacy: even operator can't see individual agent balances/yield
- Genuine Arcium integration for hackathon sponsor prize
- Clean separation: Arcium = money at rest, TEE = money in motion

**Why not Arcium for x402:**
- x402 requires real-time synchronous processing (~ms)
- Arcium's async MPC adds unacceptable latency for per-request payment processing
- Arcium alone cannot replace TEE for the full x402 flow

**How to apply:** When making architecture changes, maintain this separation. TEE handles the hot path (payment processing), Arcium handles cold path (balance/yield). Future phases replace TEE with ZK as Solana privacy primitives mature.
