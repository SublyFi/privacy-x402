# Implementation Progress

## Phase 1: On-chain Program (2026-04-12) ✅

Anchor program implemented and all tests passing.

### Account structs (all future-phase fields included to avoid realloc)
- `VaultConfig` — vault state, governance, signer, counters
- `AuditRecord` — encrypted audit trail (Phase 2+ usage)
- `ForceSettleRequest` — dispute resolution state
- `UsedWithdrawNonce` — replay prevention

### Instructions (12)
- `initialize_vault`, `deposit`, `withdraw`, `settle_vault`
- `pause_vault`, `announce_migration`, `retire_vault`, `rotate_auditor`
- `force_settle_init`, `force_settle_challenge`, `force_settle_finalize`
- `record_audit` (Phase 2 stub)

### Tests (18 passing)
- initialize_vault, deposit (+zero reject), settle_vault (+unauthorized signer reject, multi-provider batch)
- pause_vault (+deposit-on-paused reject), announce_migration, rotate_auditor
- retire_vault (+active-vault reject)
- withdraw (+wrong signer reject, +mismatched message reject, +nonce replay reject)
- force_settle_init (+wrong signer reject)
- force_settle_challenge (+stale nonce reject)
- force_settle_finalize (dispute window active reject)

### Implementation notes
- Ed25519 signature verification: shared `ed25519_utils.rs` helper uses `solana_sdk_ids::ed25519_program::ID` (Anchor 0.32.1 does not re-export `ed25519_program` from `anchor_lang::solana_program`)
- `anchor-spl/idl-build` feature required in Cargo.toml for IDL generation
- Status guard matrix enforced via Anchor constraints (design doc section 6.3)
- PDA seeds match design doc section 6.2

## Phase 1: Enclave Facilitator (2026-04-12) ✅

### API Endpoints (8)
- `GET /v1/attestation` — Vault config, signer pubkey, stub attestation doc
- `POST /v1/verify` — Full payment verification + balance reservation + WAL
- `POST /v1/settle` — Off-chain settlement + ParticipantReceipt issuance
- `POST /v1/cancel` — Release reserved balance
- `POST /v1/withdraw-auth` — Ed25519 signed withdrawal authorization
- `POST /v1/balance` — Client balance query
- `POST /v1/receipt` — Issue signed ParticipantReceipt for client
- `POST /v1/provider/register` — Provider registration

### State Management
- `VaultState` with DashMap-based concurrent state
- `ClientBalance`, `Reservation`, `ProviderCredit`, `ProviderRegistration`
- Atomic nonces for receipts and withdrawals

### Background Tasks
- Batch settlement loop (120s window, MIN_BATCH_PROVIDERS=2, MAX_SETTLEMENT_DELAY=900s)
- Reservation expiry loop (60s timeout)
- Deposit detection loop (polling mode for local dev, production uses logsSubscribe)

### Persistence
- JSONL WAL with sync/flush (durable before response)
- Events: DepositApplied, ReservationCreated, SettlementCommitted, ReservationCancelled, ReservationExpired, ParticipantReceiptIssued, BatchSubmitted, BatchConfirmed

## Phase 1: Parent Instance (2026-04-12) ✅

### Components (4)
- `ingress_relay.rs` — TCP → vsock bidirectional L4 relay (TLS terminated in enclave)
- `egress_relay.rs` — vsock → TCP with connect-request protocol for external targets
- `kms_proxy.rs` — Length-prefixed JSON proxy with KMS action whitelist
- `snapshot_store.rs` — Encrypted blob store with PUT/GET/LIST/DELETE ops, SHA-256 path hashing

### Design decisions
- All components use TCP loopback for local dev, vsock for production Nitro
- KMS proxy whitelists only Decrypt/GenerateDataKey/GenerateRandom
- Snapshot store uses atomic write (temp file + rename) for data integrity
- Parent never terminates TLS — transparent L4 relay only

## Phase 1: Deposit Detection (2026-04-12) ✅

### deposit_detector.rs
- `DepositDetector` struct with sync status, processed signature tracking
- `spawn_deposit_detector` background task
- Main loop: initial catch-up → subscribe → reconnect on failure
- Catch-up logic per design doc §5.6 (getSignaturesForAddress)
- `apply_deposit`: updates client balance + WAL + processed signatures
- Phase 1: polling mode stub. Production: logsSubscribe WebSocket

## Phase 1: Client SDK (2026-04-12) ✅

### A402Client Methods
- `verifyAttestation()` — Cached attestation verification
- `deposit(amount, program, usdcMint)` — On-chain USDC deposit
- `withdraw(amount, program, usdcMint)` — Enclave-authorized withdrawal
- `getBalance()` — Query enclave client balance
- `getReceipt(usdcMint)` — Request signed ParticipantReceipt
- `forceSettle(receipt, program)` — Emergency on-chain force settle
- `fetch(url, options)` — x402-compatible automatic payment

### Type Exports
- BalanceResponse, ParticipantReceiptResponse added to SDK types

## Phase 1: Provider Middleware (2026-04-12) ✅

- Express middleware with 402 response generation
- PAYMENT-SIGNATURE decoding and facilitator verify/settle
- Async settlement after response delivery

## Remaining for Phase 2
- `record_audit` full implementation (ElGamal encryption)
- Hierarchical key derivation for selective disclosure
- AuditTool in SDK
- settle_vault + record_audit atomic chunk pairing
- Batch submission to on-chain settle_vault (enclave → Solana RPC)
