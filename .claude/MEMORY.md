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

### Tests (11 passing)
- initialize_vault, deposit (+zero reject), settle_vault (+unauthorized signer reject)
- pause_vault (+deposit-on-paused reject), announce_migration, rotate_auditor
- retire_vault (+active-vault reject)

### Implementation notes
- Ed25519 signature verification: shared `ed25519_utils.rs` helper uses `solana_sdk_ids::ed25519_program::ID` (Anchor 0.32.1 does not re-export `ed25519_program` from `anchor_lang::solana_program`)
- `anchor-spl/idl-build` feature required in Cargo.toml for IDL generation
- Status guard matrix enforced via Anchor constraints (design doc section 6.3)
- PDA seeds match design doc section 6.2

### Remaining for Phase 1
- Enclave facilitator (Rust): `/verify`, `/settle`, `/cancel`, `/attestation`
- Client SDK (TypeScript): `A402Client`
- Provider Middleware (TypeScript/Express)
- `withdraw` and `force_settle_*` integration tests (require Ed25519 precompile instruction construction in test)
