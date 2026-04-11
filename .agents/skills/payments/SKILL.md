---
name: payments
description: "Skill for payment flows using Light Token APIs for sponsored rent-exemption."
metadata:
  source: https://github.com/Lightprotocol/skills
  documentation: https://www.zkcompression.com
  openclaw:
    requires:
      env: ["HELIUS_RPC_URL"]  # Required for all examples
      # Privy signing flow only (sign-with-privy.md): PRIVY_APP_ID, PRIVY_APP_SECRET, TREASURY_WALLET_ID, TREASURY_AUTHORIZATION_KEY — get these at privy.io
      bins: ["node", "cargo"] # node for TS client, cargo for Rust nullifier example
---

# Light Token payments

Build payment flows using light-token on Solana. The light-token API matches SPL-token and extends it to include the light token program.

| Creation cost     | SPL                 | light-token          |
| :---------------- | :------------------ | :------------------- |
| **Token Account** | ~2,000,000 lamports | ~**11,000** lamports |

## Workflow

1. **Clarify intent**
   - Recommend plan mode, if it's not activated
   - Use `AskUserQuestion` to resolve blind spots
   - All questions must be resolved before execution
2. **Identify references and skills**
   - Match task to [domain references](#domain-references) below
   - Locate relevant documentation and examples
3. **Write plan file** (YAML task format)
   - Use `AskUserQuestion` for anything unclear — never guess or assume
   - Identify blockers: permissions, dependencies, unknowns
   - Plan must be complete before execution begins
4. **Execute**
   - Use `Task` tool with subagents for parallel research
   - Subagents load skills via `Skill` tool
   - Track progress with `TodoWrite`
5. **When stuck**: ask to spawn a read-only subagent with `Read`, `Glob`, `Grep`, and DeepWiki MCP access, loading `skills/ask-mcp`. Scope reads to skill references, example repos, and docs.

## API overview

| Operation | SPL | light-token (action / instruction) |
|-----------|-----|-------------------------------------|
| Receive | `getOrCreateAssociatedTokenAccount()` | `loadAta()` / `createLoadAtaInstructions()` |
| Transfer | `createTransferInstruction()` | `transferInterface()` / `createTransferInterfaceInstructions()` |
| Get balance | `getAccount()` | `getAtaInterface()` |
| Tx history | `getSignaturesForAddress()` | `rpc.getSignaturesForOwnerInterface()` |
| Wrap from SPL | N/A | `wrap()` / `createWrapInstruction()` |
| Unwrap to SPL | N/A | `unwrap()` / `createUnwrapInstructions()` |
| Register SPL mint | N/A | `createSplInterface()` / `LightTokenProgram.createSplInterface()` |
| Create mint | `createMint()` | `createMintInterface()` |

Plural functions (`createTransferInterfaceInstructions`, `createUnwrapInstructions`) return `TransactionInstruction[][]` — each inner array is one transaction. They handle loading cold accounts automatically.

## Setup

```bash
npm install @lightprotocol/compressed-token@beta @lightprotocol/stateless.js@beta @solana/web3.js @solana/spl-token
```

```typescript
import { createRpc } from "@lightprotocol/stateless.js";
import {
  createLoadAtaInstructions,
  loadAta,
  createTransferInterfaceInstructions,
  transferInterface,
  createUnwrapInstructions,
  unwrap,
  getAssociatedTokenAddressInterface,
  getAtaInterface,
  wrap,
} from "@lightprotocol/compressed-token/unified";

const rpc = createRpc(RPC_ENDPOINT);
```

## Resources

| Name | Description | Docs | Examples | Reference |
|------|-------------|------|----------|-----------|
| Overview | Light Token APIs reduce account creation cost for stablecoin payment infrastructure by 99%. | [overview](https://zkcompression.com/light-token/payments/overview) | | |
| Basic payment | Send a single token transfer with comparison to SPL. | [basic-payment](https://zkcompression.com/light-token/payments/basic-payment) | [basic-send-action](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/basic-send-action.ts) \| [basic-send-instruction](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/basic-send-instruction.ts) | [send-payments.md](references/send-payments.md) |
| Batch payments | Send payments to multiple recipients in a single transaction. | [batch-payments](https://zkcompression.com/light-token/payments/batch-payments) | [batch-send](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/batch-send.ts) | [send-payments.md](references/send-payments.md) |
| Payment with memo | Attach invoice IDs or payment references using Solana's memo program. | [payment-with-memo](https://zkcompression.com/light-token/payments/payment-with-memo) | [payment-with-memo](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/payment-with-memo.ts) | [send-payments.md](references/send-payments.md) |
| Receive payments | Load cold accounts and share ATA address with the sender. | [receive-payments](https://zkcompression.com/light-token/payments/receive-payments) | [receive](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/receive/receive.ts) | [receive-payments.md](references/receive-payments.md) |
| Verify payments | Query token balances and transaction history. | [verify-payments](https://zkcompression.com/light-token/payments/verify-payments) | [get-balance](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/get-balance.ts) \| [get-history](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/get-history.ts) | [show-balance.md](references/show-balance.md) \| [transaction-history.md](references/transaction-history.md) |
| Verify address | Verify recipient addresses before sending payments. | [verify-recipient-address](https://zkcompression.com/light-token/payments/verify-recipient-address) | [verify-address](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/verify-address.ts) | [verify-address.md](references/verify-address.md) |
| Wrap and unwrap | Move tokens between SPL / Token 2022 and Light Token accounts. | [wrap-unwrap](https://zkcompression.com/light-token/payments/wrap-unwrap) | [wrap](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/wrap.ts) \| [unwrap](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/unwrap.ts) | [wrap-from-spl.md](references/wrap-from-spl.md) \| [unwrap-to-spl.md](references/unwrap-to-spl.md) |
| Register SPL mint | Register existing SPL mint for light-token interop. | | [register-spl-mint](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/register-spl-mint.ts) | [register-spl-mint.md](references/register-spl-mint.md) |
| Spend permissions | Delegate token spending with an amount cap. Approve, transfer as delegate, revoke. | [spend-permissions](https://zkcompression.com/light-token/payments/spend-permissions) | [delegate-approve](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/spend-permissions/delegate-approve.ts) \| [delegate-transfer](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/spend-permissions/delegate-transfer.ts) | [spend-permissions.md](references/spend-permissions.md) |
| Nullifier PDAs | Create rent-free nullifier PDAs to prevent duplicate actions. | [nullifier-pda](https://zkcompression.com/pda/compressed-pdas/nullifier-pda) | | [nullifiers.md](references/nullifiers.md) |
| Production readiness | Checklist for deploying to production: RPC, error handling, security. | [production-readiness](https://zkcompression.com/light-token/payments/production-readiness) | | [production-readiness.md](references/production-readiness.md) |
| Wallet integration | Guide for Wallet Applications to add Light-token support. | [wallets/overview](https://zkcompression.com/light-token/wallets/overview) | | |
| Sign with Privy | Integrate with Privy embedded wallets. | [privy](https://zkcompression.com/light-token/wallets/privy) | [sign-with-privy](https://github.com/Lightprotocol/examples-light-token/tree/main/toolkits/sign-with-privy) | [sign-with-privy.md](references/sign-with-privy.md) |
| Sign with Wallet Adapter | Integrate with Solana Wallet Adapter. | [wallet-adapter](https://zkcompression.com/light-token/wallets/wallet-adapter) | [sign-with-wallet-adapter](https://github.com/Lightprotocol/examples-light-token/tree/main/toolkits/sign-with-wallet-adapter) | [sign-with-adapter.md](references/sign-with-adapter.md) |
| Gasless transactions | Abstract SOL fees. Sponsor top-ups and transaction fees. | [gasless-transactions](https://zkcompression.com/light-token/wallets/gasless-transactions) | [gasless-transactions](https://github.com/Lightprotocol/examples-light-token/tree/main/toolkits/gasless-transactions) | [gasless-transactions.md](references/gasless-transactions.md) |
| SPL to Light comparison | Side-by-side API mapping. | [Docs](https://www.zkcompression.com/api-reference/solana-to-light-comparison) | | [spl-to-light.md](references/spl-to-light.md) |
| Token 2022 extensions | Supported Token 2022 extensions. | [Docs](https://www.zkcompression.com/extensions/overview) | [Examples](https://github.com/Lightprotocol/examples-light-token/tree/main/extensions) | [extensions/overview.md](references/extensions/overview.md) |

## SDK references

| Package | Link |
|---------|------|
| `@lightprotocol/stateless.js` | [API docs](https://lightprotocol.github.io/light-protocol/stateless.js/index.html) |
| `@lightprotocol/compressed-token` | [API docs](https://lightprotocol.github.io/light-protocol/compressed-token/index.html) |
| `@lightprotocol/nullifier-program` | [npm](https://www.npmjs.com/package/@lightprotocol/nullifier-program) |

## Security

The Privy signing examples transmit secrets to an external API — review [sign-with-privy.md](references/sign-with-privy.md) before running.

- **Declared dependencies.** `HELIUS_RPC_URL` is required for all examples. The Privy signing flow additionally requires `PRIVY_APP_ID`, `PRIVY_APP_SECRET`, `TREASURY_WALLET_ID`, and `TREASURY_AUTHORIZATION_KEY` — get these at [privy.io](https://privy.io). Load secrets from a secrets manager, not agent-global environment.
- **Privy signing flow.** `PRIVY_APP_SECRET` and `TREASURY_AUTHORIZATION_KEY` are sent to Privy's signing API. Verify these only reach Privy's official endpoints. See [sign-with-privy.md](references/sign-with-privy.md).
- **Subagent scope.** When stuck, the skill asks to spawn a read-only subagent with `Read`, `Glob`, `Grep` scoped to skill references, example repos, and docs.
- **Install source.** `npx skills add Lightprotocol/skills` from [Lightprotocol/skills](https://github.com/Lightprotocol/skills).
- **Audited protocol.** Light Protocol smart contracts are independently audited. Reports are published at [github.com/Lightprotocol/light-protocol/tree/main/audits](https://github.com/Lightprotocol/light-protocol/tree/main/audits).
