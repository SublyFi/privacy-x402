# Receive payments

Load creates the associated token account if needed and loads any compressed state into it. Share the associated token account address with the sender.

> **About loading**: Light tokens reduce account rent ~200x by auto-compressing inactive accounts. Before any action, the SDK detects compressed state and adds instructions to load it back on-chain. This almost always fits in a single atomic transaction. APIs return `TransactionInstruction[][]` so the same loop handles the rare multi-transaction case automatically.

## Instruction

```typescript
import { Transaction } from "@solana/web3.js";
import {
  createLoadAtaInstructions,
  getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token/unified";

const ata = getAssociatedTokenAddressInterface(mint, recipient);

// Returns TransactionInstruction[][].
// Each inner array is one transaction.
// Almost always returns just one.
const instructions = await createLoadAtaInstructions(
  rpc,
  ata,
  recipient,
  mint,
  payer.publicKey
);

for (const ixs of instructions) {
  const tx = new Transaction().add(...ixs);

  // sign and send ...
}
```

## Action

```typescript
import {
  loadAta,
  getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token/unified";

const ata = getAssociatedTokenAddressInterface(mint, recipient);

const sig = await loadAta(rpc, ata, recipient, mint, payer);
if (sig) console.log("Loaded:", sig);
```

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [receive.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/receive/receive.ts) | Prepare to receive: creates the token account if needed, loads compressed state. | `createLoadAtaInstructions` |
| [get-balance.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/get-balance.ts) | Check token balance for an account. | `getAtaInterface` |
| [get-history.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/get-history.ts) | List transactions (merged on-chain + compressed). | `getSignaturesForOwnerInterface` |

## Source

- [Receive payments docs](https://zkcompression.com/light-token/payments/accept-payments/receive-payments)
- [GitHub examples](https://github.com/Lightprotocol/examples-light-token/tree/main/toolkits/payments/receive)
