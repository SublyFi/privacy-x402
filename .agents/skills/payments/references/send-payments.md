# Send payments

The SDK checks cold balances and adds load instructions automatically. The result is `TransactionInstruction[][]` where each inner array is one transaction. Almost always returns just one.

## Instruction

```typescript
import { Transaction } from "@solana/web3.js";
import { createTransferInterfaceInstructions } from "@lightprotocol/compressed-token/unified";

// Returns TransactionInstruction[][].
// Each inner array is one transaction.
// Almost always returns just one.
const instructions = await createTransferInterfaceInstructions(
  rpc,
  payer.publicKey,
  mint,
  amount,
  owner.publicKey,
  recipient
);

for (const ixs of instructions) {
  const tx = new Transaction().add(...ixs);

  // sign and send ...
}
```

## Action

```typescript
import {
  getAssociatedTokenAddressInterface,
  transferInterface,
} from "@lightprotocol/compressed-token/unified";

const sourceAta = getAssociatedTokenAddressInterface(mint, owner.publicKey);

// Handles loading, creates recipient associated token account, transfers.
await transferInterface(rpc, payer, sourceAta, mint, recipient, owner, amount);
```

## Sign all transactions together

When a transfer returns multiple transactions (rare), sign them all with one wallet approval:

```typescript
const transactions = instructions.map((ixs) => new Transaction().add(...ixs));

// One approval for all
const signed = await wallet.signAllTransactions(transactions);

for (const tx of signed) {
  await sendAndConfirmTransaction(rpc, tx);
}
```

## Optimize sending (parallel loads)

Use `sliceLast` to separate load transactions from the final transfer, then send loads in parallel:

```typescript
import {
  createTransferInterfaceInstructions,
  sliceLast,
} from "@lightprotocol/compressed-token/unified";

const instructions = await createTransferInterfaceInstructions(
  rpc,
  payer.publicKey,
  mint,
  amount,
  owner.publicKey,
  recipient
);
const { rest: loadInstructions, last: transferInstructions } = sliceLast(instructions);
// empty = nothing to load, will no-op.
await Promise.all(
  loadInstructions.map((ixs) => {
    const tx = new Transaction().add(...ixs);
    tx.sign(payer, owner);
    return sendAndConfirmTransaction(rpc, tx);
  })
);

const transferTx = new Transaction().add(...transferInstructions);
transferTx.sign(payer, owner);
await sendAndConfirmTransaction(rpc, transferTx);
```

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [basic-send-action.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/basic-send-action.ts) | Send tokens. One call handles loading and recipient account creation. | `transferInterface` |
| [basic-send-instruction.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/basic-send-instruction.ts) | Same transfer, but returns raw instructions for custom transaction building. | `createTransferInterfaceInstructions` |
| [payment-with-memo.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/payment-with-memo.ts) | Attach an invoice ID or payment reference. Reads it back from transaction logs. | `createTransferInterfaceInstructions`, `sliceLast` |
| [batch-send.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/batch-send.ts) | Pay multiple recipients in one transaction. | `createTransferInterfaceInstructions`, `createAtaInterfaceIdempotent` |
| [sign-all-transactions.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/send/sign-all-transactions.ts) | Sign all transactions with one wallet approval. Shows parallel load optimization. | `signAllTransactions`, `sliceLast` |
| [verify-address.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/verify-address.ts) | Confirm a recipient account exists before sending. | `getAssociatedTokenAddressInterface`, `getAtaInterface` |

> `transferInterface` supports delegated transfers: pass `{ owner: ownerPublicKey }` as the 9th parameter, with the delegate as the signer (6th param). See [spend-permissions.md](spend-permissions.md).

> For gasless transfers (separate fee payer / sponsor), see [gasless-transactions.md](gasless-transactions.md).

## Source

- [Send payments docs](https://zkcompression.com/light-token/payments/send-payments/basic-payment)
- [GitHub examples](https://github.com/Lightprotocol/examples-light-token/tree/main/toolkits/payments/send)
