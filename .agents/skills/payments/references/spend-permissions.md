# Spend permissions

Delegation with Light Token works similar to SPL. When you approve a delegate, you authorize a specific account to transfer tokens on your behalf:

- **Owner retains custody**: You still own the tokens and can transfer or revoke at any time. Delegation is non-custodial.
- **Capped spending**: The delegate can spend tokens up to the limit, but cannot access or drain the account beyond the approved amount.
- **Single delegate per account**: Each token account can only have one active delegate. The owner can revoke at any time.
- **New approval replaces old**: Approving a new delegate automatically revokes the previous one.

## Use cases

| Use case | How delegation helps |
|:---------|:--------------------|
| **Subscriptions** | Approve a monthly cap. The service provider transfers the fee each period. |
| **Recurring payments** | Approve a spending limit. The payment processor draws funds as needed. |
| **Managed spending** | A parent or admin approves a cap for a sub-account. |
| **Agent wallets** | An AI agent operates within a delegated spending limit. |

## Approve a delegate

Grant a delegate permission to spend up to a capped amount:

```typescript
import { approveInterface } from "@lightprotocol/compressed-token/unified";

const tx = await approveInterface(
  rpc,
  payer,
  senderAta,
  mint,
  delegate.publicKey,     // who gets permission
  500_000,                // amount cap
  owner                   // token owner (signs)
);

console.log("Approved:", tx);
```

## Check delegation status

```typescript
import { getAtaInterface } from "@lightprotocol/compressed-token";

const account = await getAtaInterface(rpc, senderAta, owner.publicKey, mint);

console.log("Delegate:", account.parsed.delegate?.toBase58() ?? "none");
console.log("Delegated amount:", account.parsed.delegatedAmount.toString());
```

## Transfer as delegate

Once approved, the delegate can transfer tokens on behalf of the owner. The delegate is the transaction authority. Only the delegate and fee payer sign; the owner's signature is not required.

`transferInterface` takes a recipient wallet address and creates the recipient's associated token account internally. Pass `{ owner }` to transfer as a delegate instead of the owner.

### Action

```typescript
import { transferInterface } from "@lightprotocol/compressed-token/unified";

const tx = await transferInterface(
  rpc,
  payer,
  senderAta,
  mint,
  recipient.publicKey,   // recipient wallet (ATA created internally)
  delegate,              // delegate authority (signer)
  200_000,               // must be within approved cap
  undefined,
  { owner: owner.publicKey }  // owner (does not sign)
);
```

### Instruction

`createTransferInterfaceInstructions` returns `TransactionInstruction[][]` for manual transaction control. Pass `owner` to transfer as a delegate.

```typescript
import { Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { createTransferInterfaceInstructions } from "@lightprotocol/compressed-token/unified";

const instructions = await createTransferInterfaceInstructions(
  rpc,
  payer.publicKey,
  mint,
  200_000,
  delegate.publicKey,
  recipient.publicKey,
  9, // decimals
  { owner: owner.publicKey }
);

for (const ixs of instructions) {
  const tx = new Transaction().add(...ixs);
  await sendAndConfirmTransaction(rpc, tx, [payer, delegate]);
}
```

## Revoke a delegate

Remove spending permission:

```typescript
import { revokeInterface } from "@lightprotocol/compressed-token/unified";

const tx = await revokeInterface(rpc, payer, senderAta, mint, owner);

console.log("Revoked:", tx);
```

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [delegate-approve.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/spend-permissions/delegate-approve.ts) | Let a delegate spend tokens on your behalf. | `approveInterface` |
| [delegate-revoke.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/spend-permissions/delegate-revoke.ts) | Revoke delegate access. | `revokeInterface` |
| [delegate-check.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/spend-permissions/delegate-check.ts) | Check current delegation status and remaining allowance. | `getAtaInterface` |
| [delegate-transfer.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/spend-permissions/delegate-transfer.ts) | Approve delegate, then transfer on owner's behalf. | `approveInterface`, `transferInterface` |

## Source

- [Spend permissions docs](https://zkcompression.com/light-token/payments/spend-permissions)
- [GitHub examples](https://github.com/Lightprotocol/examples-light-token/tree/main/toolkits/payments/spend-permissions)
