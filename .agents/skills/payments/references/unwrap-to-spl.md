# Unwrap to SPL

Convert light-token back to SPL. Use this for composing with apps that don't yet support light-token.

## Instruction

```typescript
import { Transaction } from "@solana/web3.js";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import { createUnwrapInstructions } from "@lightprotocol/compressed-token/unified";

const splAta = getAssociatedTokenAddressSync(mint, owner.publicKey);

// Each inner array = one transaction. Handles loading + unwrapping together.
const instructions = await createUnwrapInstructions(
  rpc,
  splAta,
  owner.publicKey,
  mint,
  amount,
  payer.publicKey
);

for (const ixs of instructions) {
  const tx = new Transaction().add(...ixs);
  await sendAndConfirmTransaction(rpc, tx, [payer, owner]);
}
```

## Action

```typescript
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import { unwrap } from "@lightprotocol/compressed-token/unified";

const splAta = getAssociatedTokenAddressSync(mint, owner.publicKey);

await unwrap(rpc, payer, splAta, owner, mint, amount);
```

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [unwrap.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/unwrap.ts) | Convert light-token back to SPL. For composing with apps that don't yet support light-token. | `unwrap` |

## Source

- [Wrap and unwrap docs](https://zkcompression.com/light-token/payments/interop/wrap-unwrap)
- [GitHub example](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/unwrap.ts)
