# Wrap from SPL

Convert SPL or Token 2022 tokens to light-token.

## Instruction

```typescript
import { Transaction } from "@solana/web3.js";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import {
  createWrapInstruction,
  getAssociatedTokenAddressInterface,
  getSplInterfaceInfos,
} from "@lightprotocol/compressed-token";

const splAta = getAssociatedTokenAddressSync(mint, owner.publicKey);
const tokenAta = getAssociatedTokenAddressInterface(mint, owner.publicKey);

const splInterfaceInfos = await getSplInterfaceInfos(rpc, mint);
const splInterfaceInfo = splInterfaceInfos.find((i) => i.isInitialized);

const tx = new Transaction().add(
  createWrapInstruction(
    splAta,
    tokenAta,
    owner.publicKey,
    mint,
    amount,
    splInterfaceInfo,
    decimals,
    payer.publicKey
  )
);
```

## Action

```typescript
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import {
  wrap,
  getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token";

const splAta = getAssociatedTokenAddressSync(mint, owner.publicKey);
const tokenAta = getAssociatedTokenAddressInterface(mint, owner.publicKey);

await wrap(rpc, payer, splAta, tokenAta, owner, mint, amount);
```

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [wrap.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/wrap.ts) | Convert SPL or Token 2022 tokens to light-token. | `wrap` |

## Source

- [Wrap and unwrap docs](https://zkcompression.com/light-token/payments/interop/wrap-unwrap)
- [GitHub example](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/wrap.ts)
