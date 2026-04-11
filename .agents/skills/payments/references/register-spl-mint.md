# Register SPL mint

Before using light-token interface functions with an existing SPL mint, register it.

## Check if already registered

```typescript
import { getSplInterfaceInfos } from "@lightprotocol/compressed-token";

const infos = await getSplInterfaceInfos(rpc, mint);
const isRegistered = infos.some((i) => i.isInitialized);
```

## Register existing SPL mint (instruction)

```typescript
import { Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { LightTokenProgram } from "@lightprotocol/compressed-token";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";

const ix = await LightTokenProgram.createSplInterface({
  feePayer: payer.publicKey,
  mint,
  tokenProgramId: TOKEN_PROGRAM_ID,
});

const tx = new Transaction().add(ix);
await sendAndConfirmTransaction(rpc, tx, [payer]);
```

## Register existing SPL mint (action)

```typescript
import { createSplInterface } from "@lightprotocol/compressed-token";

await createSplInterface(rpc, payer, mint);
```

## Create new SPL mint with interface

```typescript
import { createMintInterface } from "@lightprotocol/compressed-token";
import { TOKEN_PROGRAM_ID } from "@solana/spl-token";

const { mint } = await createMintInterface(
  rpc, payer, payer, null, 9, undefined, undefined, TOKEN_PROGRAM_ID
);
```

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [register-spl-mint.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/register-spl-mint.ts) | One-time: register an interface PDA for an existing SPL mint (e.g. USDC). | `createSplInterface` |

## Source

- [Wrap and unwrap docs](https://zkcompression.com/light-token/payments/interop/wrap-unwrap)
- [GitHub example](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/interop/register-spl-mint.ts)
