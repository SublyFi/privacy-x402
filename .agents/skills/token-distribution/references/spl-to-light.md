# SPL to Light comparison

Setup operations for token distribution. Covers create mint, create ATA, mint-to, and the batch distribution advantage.

## Quick reference

| Operation | SPL | Light | Notes |
|-----------|-----|-------|-------|
| Create mint | `createMint` | `createMintInterface` | Setup step |
| Create ATA | `getOrCreateAssociatedTokenAccount` | `createAtaInterface` | Setup step |
| Mint tokens | `mintTo` | `mintToInterface` | Setup step |
| Batch distribute | Loop: N `createAssociatedTokenAccount` + N `transfer` | `compress()` single instruction | 5000x cheaper per recipient |

## Create mint

```typescript
// SPL
import { createMint } from "@solana/spl-token";

const mint = await createMint(
  connection,
  payer,
  mintAuthority,
  freezeAuthority,
  decimals
);
```

```typescript
// Light
import { createMintInterface } from "@lightprotocol/compressed-token";

const { mint } = await createMintInterface(
  rpc,
  payer,
  mintAuthority,
  freezeAuthority,
  decimals,
  mintKeypair
);
```

## Create associated token account

```typescript
// SPL
import { getOrCreateAssociatedTokenAccount } from "@solana/spl-token";

const ata = await getOrCreateAssociatedTokenAccount(
  connection,
  payer,
  mint,
  owner
);
```

```typescript
// Light
import { createAtaInterface } from "@lightprotocol/compressed-token";

const ata = await createAtaInterface(
  rpc,
  payer,
  mint,
  owner
);
```

## Mint tokens

```typescript
// SPL
import { mintTo } from "@solana/spl-token";

const tx = await mintTo(
  connection,
  payer,
  mint,
  destination,
  mintAuthority,
  amount
);
```

```typescript
// Light
import { mintToInterface } from "@lightprotocol/compressed-token";

const tx = await mintToInterface(
  rpc,
  payer,
  mint,
  destination,
  mintAuthority,
  amount
);
```

## Batch distribution

SPL requires creating a token account per recipient (N create-ATA + N transfer transactions). Light uses `compress()` to distribute to multiple recipients in a single instruction.

There is no direct SPL equivalent for batch distribution at this scale.

```typescript
// SPL — per-recipient loop
for (const recipient of recipients) {
  const ata = await getOrCreateAssociatedTokenAccount(connection, payer, mint, recipient);
  await transfer(connection, payer, sourceAta, ata.address, owner, amount);
}
```

```typescript
// Light — single instruction for all recipients
import { CompressedTokenProgram, getTokenPoolInfos, selectTokenPoolInfo } from "@lightprotocol/compressed-token";
import { bn, createRpc, selectStateTreeInfo, buildAndSignTx, sendAndConfirmTx } from "@lightprotocol/stateless.js";
import { ComputeBudgetProgram } from "@solana/web3.js";

const rpc = createRpc(RPC_ENDPOINT);

const treeInfo = selectStateTreeInfo(await rpc.getStateTreeInfos());
const tokenPoolInfo = selectTokenPoolInfo(await getTokenPoolInfos(rpc, mint));

const ix = await CompressedTokenProgram.compress({
  payer: payer.publicKey,
  owner: payer.publicKey,
  source: sourceAta.address,
  toAddress: recipients,              // PublicKey[]
  amount: recipients.map(() => bn(amount)),
  mint,
  tokenPoolInfo,
  outputStateTreeInfo: treeInfo,
});

const instructions = [
  ComputeBudgetProgram.setComputeUnitLimit({ units: 120_000 * recipients.length }),
  ix,
];
const { blockhash } = await rpc.getLatestBlockhash();
const tx = buildAndSignTx(instructions, payer, blockhash, []);
await sendAndConfirmTx(rpc, tx);
```

### Cost comparison

| | SPL | Light |
|---|-----|-------|
| Per token account | ~2,000,000 lamports | ~5,000 lamports |
| 100k recipients | ~200 SOL | ~0.5 SOL |

## Links

- [Migration reference](https://zkcompression.com/api-reference/solana-to-light-comparison)
- [Airdrop guide](https://www.zkcompression.com/compressed-tokens/airdrop)
- [Distribution examples](https://github.com/Lightprotocol/examples-light-token)
