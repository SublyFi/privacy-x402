# SPL to Light comparison

Payment-focused subset of SPL-to-Light mappings. Covers connection setup, balance queries, transaction history, transfers, wrap/unwrap, and load ATA.

## Quick reference

| Operation | SPL | Light | Notes |
|-----------|-----|-------|-------|
| Create connection | `new Connection(url)` | `createRpc(url)` | Thin wrapper extending Solana's `Connection` |
| Get balance | `getAccount(connection, ata)` | `getAtaInterface(rpc, ata, owner, mint)` | Light returns hot + cold balances |
| Transaction history | `getSignaturesForAddress(ata)` | `rpc.getSignaturesForOwnerInterface(owner)` | Merged + deduplicated across compressed |
| Transfer (action) | `transfer(connection, ...)` | `transferInterface(rpc, ...)` | |
| Transfer (instruction) | `createTransferInstruction(...)` | `createTransferInterfaceInstructions(...)` | Returns `TransactionInstruction[][]` |
| Wrap SPL to Light | N/A | `wrap(rpc, ...)` | Bridge from SPL to Light |
| Unwrap Light to SPL | N/A | `unwrap(rpc, ...)` | Bridge from Light to SPL |
| Load ATA | N/A | `loadAta(rpc, ...)` | Creates ATA + loads cold state |

## Create connection

```typescript
// SPL
import { Connection } from "@solana/web3.js";

const connection = new Connection(RPC_ENDPOINT);
```

```typescript
// Light
import { createRpc, Rpc } from '@lightprotocol/stateless.js';

const connection: Rpc = createRpc(RPC_ENDPOINT, RPC_ENDPOINT);
```

## Get balance

```typescript
// SPL
import { getAccount } from "@solana/spl-token";

const account = await getAccount(connection, ata);

console.log(account.amount);
```

```typescript
// Light — returns hot + cold balances
import {
  getAssociatedTokenAddressInterface,
  getAtaInterface,
} from "@lightprotocol/compressed-token";

const ata = getAssociatedTokenAddressInterface(mint, owner);
const account = await getAtaInterface(rpc, ata, owner, mint);

console.log(account.parsed.amount);
```

## Transaction history

```typescript
// SPL
const signatures = await connection.getSignaturesForAddress(ata);
```

```typescript
// Light — merged and deduplicated across on-chain and compressed
const result = await rpc.getSignaturesForOwnerInterface(owner);

console.log(result.signatures); // Merged + deduplicated
console.log(result.solana);     // On-chain txs only
console.log(result.compressed); // Compressed txs only
```

## Transfer

### Action

```typescript
// SPL
import { transfer } from "@solana/spl-token";

const tx = await transfer(
  connection,
  payer,
  sourceAta,
  destinationAta,
  owner,
  amount
);
```

```typescript
// Light
import { transferInterface } from "@lightprotocol/compressed-token/unified";

const tx = await transferInterface(
  rpc,
  payer,
  sourceAta,
  mint,
  recipient,
  owner,
  amount
);
```

### Instruction

For payment flows where you need to handle cold account loading and multi-transaction signing:

```typescript
// SPL
import { createTransferInstruction } from "@solana/spl-token";

const ix = createTransferInstruction(
  sourceAta,
  destinationAta,
  owner.publicKey,
  amount
);
```

```typescript
// Light — returns TransactionInstruction[][] (handles cold loading)
import { createTransferInterfaceInstructions } from "@lightprotocol/compressed-token/unified";

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
  // sign and send...
}
```

## Wrap and unwrap (Light only)

Move tokens between SPL and Light. No SPL equivalent — this bridges the two systems.

```typescript
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import {
  wrap,
  getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token";
import { unwrap } from "@lightprotocol/compressed-token/unified";

const splAta = getAssociatedTokenAddressSync(mint, owner.publicKey);
const tokenAta = getAssociatedTokenAddressInterface(mint, owner.publicKey);

// Wrap: SPL → Light
await wrap(rpc, payer, splAta, tokenAta, owner, mint, amount);

// Unwrap: Light → SPL
await unwrap(rpc, payer, splAta, owner, mint, amount);
```

## Load ATA (Light only)

Creates the ATA if needed and loads any compressed (cold) state into it. Use this as the "receive" flow — ensures the recipient account is ready.

```typescript
import {
  loadAta,
  getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token";

const ata = getAssociatedTokenAddressInterface(mint, recipient);

const sig = await loadAta(rpc, ata, recipient, mint, payer);
```

## Links

- [Migration reference](https://zkcompression.com/api-reference/solana-to-light-comparison)
- [Payments guide](https://zkcompression.com/light-token/toolkits/for-payments)
- [Wallets guide](https://zkcompression.com/light-token/toolkits/for-wallets)
- [Payment examples](https://github.com/Lightprotocol/examples-light-token/tree/main/toolkits/payments)
