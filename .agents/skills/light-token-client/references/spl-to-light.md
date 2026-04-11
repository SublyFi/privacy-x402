# SPL to Light comparison

Side-by-side mapping of SPL Token client operations to Light Token equivalents. Covers TypeScript (`@lightprotocol/compressed-token`) and Rust (`light_token_client` / `light_token`).

## Quick reference

| Operation | SPL (TypeScript) | Light (TypeScript) | SPL (Rust) | Light (Rust) |
|-----------|------------------|--------------------|------------|--------------|
| Create connection | `Connection` | `createRpc` | `RpcClient` | `LightClient` |
| Create mint | `createMint` | `createMintInterface` | `initialize_mint` | `CreateMint` |
| Create ATA | `getOrCreateAssociatedTokenAccount` | `createAtaInterface` | `create_associated_token_account` | `CreateAta` |
| Mint tokens | `mintTo` | `mintToInterface` | `mint_to` | `MintTo` |
| Transfer | `transfer` | `transferInterface` | `transfer` | `TransferInterface` |
| Approve | `approve` | `approveInterface` | `approve` | `Approve` |
| Revoke | `revoke` | `revokeInterface` | `revoke` | `Revoke` |
| Create token account | — | — | `initialize_account` | `CreateTokenAccount` |
| Burn | — | — | `burn` | `Burn` |
| Freeze | — | — | `freeze_account` | `Freeze` |
| Thaw | — | — | `thaw_account` | `Thaw` |
| Close | — | — | `close_account` | `CloseAccount` |
| Wrap SPL to Light | — | `wrap` | — | `Wrap` |
| Unwrap Light to SPL | — | `unwrap` | — | `Unwrap` |
| Get balance | `getAccount` | `getAtaInterface` | — | — |
| Transaction history | `getSignaturesForAddress` | `getSignaturesForOwnerInterface` | — | — |
| Load ATA | — | `loadAta` | — | — |

## RPC connection

### TypeScript

```typescript
// SPL
import { Connection } from "@solana/web3.js";

const connection = new Connection(RPC_ENDPOINT);
```

```typescript
// Light
import { createRpc, Rpc } from '@lightprotocol/stateless.js';

const RPC_ENDPOINT = 'https://mainnet.helius-rpc.com?api-key=YOUR_KEY';
const connection: Rpc = createRpc(RPC_ENDPOINT, RPC_ENDPOINT);
```

### Rust

```rust
// SPL
use solana_client::rpc_client::RpcClient;

let client = RpcClient::new(rpc_url.to_string());
```

```rust
// Light
use light_client::rpc::{LightClient, LightClientConfig, Rpc};

let rpc = LightClient::new(
    LightClientConfig::new(rpc_url.to_string(), None, None)
).await?;
```

## Create mint

### TypeScript action

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

### TypeScript instruction

```typescript
// SPL
import { createInitializeMint2Instruction } from "@solana/spl-token";

const ix = createInitializeMint2Instruction(
  mint.publicKey,
  decimals,
  mintAuthority,
  freezeAuthority,
  TOKEN_PROGRAM_ID
);
```

```typescript
// Light
import { createMintInstruction } from "@lightprotocol/compressed-token";

const ix = createMintInstruction(
  mintSigner.publicKey,
  decimals,
  payer.publicKey,
  freezeAuthority,
  payer.publicKey,
  validityProof,
  addressTreeInfo,
  stateTreeInfo,
  tokenMetadata
);
```

### Rust action

```rust
// SPL
use spl_token::instruction::initialize_mint;

let ix = initialize_mint(
    &spl_token::id(),
    &mint.pubkey(),
    &mint_authority,
    Some(&freeze_authority),
    decimals,
)?;
```

```rust
// Light
use light_token_client::actions::CreateMint;

let (sig, mint) = CreateMint {
    decimals: 9,
    freeze_authority: Some(payer.pubkey()),
    token_metadata: None,
    seed: None,
}
.execute(&mut rpc, &payer, &mint_authority)
.await?;
```

### Rust instruction

```rust
// Light
use light_token::instruction::CreateMint;

let ix = CreateMint::new(
    params,
    mint_seed.pubkey(),
    payer.pubkey(),
    address_tree.tree,
    output_queue,
)
.instruction()?;
```

## Create associated token account

### TypeScript action

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

### TypeScript instruction

```typescript
// SPL
import { createAssociatedTokenAccountInstruction } from "@solana/spl-token";

const ix = createAssociatedTokenAccountInstruction(
  payer.publicKey,
  ata,
  owner.publicKey,
  mint
);
```

```typescript
// Light
import { createAssociatedTokenAccountInterfaceInstruction } from "@lightprotocol/compressed-token";

const ix = createAssociatedTokenAccountInterfaceInstruction(
  payer.publicKey,
  ata,
  owner.publicKey,
  mint
);
```

### Rust action

```rust
// SPL
use spl_associated_token_account::instruction::create_associated_token_account;

let ix = create_associated_token_account(
    &payer.pubkey(),
    &owner.pubkey(),
    &mint,
    &spl_token::id(),
);
```

```rust
// Light
use light_token_client::actions::CreateAta;

let (sig, ata) = CreateAta {
    mint,
    owner: owner.pubkey(),
    idempotent: false,
}
.execute(&mut rpc, &payer)
.await?;
```

### Rust instruction

```rust
// Light
use light_token::instruction::CreateAssociatedTokenAccount;

let ix = CreateAssociatedTokenAccount::new(
    payer.pubkey(),
    owner.pubkey(),
    mint,
)
.instruction()?;
```

## Mint tokens

### TypeScript action

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

### TypeScript instruction

```typescript
// SPL
import { createMintToInstruction } from "@solana/spl-token";

const ix = createMintToInstruction(
  mint,
  destination,
  mintAuthority.publicKey,
  amount
);
```

```typescript
// Light
import { createMintToInterfaceInstruction } from "@lightprotocol/compressed-token";

const ix = createMintToInterfaceInstruction(
  mintInterface,
  destination,
  authority.publicKey,
  payer.publicKey,
  amount
);
```

### Rust action

```rust
// SPL
use spl_token::instruction::mint_to;

let ix = mint_to(
    &spl_token::id(),
    &mint,
    &destination,
    &mint_authority,
    &[],
    amount,
)?;
```

```rust
// Light
use light_token_client::actions::MintTo;

let sig = MintTo {
    mint,
    destination,
    amount,
}
.execute(&mut rpc, &payer, &authority)
.await?;
```

### Rust instruction

```rust
// Light
use light_token::instruction::MintTo;

let ix = MintTo {
    mint,
    destination,
    amount,
    authority: payer.pubkey(),
    fee_payer: payer.pubkey(),
}
.instruction()?;
```

## Transfer

### TypeScript action

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

### TypeScript instruction

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

### Rust action

```rust
// SPL
use spl_token::instruction::transfer;

let ix = transfer(
    &spl_token::id(),
    &source,
    &destination,
    &authority,
    &[],
    amount,
)?;
```

```rust
// Light
use light_token_client::actions::TransferInterface;

let sig = TransferInterface {
    source,
    mint,
    destination,
    amount,
    decimals,
    ..Default::default()
}
.execute(&mut rpc, &payer, &authority)
.await?;
```

### Rust instruction

```rust
// Light
use light_token::instruction::TransferInterface;

let ix = TransferInterface {
    source,
    destination,
    amount,
    decimals,
    authority: payer.pubkey(),
    payer: payer.pubkey(),
    mint,
    spl_interface: None,
    source_owner: LIGHT_TOKEN_PROGRAM_ID,
    destination_owner: LIGHT_TOKEN_PROGRAM_ID,
}
.instruction()?;
```

## Approve

### TypeScript

```typescript
// SPL
import { approve } from "@solana/spl-token";

const tx = await approve(
  connection,
  payer,
  source,
  delegate,
  owner,
  amount
);
```

```typescript
// Light
import { approveInterface } from "@lightprotocol/compressed-token/unified";
import { getAssociatedTokenAddressInterface } from "@lightprotocol/compressed-token";

const senderAta = getAssociatedTokenAddressInterface(mint, owner.publicKey);
const tx = await approveInterface(
  rpc,
  payer,
  senderAta,
  mint,
  delegate,
  amount,
  owner
);
```

### Rust action

```rust
// SPL
use spl_token::instruction::approve;

let ix = approve(
    &spl_token::id(),
    &source,
    &delegate,
    &owner,
    &[],
    amount,
)?;
```

```rust
// Light
use light_token_client::actions::Approve;

let sig = Approve {
    token_account: ata,
    delegate: delegate.pubkey(),
    amount,
    owner: None,
}
.execute(&mut rpc, &payer)
.await?;
```

### Rust instruction

```rust
// Light
use light_token::instruction::Approve;

let ix = Approve {
    token_account: ata,
    delegate: delegate.pubkey(),
    owner: payer.pubkey(),
    amount,
    fee_payer: payer.pubkey(),
}
.instruction()?;
```

## Revoke

### TypeScript

```typescript
// SPL
import { revoke } from "@solana/spl-token";

const tx = await revoke(
  connection,
  payer,
  source,
  owner
);
```

```typescript
// Light
import { revokeInterface } from "@lightprotocol/compressed-token/unified";
import { getAssociatedTokenAddressInterface } from "@lightprotocol/compressed-token";

const senderAta = getAssociatedTokenAddressInterface(mint, owner.publicKey);
const tx = await revokeInterface(rpc, payer, senderAta, mint, owner);
```

### Rust action

```rust
// SPL
use spl_token::instruction::revoke;

let ix = revoke(
    &spl_token::id(),
    &source,
    &owner,
    &[],
)?;
```

```rust
// Light
use light_token_client::actions::Revoke;

let sig = Revoke {
    token_account: ata,
    owner: None,
}
.execute(&mut rpc, &payer)
.await?;
```

### Rust instruction

```rust
// Light
use light_token::instruction::Revoke;

let ix = Revoke {
    token_account: ata,
    owner: payer.pubkey(),
    fee_payer: payer.pubkey(),
}
.instruction()?;
```

## Create token account (Rust only)

```rust
// SPL
use spl_token::instruction::initialize_account;

let ix = initialize_account(
    &spl_token::id(),
    &account,
    &mint,
    &owner,
)?;
```

```rust
// Light
use light_token::instruction::CreateTokenAccount;

let ix = CreateTokenAccount::new(
    payer.pubkey(),
    account.pubkey(),
    mint,
    owner,
)
.instruction()?;
```

## Burn (Rust only)

```rust
// SPL
use spl_token::instruction::burn;

let ix = burn(
    &spl_token::id(),
    &source,
    &mint,
    &authority,
    &[],
    amount,
)?;
```

```rust
// Light
use light_token::instruction::Burn;

let ix = Burn {
    source,
    mint,
    amount,
    authority: payer.pubkey(),
    fee_payer: payer.pubkey(),
}
.instruction()?;
```

## Freeze and thaw (Rust only)

```rust
// SPL
use spl_token::instruction::{freeze_account, thaw_account};

let ix = freeze_account(
    &spl_token::id(),
    &account,
    &mint,
    &freeze_authority,
    &[],
)?;

let ix = thaw_account(
    &spl_token::id(),
    &account,
    &mint,
    &freeze_authority,
    &[],
)?;
```

```rust
// Light
use light_token::instruction::{Freeze, Thaw};

let ix = Freeze {
    token_account: ata,
    mint,
    freeze_authority: payer.pubkey(),
}
.instruction()?;

let ix = Thaw {
    token_account: ata,
    mint,
    freeze_authority: payer.pubkey(),
}
.instruction()?;
```

## Close token account (Rust only)

```rust
// SPL
use spl_token::instruction::close_account;

let ix = close_account(
    &spl_token::id(),
    &account,
    &destination,
    &owner,
    &[],
)?;
```

```rust
// Light
use light_token::instruction::{CloseAccount, LIGHT_TOKEN_PROGRAM_ID};

let ix = CloseAccount::new(
    LIGHT_TOKEN_PROGRAM_ID,
    account,
    destination,
    owner,
)
.instruction()?;
```

## Wrap and unwrap (Light only)

Move tokens between SPL and Light. No SPL equivalent — this bridges the two systems.

### TypeScript

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

### Rust

```rust
use light_token_client::actions::Wrap;

let sig = Wrap {
    source_spl_ata: spl_ata,
    destination: light_ata,
    mint,
    amount,
    decimals,
}
.execute(&mut rpc, &payer, &payer)
.await?;
```

```rust
use light_token_client::actions::Unwrap;

let sig = Unwrap {
    source: light_ata,
    destination_spl_ata: spl_ata,
    mint,
    amount,
    decimals,
}
.execute(&mut rpc, &payer, &payer)
.await?;
```

## Get balance (TypeScript only)

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

## Transaction history (TypeScript only)

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

## Load ATA (Light only)

Creates the ATA if needed and loads any compressed (cold) state into it. Light Token accounts auto-compress inactive accounts. Before any action, the SDK detects cold balances and adds load instructions.

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
- [TypeScript examples](https://github.com/Lightprotocol/examples-light-token/tree/main/typescript-client)
- [Rust examples](https://github.com/Lightprotocol/examples-light-token/tree/main/rust-client)
- [Cookbook](https://zkcompression.com/light-token/cookbook)
