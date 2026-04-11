# Gasless transactions

Abstract SOL fees so users never hold SOL. Light Token lets your application cover rent and transaction fees for around 0.001 USD per transaction.

Your sponsor covers three costs:

| Cost | Amount | Details |
|:-----|:-------|:--------|
| **Account creation** | ~11,000 lamports (0.001 USD) | Initial bump on virtual rent balance. Rent-exemption is sponsored. |
| **Rent top-ups** | ~766 lamports per write | Fee payer bumps the virtual rent balance on each write to keep accounts active. Set `payer` parameter on any Light Token instruction. |
| **Transaction fees** | ~5,000 lamports per tx | Standard Solana fee payer. Set `feePayer` on the transaction. |

The `payer` parameter on any Light Token instruction determines who pays rent top-ups in addition to transaction fees. Set your application server as the payer so users never interact with SOL.

## TypeScript

### Create a sponsor account

```typescript
import { Keypair } from "@solana/web3.js";
import { createRpc } from "@lightprotocol/stateless.js";

const rpc = createRpc(RPC_ENDPOINT);

// Sponsor: your application server
const sponsor = Keypair.fromSecretKey(/* your server keypair */);

// User: only signs to authorize the transfer
const sender = Keypair.fromSecretKey(/* user's keypair */);
```

### Create the transfer instruction

Create the transfer instruction with the sponsor as `payer` and the sender as `authority`. The sender owns the tokens and must sign the transfer.

```typescript
import { createTransferInterfaceInstructions } from "@lightprotocol/compressed-token/unified";

const instructions = await createTransferInterfaceInstructions(
  rpc,
  sponsor.publicKey,      // payer: covers rent top-ups and transaction fees
  mint,
  amount,
  sender.publicKey,       // authority: user signs to authorize
  recipient.publicKey
);
```

### Send with both signers

Both the sponsor and sender must sign the transaction:

| Role | Parameter | What it does |
|:-----|:----------|:-------------|
| **Payer** (fee payer) | First positional arg | Signs to authorize payment of rent top-ups and transaction fees. Can be your application server. |
| **Authority** (owner) | `owner` / authority arg | Signs to authorize the token transfer. The account holder. |

```typescript
import { Transaction, sendAndConfirmTransaction } from "@solana/web3.js";

for (const ixs of instructions) {
  const tx = new Transaction().add(...ixs);
  // Both sponsor and sender must sign
  await sendAndConfirmTransaction(rpc, tx, [sponsor, sender]);
}
```

## Rust

### Create a sponsor account

```rust
use solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer};

// Sponsor: your application server
let sponsor: Keypair = /* your server keypair */;

// User: only signs to authorize the transfer
let sender: Keypair = /* user's keypair */;
let recipient: Pubkey = /* recipient address */;
let mint: Pubkey = /* e.g. USDC mint */;
```

### Create the transfer instruction

```rust
use light_token::instruction::{
    get_associated_token_address, TransferInterface, LIGHT_TOKEN_PROGRAM_ID,
};

let sender_ata = get_associated_token_address(&sender.pubkey(), &mint);
let recipient_ata = get_associated_token_address(&recipient, &mint);

let transfer_ix = TransferInterface {
    source: sender_ata,
    destination: recipient_ata,
    amount: 500_000,
    decimals: 6,
    mint,
    authority: sender.pubkey(),       // user signs to authorize
    payer: sponsor.pubkey(),          // sponsor covers rent top-ups and transaction fees
    spl_interface: None,
    source_owner: LIGHT_TOKEN_PROGRAM_ID,
    destination_owner: LIGHT_TOKEN_PROGRAM_ID,
}
.instruction()?;
```

### Send with both signers

```rust
let sig = rpc
    .create_and_send_transaction(
        &[transfer_ix],
        &sponsor.pubkey(),          // fee payer
        &[&sponsor, &sender],       // both sign
    )
    .await?;

println!("Tx: {sig}");
```

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [gasless-transfer.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/gasless-transactions/typescript/gasless-transfer.ts) | Full gasless transfer: sponsor pays all fees, user only signs to authorize. | `createTransferInterfaceInstructions` |

## Source

- [Gasless transactions docs](https://zkcompression.com/light-token/wallets/gasless-transactions)
- [GitHub example](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/gasless-transactions/typescript/gasless-transfer.ts)
