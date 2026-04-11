# Unwrap

Moves tokens from a Light Token associated token account (hot balance) back to an SPL or Token-2022 account.

## TypeScript

### Action

```typescript
import "dotenv/config";
import { Keypair } from "@solana/web3.js";
import { createRpc } from "@lightprotocol/stateless.js";
import {
    createMintInterface,
    createAtaInterface,
    mintToInterface,
    getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token";
import { unwrap } from "@lightprotocol/compressed-token/unified";
import {
    createAssociatedTokenAccount,
    TOKEN_2022_PROGRAM_ID,
} from "@solana/spl-token";
import { homedir } from "os";
import { readFileSync } from "fs";

// devnet:
// const RPC_URL = `https://devnet.helius-rpc.com?api-key=${process.env.API_KEY!}`;
// const rpc = createRpc(RPC_URL);
// localnet:
const rpc = createRpc();

const payer = Keypair.fromSecretKey(
    new Uint8Array(
        JSON.parse(readFileSync(`${homedir()}/.config/solana/id.json`, "utf8"))
    )
);

(async function () {
    // Setup: Create and mint tokens to light-token associated token account
    const { mint } = await createMintInterface(rpc, payer, payer, null, 9);
    await createAtaInterface(rpc, payer, mint, payer.publicKey);
    const destination = getAssociatedTokenAddressInterface(
        mint,
        payer.publicKey
    );
    await mintToInterface(rpc, payer, mint, destination, payer, 1000);

    // Unwrap light-token to SPL associated token account
    const splAta = await createAssociatedTokenAccount(
        rpc,
        payer,
        mint,
        payer.publicKey,
        undefined,
        TOKEN_2022_PROGRAM_ID
    );
    const tx = await unwrap(rpc, payer, splAta, payer, mint, 500);

    console.log("Tx:", tx);
})();
```

### Instruction

```typescript
import "dotenv/config";
import {
    Keypair,
    Transaction,
    sendAndConfirmTransaction,
} from "@solana/web3.js";
import { createRpc } from "@lightprotocol/stateless.js";
import {
    createMintInterface,
    createAtaInterface,
    getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token";
import {
    wrap,
    createUnwrapInstructions,
} from "@lightprotocol/compressed-token/unified";
import {
    TOKEN_PROGRAM_ID,
    createAssociatedTokenAccount,
    mintTo,
} from "@solana/spl-token";
import { homedir } from "os";
import { readFileSync } from "fs";

// devnet:
const RPC_URL = `https://devnet.helius-rpc.com?api-key=${process.env.API_KEY}`;
const rpc = createRpc(RPC_URL);
// localnet: const rpc = createRpc();
const payer = Keypair.fromSecretKey(
    new Uint8Array(
        JSON.parse(readFileSync(`${homedir()}/.config/solana/id.json`, "utf8"))
    )
);

(async function () {
    const { mint } = await createMintInterface(rpc, payer, payer, null, 9);
    await mintToCompressed(rpc, payer, mint, payer, [
        { recipient: payer.publicKey, amount: 1000n },
    ]);

    const splAta = await createAssociatedTokenAccount(
        rpc,
        payer,
        mint,
        payer.publicKey
    );

    // Returns TransactionInstruction[][]. Each inner array is one txn.
    // Handles loading cold state + unwrapping in one go.
    const instructions = await createUnwrapInstructions(
        rpc,
        splAta,
        payer.publicKey,
        mint,
        500n,
        payer.publicKey
    );

    for (const ixs of instructions) {
        const tx = new Transaction().add(...ixs);
        await sendAndConfirmTransaction(rpc, tx, [payer]);
    }
})();
```

## Rust

### Action

```rust
use anchor_spl::token::spl_token::state::Account as SplAccount;
use light_client::rpc::Rpc;
use light_token_client::actions::Unwrap;
use rust_client::{setup_for_unwrap, UnwrapContext};
use solana_sdk::program_pack::Pack;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup creates Light associated token account with tokens and empty SPL associated token account
    let UnwrapContext {
        mut rpc,
        payer,
        mint,
        destination_associated_token_account,
        light_associated_token_account,
        decimals,
    } = setup_for_unwrap().await;

    // Unwrap tokens from Light Token associated token account to SPL associated token account
    let sig = Unwrap {
        source: light_associated_token_account,
        destination_spl_ata: destination_associated_token_account,
        mint,
        amount: 500_000,
        decimals,
    }
    .execute(&mut rpc, &payer, &payer)
    .await?;

    let data = rpc
        .get_account(destination_associated_token_account)
        .await?
        .ok_or("Account not found")?;
    let token = SplAccount::unpack(&data.data)?;
    println!("Balance: {} Tx: {sig}", token.amount);

    Ok(())
}
```

## Links

- [Docs](https://zkcompression.com/light-token/cookbook/wrap-unwrap)
- [TS action example](https://github.com/Lightprotocol/examples-light-token/blob/main/typescript-client/actions/unwrap.ts)
- [TS instruction example](https://github.com/Lightprotocol/examples-light-token/blob/main/typescript-client/instructions/unwrap.ts)
- [Rust action example](https://github.com/Lightprotocol/examples-light-token/blob/main/rust-client/actions/unwrap.rs)
