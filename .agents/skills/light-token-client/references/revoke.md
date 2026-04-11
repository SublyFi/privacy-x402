# Revoke

Revokes a delegate's spending authority.

Only the token account owner can revoke delegates.

## TypeScript

### Action

```typescript
import "dotenv/config";
import { Keypair } from "@solana/web3.js";
import { createRpc } from "@lightprotocol/stateless.js";
import {
    createMintInterface,
    mintToCompressed,
    getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token";
import {
    approveInterface,
    revokeInterface,
} from "@lightprotocol/compressed-token/unified";
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
    const { mint } = await createMintInterface(rpc, payer, payer, null, 9);
    await mintToCompressed(rpc, payer, mint, payer, [
        { recipient: payer.publicKey, amount: 1000n },
    ]);

    const senderAta = getAssociatedTokenAddressInterface(mint, payer.publicKey);
    const delegate = Keypair.generate();
    await approveInterface(
        rpc,
        payer,
        senderAta,
        mint,
        delegate.publicKey,
        500_000,
        payer
    );
    console.log("Approved delegate:", delegate.publicKey.toBase58());

    const tx = await revokeInterface(rpc, payer, senderAta, mint, payer);

    console.log("Revoked all delegate permissions");
    console.log("Tx:", tx);
})();
```

### Instruction

```typescript
import "dotenv/config";
import { Keypair, sendAndConfirmTransaction, Transaction } from "@solana/web3.js";
import { createRpc } from "@lightprotocol/stateless.js";
import {
    createMintInterface,
    createAtaInterface,
    mintToInterface,
    getAssociatedTokenAddressInterface,
    createApproveInterfaceInstructions,
    createRevokeInterfaceInstructions,
} from "@lightprotocol/compressed-token";
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
    const owner = Keypair.generate();
    const { mint } = await createMintInterface(rpc, payer, payer, null, 9);
    await createAtaInterface(rpc, payer, mint, owner.publicKey);
    const ownerAta = getAssociatedTokenAddressInterface(mint, owner.publicKey);
    await mintToInterface(rpc, payer, mint, ownerAta, payer, 1_000_000_000);

    const delegate = Keypair.generate();

    // First approve, then revoke
    const approveBatches = await createApproveInterfaceInstructions(
        rpc, payer.publicKey, mint, ownerAta, delegate.publicKey, 500_000_000, owner.publicKey, 9
    );
    for (const ixs of approveBatches) {
        await sendAndConfirmTransaction(rpc, new Transaction().add(...ixs), [payer, owner]);
    }

    // Returns TransactionInstruction[][] — send sequentially
    const revokeBatches = await createRevokeInterfaceInstructions(
        rpc,
        payer.publicKey,
        mint,
        ownerAta,
        owner.publicKey,
        9,
    );

    for (let i = 0; i < revokeBatches.length - 1; i++) {
        await sendAndConfirmTransaction(rpc, new Transaction().add(...revokeBatches[i]), [payer, owner]);
    }
    const revokeTx = new Transaction().add(...revokeBatches[revokeBatches.length - 1]);
    const signature = await sendAndConfirmTransaction(rpc, revokeTx, [payer, owner]);

    console.log("Revoked delegate permissions");
    console.log("Tx:", signature);
})();
```

## Rust

### Action

```rust
use borsh::BorshDeserialize;
use light_client::rpc::Rpc;
use light_token_client::actions::Revoke;
use rust_client::{setup, SetupContext};
use solana_sdk::signer::Signer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup creates mint and associated token account with approved delegate
    let SetupContext {
        mut rpc,
        payer,
        associated_token_account,
        ..
    } = setup().await;

    let sig = Revoke {
        token_account: associated_token_account,
        owner: Some(payer.pubkey()),
    }
    .execute(&mut rpc, &payer)
    .await?;

    let data = rpc.get_account(associated_token_account).await?.ok_or("Account not found")?;
    let token = light_token_interface::state::Token::deserialize(&mut &data.data[..])?;
    println!("Delegate: {:?} Tx: {sig}", token.delegate);

    Ok(())
}
```

### Instruction

```rust
use borsh::BorshDeserialize;
use light_client::rpc::Rpc;
use light_token::instruction::Revoke;
use rust_client::{setup, SetupContext};
use solana_sdk::signer::Signer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup creates mint, associated token account with tokens, and approves delegate
    let SetupContext {
        mut rpc,
        payer,
        associated_token_account,
        ..
    } = setup().await;

    let revoke_instruction = Revoke {
        token_account: associated_token_account,
        owner: payer.pubkey(),
        fee_payer: payer.pubkey(),
    }
    .instruction()?;

    let sig = rpc
        .create_and_send_transaction(&[revoke_instruction], &payer.pubkey(), &[&payer])
        .await?;

    let data = rpc.get_account(associated_token_account).await?.ok_or("Account not found")?;
    let token = light_token_interface::state::Token::deserialize(&mut &data.data[..])?;
    println!("Delegate: {:?} Tx: {sig}", token.delegate);

    Ok(())
}
```

## Links

- [Docs](https://zkcompression.com/light-token/cookbook/approve-revoke)
- [TS example](https://github.com/Lightprotocol/examples-light-token/blob/main/typescript-client/actions/delegate-revoke.ts)
- [Rust action example](https://github.com/Lightprotocol/examples-light-token/blob/main/rust-client/actions/revoke.rs)
- [Rust instruction example](https://github.com/Lightprotocol/examples-light-token/blob/main/rust-client/instructions/revoke.rs)
