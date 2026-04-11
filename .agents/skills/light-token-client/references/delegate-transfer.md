# Delegate transfer

Transfers tokens on behalf of the owner using a delegate's authority. The owner must first approve the delegate via `approveInterface`.

## TypeScript

### Action

```typescript
import "dotenv/config";
import { Keypair } from "@solana/web3.js";
import { createRpc } from "@lightprotocol/stateless.js";
import {
    createMintInterface,
    createAtaInterface,
    getAssociatedTokenAddressInterface,
} from "@lightprotocol/compressed-token";
import {
    approveInterface,
    transferInterface,
    wrap,
} from "@lightprotocol/compressed-token/unified";
import {
    TOKEN_PROGRAM_ID,
    createAssociatedTokenAccount,
    mintTo,
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
    // Setup: Create SPL mint, fund, wrap into Light ATA (hot balance)
    const { mint } = await createMintInterface(
        rpc,
        payer,
        payer,
        null,
        9,
        undefined,
        undefined,
        TOKEN_PROGRAM_ID
    );
    const splAta = await createAssociatedTokenAccount(
        rpc,
        payer,
        mint,
        payer.publicKey,
        undefined,
        TOKEN_PROGRAM_ID
    );
    await mintTo(rpc, payer, mint, splAta, payer, 1_000_000_000);
    await createAtaInterface(rpc, payer, mint, payer.publicKey);
    const senderAta = getAssociatedTokenAddressInterface(
        mint,
        payer.publicKey
    );
    await wrap(
        rpc,
        payer,
        splAta,
        senderAta,
        payer,
        mint,
        BigInt(1_000_000_000)
    );

    const delegate = Keypair.generate();
    const recipient = Keypair.generate();

    // Approve delegate
    await approveInterface(
        rpc,
        payer,
        senderAta,
        mint,
        delegate.publicKey,
        500_000_000,
        payer
    );
    console.log("Approved delegate:", delegate.publicKey.toBase58());

    // Delegate transfers tokens on behalf of the owner
    const tx = await transferInterface(
        rpc,
        payer,
        senderAta,
        mint,
        recipient.publicKey,
        delegate,
        200_000_000,
        undefined,
        { owner: payer.publicKey }
    );

    console.log("Delegated transfer:", tx);
})();
```

## Links

- [Docs](https://zkcompression.com/light-token/cookbook/approve-revoke)
- [TS example](https://github.com/Lightprotocol/examples-light-token/blob/main/typescript-client/actions/delegate-transfer.ts)
