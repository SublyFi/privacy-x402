# Transfer fees

Create a Token 2022 mint with the TransferFeeConfig extension and register it with Light Token.

**Restriction**: Fees must be zero.

## TypeScript

```typescript
import "dotenv/config";
import {
    Keypair,
    SystemProgram,
    Transaction,
    sendAndConfirmTransaction,
} from "@solana/web3.js";
import { createRpc } from "@lightprotocol/stateless.js";
import { LightTokenProgram } from "@lightprotocol/compressed-token";
import {
    TOKEN_2022_PROGRAM_ID,
    getMintLen,
    createInitializeMint2Instruction,
    ExtensionType,
    createInitializeTransferFeeConfigInstruction,
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
    const mintKeypair = Keypair.generate();
    const decimals = 9;

    // Calculate space for mint + TransferFeeConfig extension
    const mintLen = getMintLen([ExtensionType.TransferFeeConfig]);
    const rentExemptBalance =
        await rpc.getMinimumBalanceForRentExemption(mintLen);

    // Instruction 1: Create account
    const createAccountIx = SystemProgram.createAccount({
        fromPubkey: payer.publicKey,
        lamports: rentExemptBalance,
        newAccountPubkey: mintKeypair.publicKey,
        programId: TOKEN_2022_PROGRAM_ID,
        space: mintLen,
    });

    // Instruction 2: Initialize TransferFeeConfig with zero fees
    // Light Token requires fees to be zero
    const initTransferFeeIx = createInitializeTransferFeeConfigInstruction(
        mintKeypair.publicKey,
        payer.publicKey, // transfer fee config authority
        payer.publicKey, // withdraw withheld authority
        0,               // fee basis points (must be zero)
        BigInt(0),       // maximum fee (must be zero)
        TOKEN_2022_PROGRAM_ID
    );

    // Instruction 3: Initialize mint
    const initMintIx = createInitializeMint2Instruction(
        mintKeypair.publicKey,
        decimals,
        payer.publicKey, // mint authority
        null, // freeze authority
        TOKEN_2022_PROGRAM_ID
    );

    // Instruction 4: Create SPL interface PDA
    // Holds Token-2022 tokens when wrapped to light-token
    const createSplInterfaceIx = await LightTokenProgram.createSplInterface({
        feePayer: payer.publicKey,
        mint: mintKeypair.publicKey,
        tokenProgramId: TOKEN_2022_PROGRAM_ID,
    });

    const tx = new Transaction().add(
        createAccountIx,
        initTransferFeeIx,
        initMintIx,
        createSplInterfaceIx
    );

    const signature = await sendAndConfirmTransaction(rpc, tx, [
        payer,
        mintKeypair,
    ]);

    console.log("Mint:", mintKeypair.publicKey.toBase58());
    console.log("Tx:", signature);
})();
```

## Links

- [Docs](https://www.zkcompression.com/light-token/extensions/transfer-fees)
- [GitHub example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/transfer-fees.ts)
