# Token 2022 extensions

Create Token 2022 mints with extensions and register them for use with Light Token.

1. Create a Token 2022 mint with one or more extensions
2. Register an interface PDA to hold balances from that mint in Light Token accounts
3. Use the same Light Token APIs (`transferInterface`, `wrap`, `unwrap`) as any other token

> This skill includes references for payment-relevant extensions. For the complete set, see the `light-token-client` skill.

## Supported extensions

| Extension | Restriction | Example | Docs |
|-----------|-------------|---------|------|
| MetadataPointer + TokenMetadata | -- | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/metadata-and-metadata-pointer.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/metadata-and-metadata-pointer) |
| TransferFeeConfig | Fees must be zero | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/transfer-fees.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/transfer-fees) |
| TransferHook | `program_id` must be nil | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/transfer-hook.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/transfer-hook) |
| InterestBearingConfig | -- | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/interest-bearing-tokens.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/interest-bearing-tokens) |
| DefaultAccountState | Set `compression_only` flag on token accounts | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/default-account-state.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/default-account-state) |
| PermanentDelegate | Set `compression_only` flag on token accounts | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/permanent-delegate.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/permanent-delegate) |
| MintCloseAuthority | Set `compression_only` flag on token accounts | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/close-mint.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/close-mint) |
| GroupPointer + TokenGroup + GroupMemberPointer + TokenGroupMember | -- | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/token-groups-and-members.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/token-groups-and-members) |
| Pausable | Set `compression_only` flag on token accounts | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/pausable-mint.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/pausable-mint) |
| ConfidentialTransferMint | Initialized but not enabled | [Example](https://github.com/Lightprotocol/examples-light-token/blob/main/extensions/confidential-transfer.ts) | [Docs](https://www.zkcompression.com/light-token/extensions/confidential-transfer) |

## Creation flow

```typescript
// 1. Calculate space for mint + extension(s)
const mintLen = getMintLen([ExtensionType.YourExtension]);
const rentExemptBalance = await rpc.getMinimumBalanceForRentExemption(mintLen);

// 2. Create account
const createAccountIx = SystemProgram.createAccount({
    fromPubkey: payer.publicKey,
    lamports: rentExemptBalance,
    newAccountPubkey: mintKeypair.publicKey,
    programId: TOKEN_2022_PROGRAM_ID,
    space: mintLen,
});

// 3. Initialize extension (before mint init)
const initExtensionIx = createInitializeYourExtensionInstruction(/* ... */);

// 4. Initialize mint
const initMintIx = createInitializeMint2Instruction(
    mintKeypair.publicKey,
    decimals,
    payer.publicKey,
    null,
    TOKEN_2022_PROGRAM_ID,
);

// 5. Register interface PDA with Light Token
const createSplInterfaceIx = await LightTokenProgram.createSplInterface({
    feePayer: payer.publicKey,
    mint: mintKeypair.publicKey,
    tokenProgramId: TOKEN_2022_PROGRAM_ID,
});

// 6. Send transaction
const tx = new Transaction().add(
    createAccountIx,
    initExtensionIx,
    initMintIx,
    createSplInterfaceIx,
);
```

## Not supported

Scaled UI Amount, Non-Transferable Tokens, Memo Transfer, Immutable Owner, CPI Guard.

## Links

- [Extensions overview](https://www.zkcompression.com/light-token/extensions/overview)
- [GitHub examples](https://github.com/Lightprotocol/examples-light-token/tree/main/extensions)
