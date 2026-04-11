# Token 2022 extensions overview

Create Token 2022 mints with extensions and register them for use with Light Token. Once registered, use the same Light Token APIs (`transferInterface`, `wrap`, `unwrap`) as any other token.

## Supported extensions

| Extension | Restriction | Docs |
|-----------|-------------|------|
| MetadataPointer + TokenMetadata | — | [Docs](https://www.zkcompression.com/light-token/extensions/metadata-and-metadata-pointer) |
| TransferFeeConfig | Fees must be zero | [Docs](https://www.zkcompression.com/light-token/extensions/transfer-fees) |
| TransferHook | `program_id` must be nil | [Docs](https://www.zkcompression.com/light-token/extensions/transfer-hook) |
| InterestBearingConfig | — | [Docs](https://www.zkcompression.com/light-token/extensions/interest-bearing-tokens) |
| DefaultAccountState | Set `compression_only` flag on token accounts | [Docs](https://www.zkcompression.com/light-token/extensions/default-account-state) |
| PermanentDelegate | Set `compression_only` flag on token accounts | [Docs](https://www.zkcompression.com/light-token/extensions/permanent-delegate) |
| MintCloseAuthority | Set `compression_only` flag on token accounts | [Docs](https://www.zkcompression.com/light-token/extensions/close-mint) |
| GroupPointer + TokenGroup + GroupMemberPointer + TokenGroupMember | — | [Docs](https://www.zkcompression.com/light-token/extensions/token-groups-and-members) |
| PausableConfig | Set `compression_only` flag on token accounts | [Docs](https://www.zkcompression.com/light-token/extensions/pausable-mint) |
| ConfidentialTransferMint | Initialized but not enabled | [Docs](https://www.zkcompression.com/light-token/extensions/confidential-transfer) |

## Standard flow

1. Calculate space for mint account with the extension(s)
2. Get rent-exempt balance for that space
3. Create the mint account (`SystemProgram.createAccount`)
4. Initialize the extension(s) (must come before mint init)
5. Initialize the mint (`createInitializeMint2Instruction`)
6. Register the SPL interface PDA (`LightTokenProgram.createSplInterface`)

## Not supported

Scaled UI Amount, Non-Transferable Tokens, Memo Transfer, Immutable Owner, CPI Guard.

## Links

- [Docs overview](https://www.zkcompression.com/light-token/extensions/overview)
- [GitHub examples](https://github.com/Lightprotocol/examples-light-token/tree/main/extensions)
