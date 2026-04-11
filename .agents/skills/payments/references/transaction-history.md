# Transaction history

```typescript
const result = await rpc.getSignaturesForOwnerInterface(owner);

console.log(result.signatures); // Merged + deduplicated
console.log(result.solana); // On-chain txs only
console.log(result.compressed); // Compressed txs only
```

Use `getSignaturesForAddressInterface(address)` for address-specific rather than owner-wide history.

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [get-history.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/get-history.ts) | List transactions (merged on-chain + compressed). | `getSignaturesForOwnerInterface` |

## Source

- [Verify payments docs](https://zkcompression.com/light-token/payments/accept-payments/verify-payments)
- [GitHub example](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/get-history.ts)
