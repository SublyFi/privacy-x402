# Show balance

`getAtaInterface` returns a unified balance aggregating Light Token (hot + cold), SPL, and Token 2022 sources in `parsed.amount`.

```typescript
import {
  getAssociatedTokenAddressInterface,
  getAtaInterface,
} from "@lightprotocol/compressed-token";

const ata = getAssociatedTokenAddressInterface(mint, owner);
const account = await getAtaInterface(rpc, ata, owner, mint);

console.log(account.parsed.amount);
```

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [get-balance.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/get-balance.ts) | Check token balance for an account. | `getAtaInterface` |

## Source

- [Verify payments docs](https://zkcompression.com/light-token/payments/accept-payments/verify-payments)
- [GitHub example](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/get-balance.ts)
