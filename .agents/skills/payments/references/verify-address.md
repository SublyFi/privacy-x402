# Verify address

Verify recipient addresses before sending payments. Address validation prevents sending tokens to invalid or unexpected account types.

Before sending a payment:

1. Check if the address is on-curve (wallet) or off-curve (PDA).
2. If the address has an on-chain account, check the account owner and type.
3. For Light Token, derive the associated token account to verify it matches the expected mint.

```typescript
import {
  getAssociatedTokenAddressInterface,
  getAtaInterface,
} from "@lightprotocol/compressed-token/unified";

// Derive the expected associated token account for this recipient and mint
const expectedAta = getAssociatedTokenAddressInterface(mint, recipientWallet);

// Check if the account exists and is active
try {
  const account = await getAtaInterface(rpc, expectedAta, recipientWallet, mint);
  console.log("Account exists, balance:", account.parsed.amount);
} catch {
  console.log("Account does not exist yet — will be created on first transfer");
}
```

> Use `getAssociatedTokenAddressInterface()` instead of SPL's `getAssociatedTokenAddressSync()` to derive Light Token associated token account addresses.

> When you send a payment with `transferInterface()` or `createTransferInterfaceInstructions()`, the SDK automatically creates the recipient's associated token account if it doesn't exist. Address verification is a safety check, not a prerequisite.

## Examples

| File | Description | Key function |
|:-----|:------------|:-------------|
| [verify-address.ts](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/verify-address.ts) | Check if ATA exists for a recipient. | `getAtaInterface` |

## Source

- [Verify payments docs](https://zkcompression.com/light-token/payments/accept-payments/verify-payments)
- [GitHub example](https://github.com/Lightprotocol/examples-light-token/blob/main/toolkits/payments/verify/verify-address.ts)
