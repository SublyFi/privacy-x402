# Production readiness

Non-exhaustive checklist for deploying Light Token payment flows to production.

## RPC infrastructure

Light Token requires a Photon-compatible RPC endpoint for cold account lookups and balance queries.

| Provider | Photon support | Notes |
|:---------|:---------------|:------|
| [Helius](https://helius.dev) | Yes | Recommended. Maintains the Photon indexer. |
| [Triton](https://triton.one) | Yes | Alternative provider. |

## Transaction landing

Light Token transactions follow standard Solana patterns for landing:

- **Priority fees**: Use `ComputeBudgetProgram.setComputeUnitPrice()` to increase transaction priority.
- **Compute units**: Set appropriate compute unit limits with `ComputeBudgetProgram.setComputeUnitLimit()`.
- **Retry logic**: Implement retries with fresh blockhashes for failed transactions.

## Confirmation levels

| Level | When to use |
|:------|:------------|
| `processed` | Fastest. Use for UI updates. Not guaranteed to finalize. |
| `confirmed` | Recommended for most payment flows. Confirmed by supermajority of validators. |
| `finalized` | Highest certainty. Use for high-value transfers or irreversible actions. |

## Error handling

Handle both standard Solana errors and Light Token-specific scenarios:

- **Cold account load failures**: Retry the load if the indexer returns stale data.
- **Associated token account creation**: Idempotent — safe to retry.
- **Rent top-up failures**: Ensure the fee payer has sufficient SOL balance. See [gasless-transactions.md](gasless-transactions.md) for cost breakdown.
- **Transaction size limits**: If `TransactionInstruction[][]` returns multiple batches, process them sequentially.

## Fee sponsorship

Set your application as the fee payer so users never interact with SOL:

1. **Rent top-ups and transaction fees**: Set `payer` parameter on Light Token instructions. See [gasless-transactions.md](gasless-transactions.md).
2. **Rent sponsor funding**: Ensure the rent sponsor PDA is funded.

## Pre-launch checklist

- [ ] Photon-compatible RPC endpoint configured and tested
- [ ] Fee payer wallet funded with sufficient SOL
- [ ] Error handling covers load failures, tx size limits, and retries
- [ ] Confirmation level appropriate for your use case
- [ ] Address verification implemented (see [verify-address.md](verify-address.md))
- [ ] Wrap/unwrap flows tested for SPL / Token 2022 interoperability (if applicable)

## Source

- [Production readiness docs](https://zkcompression.com/light-token/payments/production-readiness)
