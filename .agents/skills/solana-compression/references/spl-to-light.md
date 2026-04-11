# SPL to Light comparison

PDA and account pattern comparison between standard Anchor and Light-PDA (compressed accounts).

## Quick reference

| Concept | Standard Solana/Anchor | Light | Notes |
|---------|----------------------|-------|-------|
| Account declaration | `#[account]` | `#[derive(LightAccount, LightDiscriminator)]` + `CompressionInfo` field | ~160x cheaper |
| Accounts struct | `#[derive(Accounts)]` | `#[derive(LightAccounts)]` | |
| Program attribute | `#[program]` | `#[light_program]` above `#[program]` | |
| Init account | `#[account(init, payer, space)]` | `#[light_account(init)]` | No space calculation needed |
| Account type | `Account<'info, T>` | `UncheckedAccount<'info>` | Validated by Light System CPI |
| Rent cost | ~0.00203 SOL per account | ~0.0000128 SOL | No rent-exemption required |

## Counter program comparison

### Standard Anchor

```rust
use anchor_lang::prelude::*;

declare_id!("...");

#[program]
pub mod counter {
    use super::*;

    pub fn create(ctx: Context<Create>) -> Result<()> {
        ctx.accounts.counter.authority = ctx.accounts.authority.key();
        ctx.accounts.counter.count = 0;
        Ok(())
    }

    pub fn increment(ctx: Context<Increment>) -> Result<()> {
        ctx.accounts.counter.count += 1;
        Ok(())
    }
}

#[account]
pub struct Counter {
    pub authority: Pubkey,
    pub count: u64,
}

#[derive(Accounts)]
pub struct Create<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + Counter::INIT_SPACE,
        seeds = [b"counter", authority.key().as_ref()],
        bump,
    )]
    pub counter: Account<'info, Counter>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Increment<'info> {
    #[account(
        mut,
        seeds = [b"counter", authority.key().as_ref()],
        bump,
    )]
    pub counter: Account<'info, Counter>,
    pub authority: Signer<'info>,
}
```

### Light-PDA

```rust
use anchor_lang::prelude::*;
use light_account::{
    CompressionInfo, LightAccount, LightAccounts,
    CreateAccountsProof, derive_light_cpi_signer,
    light_program, CpiSigner, LightDiscriminator,
};

declare_id!("...");

pub const LIGHT_CPI_SIGNER: CpiSigner =
    derive_light_cpi_signer!("YOUR_PROGRAM_ID");

#[light_program]
#[program]
pub mod counter {
    use super::*;

    pub fn create<'info>(
        ctx: Context<'_, '_, '_, 'info, Create<'info>>,
        params: CreateParams,
    ) -> Result<()> {
        ctx.accounts.counter.authority = ctx.accounts.authority.key();
        ctx.accounts.counter.count = params.count;
        Ok(())
    }
}

#[derive(LightAccount, LightDiscriminator)]
pub struct Counter {
    pub compression_info: CompressionInfo,
    pub authority: Pubkey,
    pub count: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct CreateParams {
    pub create_accounts_proof: CreateAccountsProof,
    pub count: u64,
}

#[derive(Accounts, LightAccounts)]
#[instruction(params: CreateParams)]
pub struct Create<'info> {
    #[account(
        init,
        payer = fee_payer,
        space = 8 + Counter::INIT_SPACE,
        seeds = [b"counter", owner.key().as_ref()],
        bump,
    )]
    #[light_account(init)]
    pub counter: Account<'info, Counter>,

    pub owner: Signer<'info>,

    #[account(mut)]
    pub fee_payer: Signer<'info>,

    /// Validated by Light System CPI
    pub compression_config: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}
```

## Key differences

1. **State struct**: Add `compression_info: CompressionInfo` field and derive `LightAccount` + `LightDiscriminator`.
2. **Accounts struct**: Derive `LightAccounts` alongside `Accounts`. Add `#[light_account(init)]` to init accounts.
3. **Program module**: Stack `#[light_program]` above `#[program]`.
4. **`LIGHT_CPI_SIGNER`**: Required constant derived from the program ID.
5. **Params struct**: Must use single params struct with `CreateAccountsProof` field.
6. **Explicit lifetimes**: Use `Context<'_, '_, '_, 'info, T<'info>>` on instruction handlers.
7. **No space calculation**: Light handles storage allocation. Standard `space` is still needed for the Anchor PDA itself.
8. **Infrastructure accounts**: Add `compression_config: AccountInfo<'info>` for PDA accounts.

## Cost comparison

| Account size | Anchor | Light-PDA |
|-------------|--------|-----------|
| 128 bytes | ~1,100,000 lamports (~0.00113 SOL) | ~5,000 lamports (~0.000005 SOL) |
| 256 bytes | ~2,000,000 lamports (~0.00203 SOL) | ~12,800 lamports (~0.0000128 SOL) |

## Links

- [Migration reference](https://zkcompression.com/api-reference/solana-to-light-comparison)
- [Light-PDA guide](https://zkcompression.com/pda/light-pda/overview)
- [Counter example (macro)](https://github.com/Lightprotocol/examples-light-token/tree/main/programs/anchor/basic-macros/counter)
- [Account comparison](https://github.com/Lightprotocol/program-examples/tree/main/account-comparison)
