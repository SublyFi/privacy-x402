# SPL to Light comparison

Side-by-side mapping of SPL Token program operations to Light Token equivalents. Covers CPI instructions (`light_token::instruction::*Cpi`) and Anchor macros (`#[light_account(...)]`).

## CPI quick reference

| Operation | SPL CPI | Light CPI | Notes |
|-----------|---------|-----------|-------|
| Create mint | `initialize_mint` + `invoke` | `CreateMintCpi{...}.invoke()` | Chain `.rent_free()` for rent sponsorship |
| Create ATA | `create_associated_token_account` + `invoke` | `CreateAssociatedAccountCpi{...}.invoke()` | Chain `.rent_free()` + `.idempotent()` |
| Create token account | `initialize_account` + `invoke` | `CreateTokenAccountCpi{...}.invoke()` | Chain `.rent_free()` |
| Mint to | `mint_to` + `invoke` | `MintToCpi{...}.invoke()` | |
| Transfer checked | `transfer_checked` + `invoke` | `TransferCheckedCpi{...}.invoke()` | |
| Transfer interface | `transfer_checked` + `invoke` | `TransferInterfaceCpi::new(...).invoke()` | Cross-program routing (SPL, T22, Light) |
| Burn | `burn` + `invoke` | `BurnCpi{...}.invoke()` | |
| Freeze | `freeze_account` + `invoke` | `FreezeCpi{...}.invoke()` | |
| Thaw | `thaw_account` + `invoke` | `ThawCpi{...}.invoke()` | |
| Approve | `approve` + `invoke` | `ApproveCpi{...}.invoke()` | |
| Revoke | `revoke` + `invoke` | `RevokeCpi{...}.invoke()` | |
| Close | `close_account` + `invoke` | `CloseAccountCpi{...}.invoke()` | |

## Macro quick reference

| Pattern | Anchor | Light | Notes |
|---------|--------|-------|-------|
| Create mint | `#[account(init, mint::...)]` | `#[light_account(init, mint::...)]` | `UncheckedAccount` instead of `InterfaceAccount<Mint>` |
| Create mint with metadata | `#[account(init, ...)]` + separate metadata CPI | `#[light_account(init, mint::name=..., ...)]` | Inline metadata, no separate CPI |
| Create ATA | `#[account(init, associated_token::...)]` | `#[light_account(init, associated_token::...)]` | `UncheckedAccount` instead of `Account<TokenAccount>` |
| Create token account | `#[account(init, token::...)]` | `#[light_account(init, token::...)]` | `UncheckedAccount` instead of `Account<TokenAccount>` |
| Light-PDA | `#[program]` + `#[account]` + `#[derive(Accounts)]` | `#[light_program]` + `LightAccount` + `LightAccounts` | ~160x cheaper, no rent-exemption |

## CPI comparisons

### CreateMintCpi

```rust
// SPL
use spl_token::instruction::initialize_mint;

let ix = initialize_mint(
    &spl_token::id(),
    &mint.pubkey(),
    &mint_authority,
    Some(&freeze_authority),
    decimals,
)?;

invoke(&ix, &[mint, rent_sysvar])?;
```

```rust
// Light
use light_token::instruction::CreateMintCpi;

CreateMintCpi {
    mint_seed: mint_seed.clone(),
    authority: authority.clone(),
    payer: payer.clone(),
    address_tree: address_tree.clone(),
    output_queue: output_queue.clone(),
    compressible_config: compressible_config.clone(),
    mint: mint.clone(),
    rent_sponsor: rent_sponsor.clone(),
    system_accounts,
    cpi_context: None,
    cpi_context_account: None,
    params,
}
.invoke()?
```

### CreateAssociatedAccountCpi

```rust
// SPL
use spl_associated_token_account::instruction::create_associated_token_account;

let ix = create_associated_token_account(
    &payer.pubkey(),
    &owner.pubkey(),
    &mint,
    &spl_token::id(),
);

invoke(&ix, &[payer, owner, mint])?;
```

```rust
// Light — .rent_free() sponsors rent, .idempotent() skips if exists
use light_token::instruction::CreateAssociatedAccountCpi;

CreateAssociatedAccountCpi {
    payer: payer.clone(),
    owner: owner.clone(),
    mint: mint.clone(),
    ata: associated_token_account.clone(),
    bump,
}
.rent_free(
    compressible_config.clone(),
    rent_sponsor.clone(),
    system_program.clone(),
)
.invoke()?
```

### CreateTokenAccountCpi

```rust
// SPL
use spl_token::instruction::initialize_account;

let ix = initialize_account(
    &spl_token::id(),
    &account,
    &mint,
    &owner,
)?;

invoke(&ix, &[account, mint, owner])?;
```

```rust
// Light
use light_token::instruction::CreateTokenAccountCpi;

CreateTokenAccountCpi {
    payer: payer.clone(),
    account: account.clone(),
    mint: mint.clone(),
    owner,
}
.rent_free(
    compressible_config.clone(),
    rent_sponsor.clone(),
    system_program.clone(),
    token_program.key,
)
.invoke()?
```

### MintToCpi

```rust
// SPL
use spl_token::instruction::mint_to;

let ix = mint_to(
    &spl_token::id(),
    &mint,
    &destination,
    &mint_authority,
    &[],
    amount,
)?;

invoke(&ix, &[mint, destination, authority])?;
```

```rust
// Light
use light_token::instruction::MintToCpi;

MintToCpi {
    mint: mint.clone(),
    destination: destination.clone(),
    authority: authority.clone(),
    amount,
    fee_payer: None,
    max_top_up: None,
}
.invoke()?
```

### TransferCheckedCpi

```rust
// SPL
use spl_token::instruction::transfer_checked;

let ix = transfer_checked(
    &spl_token::id(),
    &source,
    &mint,
    &destination,
    &authority,
    &[],
    amount,
    decimals,
)?;

invoke(&ix, &[source, mint, destination, authority])?;
```

```rust
// Light
use light_token::instruction::TransferCheckedCpi;

TransferCheckedCpi {
    source: source.clone(),
    destination: destination.clone(),
    mint: mint.clone(),
    authority: authority.clone(),
    amount,
    decimals,
}
.invoke()?
```

### TransferInterfaceCpi

Routes transfers across SPL, Token 2022, and Light Token accounts automatically.

```rust
// SPL
use spl_token::instruction::transfer_checked;

let ix = transfer_checked(
    &spl_token::id(),
    &source,
    &mint,
    &destination,
    &authority,
    &[],
    amount,
    decimals,
)?;

invoke(&ix, &[source, mint, destination, authority])?;
```

```rust
// Light
use light_token::instruction::TransferInterfaceCpi;

TransferInterfaceCpi::new(
    amount,
    decimals,
    source.clone(),
    destination.clone(),
    authority.clone(),
    payer.clone(),
    light_token_authority.clone(),
    system_program.clone(),
)
.invoke()?;
```

### BurnCpi

```rust
// SPL
use spl_token::instruction::burn;

let ix = burn(
    &spl_token::id(),
    &source,
    &mint,
    &authority,
    &[],
    amount,
)?;

invoke(&ix, &[source, mint, authority])?;
```

```rust
// Light
use light_token::instruction::BurnCpi;

BurnCpi {
    source: source.clone(),
    mint: mint.clone(),
    authority: authority.clone(),
    amount,
}
.invoke()?
```

### FreezeCpi

```rust
// SPL
use spl_token::instruction::freeze_account;

let ix = freeze_account(
    &spl_token::id(), &account, &mint, &freeze_authority, &[],
)?;
invoke(&ix, &[account, mint, freeze_authority])?;
```

```rust
// Light
use light_token::instruction::FreezeCpi;

FreezeCpi {
    token_account: token_account.clone(),
    mint: mint.clone(),
    freeze_authority: freeze_authority.clone(),
}
.invoke()?
```

### ThawCpi

```rust
// SPL
use spl_token::instruction::thaw_account;

let ix = thaw_account(
    &spl_token::id(), &account, &mint, &freeze_authority, &[],
)?;
invoke(&ix, &[account, mint, freeze_authority])?;
```

```rust
// Light
use light_token::instruction::ThawCpi;

ThawCpi {
    token_account: token_account.clone(),
    mint: mint.clone(),
    freeze_authority: freeze_authority.clone(),
}
.invoke()?
```

### ApproveCpi

```rust
// SPL
use spl_token::instruction::approve;

let ix = approve(
    &spl_token::id(), &source, &delegate, &owner, &[], amount,
)?;
invoke(&ix, &[source, delegate, owner])?;
```

```rust
// Light
use light_token::instruction::ApproveCpi;

ApproveCpi {
    token_account: token_account.clone(),
    delegate: delegate.clone(),
    owner: owner.clone(),
    amount,
}
.invoke()?
```

### RevokeCpi

```rust
// SPL
use spl_token::instruction::revoke;

let ix = revoke(
    &spl_token::id(), &source, &owner, &[],
)?;
invoke(&ix, &[source, owner])?;
```

```rust
// Light
use light_token::instruction::RevokeCpi;

RevokeCpi {
    token_account: token_account.clone(),
    owner: owner.clone(),
}
.invoke()?
```

### CloseAccountCpi

```rust
// SPL
use spl_token::instruction::close_account;

let ix = close_account(
    &spl_token::id(), &account, &destination, &owner, &[],
)?;
invoke(&ix, &[account, destination, owner])?;
```

```rust
// Light
use light_token::instruction::CloseAccountCpi;

CloseAccountCpi {
    account: account.clone(),
    destination: destination.clone(),
    authority: authority.clone(),
}
.invoke()?
```

## Anchor macro comparisons

### Create mint

```rust
// Anchor
#[account(
    init,
    payer = fee_payer,
    mint::decimals = 9,
    mint::authority = fee_payer,
)]
pub mint: InterfaceAccount<'info, Mint>,
```

```rust
// Light — uses UncheckedAccount, validated by light-token CPI
#[light_account(init,
    mint::signer = mint_signer,
    mint::authority = fee_payer,
    mint::decimals = 9,
    mint::seeds = &[MINT_SIGNER_SEED, self.authority.to_account_info().key.as_ref()],
    mint::bump = params.mint_signer_bump
)]
pub mint: UncheckedAccount<'info>,
```

### Create mint with metadata

```rust
// Anchor — requires separate metadata CPI
#[account(
    init,
    payer = fee_payer,
    mint::decimals = 9,
    mint::authority = fee_payer,
    extensions::metadata_pointer::authority = fee_payer,
    extensions::metadata_pointer::metadata_address = mint_account,
)]
pub mint_account: InterfaceAccount<'info, Mint>,

// Metadata requires a separate CPI:
token_metadata_initialize(
    cpi_ctx,
    params.name,
    params.symbol,
    params.uri,
)?;
```

```rust
// Light — metadata declared inline, no separate CPI
#[light_account(init,
    mint::signer = mint_signer,
    mint::authority = fee_payer,
    mint::decimals = 9,
    mint::seeds = &[MINT_SIGNER_SEED, self.authority.to_account_info().key.as_ref()],
    mint::bump = params.mint_signer_bump,
    mint::name = params.name.clone(),
    mint::symbol = params.symbol.clone(),
    mint::uri = params.uri.clone(),
    mint::update_authority = authority
)]
pub mint: UncheckedAccount<'info>,
```

### Create associated token account

```rust
// Anchor
#[account(
    init,
    payer = fee_payer,
    associated_token::mint = mint,
    associated_token::authority = owner,
)]
pub ata: Account<'info, TokenAccount>,
```

```rust
// Light
#[light_account(
    init,
    associated_token::authority = ata_owner,
    associated_token::mint = ata_mint,
    associated_token::bump = params.ata_bump
)]
pub ata: UncheckedAccount<'info>,
```

### Create token account (vault)

```rust
// Anchor
#[account(
    init,
    payer = fee_payer,
    token::mint = mint,
    token::authority = authority,
)]
pub vault: Account<'info, TokenAccount>,
```

```rust
// Light
#[account(
    mut,
    seeds = [VAULT_SEED, mint.key().as_ref()],
    bump,
)]
#[light_account(init,
    token::authority = [VAULT_SEED, self.mint.key()],
    token::mint = mint,
    token::owner = vault_authority,
    token::bump = params.vault_bump
)]
pub vault: UncheckedAccount<'info>,
```

### Light-PDA (rent-free program accounts)

```rust
// Anchor
#[program]
pub mod my_program {
    // instruction logic unchanged
}

#[account]
pub struct MyState {
    pub authority: Pubkey,
    pub data: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + MyState::INIT_SPACE,
    )]
    pub state: Account<'info, MyState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

```rust
// Light — ~160x cheaper, no rent-exemption
use light_account::{
    CompressionInfo, LightAccount, LightAccounts,
    CreateAccountsProof, derive_light_cpi_signer,
    light_program, CpiSigner, LightDiscriminator,
};

#[light_program]
#[program]
pub mod my_program {
    // instruction logic unchanged
}

#[derive(LightAccount, LightDiscriminator)]
pub struct MyState {
    pub compression_info: CompressionInfo,
    pub authority: Pubkey,
    pub data: u64,
}

#[derive(LightAccounts)]
pub struct Initialize<'info> {
    #[light_account(init)]
    pub state: UncheckedAccount<'info>,
    #[account(mut)]
    pub pda_rent_sponsor: AccountInfo<'info>,
    // ...
}
```

## Links

- [Migration reference](https://zkcompression.com/api-reference/solana-to-light-comparison)
- [CPI examples](https://github.com/Lightprotocol/examples-light-token/tree/main/program-examples/anchor/basic-instructions)
- [Macro examples](https://github.com/Lightprotocol/examples-light-token/tree/main/programs/anchor/basic-macros)
- [light-token docs.rs](https://docs.rs/light-token/latest/light_token/)
