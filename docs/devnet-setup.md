# Devnet Setup

Local Devnet settings live in `.env.devnet.local`, which is ignored by git.

## One-time RPC setup

```bash
source ./.env.devnet.local
solana config set --url "$A402_SOLANA_RPC_URL" --ws "$A402_SOLANA_WS_URL" --keypair "$ANCHOR_WALLET"
```

## Deploy the program

```bash
NO_DNA=1 anchor build
NO_DNA=1 anchor deploy \
  --provider.cluster "$A402_SOLANA_RPC_URL" \
  --provider.wallet "$ANCHOR_WALLET"
```

## Bootstrap the vault

This creates a Devnet USDC mint if needed, derives the vault PDAs, initializes
the on-chain vault, and writes reusable runtime values to:

- `data/devnet-state.json`
- `.env.devnet.generated`

```bash
yarn devnet:bootstrap
```

## Start local watchtower + enclave against Devnet

```bash
yarn devnet:start
```

## Check status

```bash
yarn devnet:status
```

## Run an end-to-end smoke test

This executes:

- client funding
- mint to client ATA
- on-chain `deposit`
- authenticated `provider/register`
- `verify`
- `settle`
- authenticated `fire-batch`

Set `SUBLY402_ADMIN_AUTH_TOKEN` in `.env.devnet.local` when
`SUBLY402_ENABLE_PROVIDER_REGISTRATION_API=1` or `SUBLY402_ENABLE_ADMIN_API=1`.
Single-provider smoke tests that need immediate on-chain payout must also set
`SUBLY402_ALLOW_ADMIN_PRIVACY_BYPASS_BATCH=1`; keep it unset or `0` for public
runtime.

```bash
yarn devnet:smoke
```

## Stop local processes

```bash
yarn devnet:stop
```
