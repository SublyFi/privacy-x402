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
- `provider/register`
- `verify`
- `settle`
- `fire-batch`

```bash
yarn devnet:smoke
```

## Stop local processes

```bash
yarn devnet:stop
```
