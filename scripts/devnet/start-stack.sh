#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [[ -f ./.env.devnet.local ]]; then
  source ./.env.devnet.local
fi

if [[ ! -f ./.env.devnet.generated ]]; then
  echo ".env.devnet.generated is missing. Run bootstrap first." >&2
  exit 1
fi

source ./.env.devnet.generated

mkdir -p data/logs

if [[ ! -x target/debug/subly402-watchtower || ! -x target/debug/subly402-enclave ]]; then
  NO_DNA=1 cargo build -p subly402-watchtower -p subly402-enclave
fi

if [[ -f data/watchtower-devnet.pid ]] && kill -0 "$(cat data/watchtower-devnet.pid)" 2>/dev/null; then
  echo "watchtower already running"
else
  rm -f data/watchtower-devnet.pid
  NO_DNA=1 nohup target/debug/subly402-watchtower > data/logs/watchtower-devnet.log 2>&1 < /dev/null &
  echo $! > data/watchtower-devnet.pid
fi

if [[ -f data/enclave-devnet.pid ]] && kill -0 "$(cat data/enclave-devnet.pid)" 2>/dev/null; then
  echo "enclave already running"
else
  rm -f data/enclave-devnet.pid
  NO_DNA=1 nohup target/debug/subly402-enclave > data/logs/enclave-devnet.log 2>&1 < /dev/null &
  echo $! > data/enclave-devnet.pid
fi

node scripts/devnet/status.js --wait
