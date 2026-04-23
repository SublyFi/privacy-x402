#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-/etc/subly402/watchtower.env}"
BIN_PATH="${SUBLY402_WATCHTOWER_BIN_PATH:-/opt/subly402/bin/subly402-watchtower}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

exec "$BIN_PATH"
