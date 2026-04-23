#!/usr/bin/env bash
set -euo pipefail

if [[ -f /etc/subly402/enclave.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source /etc/subly402/enclave.env
  set +a
fi

exec /opt/subly402/bin/subly402-enclave
