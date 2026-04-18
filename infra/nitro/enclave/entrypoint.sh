#!/usr/bin/env bash
set -euo pipefail

if [[ -f /etc/a402/enclave.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source /etc/a402/enclave.env
  set +a
fi

exec /opt/a402/bin/a402-enclave
