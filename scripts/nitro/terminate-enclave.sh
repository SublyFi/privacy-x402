#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 0 ]]; then
  NO_DNA=1 nitro-cli terminate-enclave --enclave-name "$1"
else
  NO_DNA=1 nitro-cli terminate-enclave --all
fi
