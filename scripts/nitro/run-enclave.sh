#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH="${1:-/etc/subly402/run-enclave.json}"
NO_DNA=1 nitro-cli run-enclave --config "$CONFIG_PATH"
