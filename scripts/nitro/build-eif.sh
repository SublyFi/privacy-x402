#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

ENV_FILE="${SUBLY402_NITRO_ENCLAVE_ENV:-$ROOT/infra/nitro/generated/enclave.env}"
TLS_CERT_SOURCE="${SUBLY402_ENCLAVE_TLS_CERT_SOURCE:-}"
TLS_KEY_SOURCE="${SUBLY402_ENCLAVE_TLS_KEY_SOURCE:-}"
TLS_CA_SOURCE="${SUBLY402_ENCLAVE_TLS_CA_SOURCE:-}"
EIF_OUTPUT="${SUBLY402_NITRO_EIF_OUTPUT:-$ROOT/infra/nitro/generated/subly402-enclave.eif}"
MEASUREMENTS_OUTPUT="${SUBLY402_EIF_MEASUREMENTS_FILE:-$ROOT/infra/nitro/generated/eif-measurements.json}"
DOCKER_URI="${SUBLY402_NITRO_DOCKER_URI:-subly402-enclave:devnet}"
SIGNING_PRIVATE_KEY="${SUBLY402_NITRO_SIGNING_PRIVATE_KEY:-}"
SIGNING_CERT="${SUBLY402_EIF_SIGNING_CERT_PATH:-}"
STAGE_DIR="$ROOT/.nitro-build/enclave"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing enclave env file: $ENV_FILE" >&2
  exit 1
fi
if [[ -z "$TLS_CERT_SOURCE" || -z "$TLS_KEY_SOURCE" ]]; then
  echo "SUBLY402_ENCLAVE_TLS_CERT_SOURCE and SUBLY402_ENCLAVE_TLS_KEY_SOURCE must be set" >&2
  exit 1
fi

NO_DNA=1 cargo build --release -p subly402-enclave

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/bin" "$STAGE_DIR/etc/subly402" "$STAGE_DIR/tls"
cp "$ROOT/infra/nitro/enclave/Dockerfile" "$STAGE_DIR/Dockerfile"
cp "$ROOT/infra/nitro/enclave/entrypoint.sh" "$STAGE_DIR/entrypoint.sh"
cp "$ROOT/target/release/subly402-enclave" "$STAGE_DIR/bin/subly402-enclave"
cp "$ENV_FILE" "$STAGE_DIR/etc/subly402/enclave.env"
cp "$TLS_CERT_SOURCE" "$STAGE_DIR/tls/server.crt"
cp "$TLS_KEY_SOURCE" "$STAGE_DIR/tls/server.key"
if [[ -n "$TLS_CA_SOURCE" ]]; then
  cp "$TLS_CA_SOURCE" "$STAGE_DIR/tls/client-ca.crt"
fi

mkdir -p "$(dirname "$EIF_OUTPUT")" "$(dirname "$MEASUREMENTS_OUTPUT")"

BUILD_ARGS=(
  build-enclave
  --docker-dir "$STAGE_DIR"
  --docker-uri "$DOCKER_URI"
  --output-file "$EIF_OUTPUT"
)
if [[ -n "$SIGNING_PRIVATE_KEY" || -n "$SIGNING_CERT" ]]; then
  if [[ -z "$SIGNING_PRIVATE_KEY" || -z "$SIGNING_CERT" ]]; then
    echo "SUBLY402_NITRO_SIGNING_PRIVATE_KEY and SUBLY402_EIF_SIGNING_CERT_PATH must be set together" >&2
    exit 1
  fi
  BUILD_ARGS+=(--private-key "$SIGNING_PRIVATE_KEY" --signing-certificate "$SIGNING_CERT")
fi

NO_DNA=1 nitro-cli "${BUILD_ARGS[@]}"
NO_DNA=1 nitro-cli describe-eif --eif-path "$EIF_OUTPUT" > "$MEASUREMENTS_OUTPUT"

echo "Built EIF: $EIF_OUTPUT"
echo "Saved measurements: $MEASUREMENTS_OUTPUT"
