#!/usr/bin/env bash
set -euo pipefail

# Decrypt .env.enc to runtime .env
# Usage: bash scripts/decrypt-env.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENC_FILE="$PROJECT_DIR/.env.enc"
RUNTIME_ENV="$PROJECT_DIR/.openclaw/.env"

# --- Derive key (same as encrypt) ---
get_machine_key() {
  local uuid=""
  if [[ "$(uname)" == "Darwin" ]]; then
    uuid=$(ioreg -d2 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}')
  elif [[ -f /etc/machine-id ]]; then
    uuid=$(cat /etc/machine-id)
  elif [[ -f /sys/class/dmi/id/product_uuid ]]; then
    uuid=$(cat /sys/class/dmi/id/product_uuid)
  fi

  if [[ -z "$uuid" ]]; then
    echo "ERROR: Cannot determine machine UUID." >&2
    exit 1
  fi

  echo -n "$uuid" | openssl dgst -sha256 -binary | xxd -p -c 64
}

if [[ ! -f "$ENC_FILE" ]]; then
  echo "ERROR: $ENC_FILE not found. Run encrypt-env.sh first."
  exit 1
fi

KEY=$(get_machine_key)

openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 \
  -in "$ENC_FILE" \
  -out "$RUNTIME_ENV" \
  -pass "pass:$KEY"

chmod 600 "$RUNTIME_ENV"
echo "Decrypted to: $RUNTIME_ENV (mode 600)"
