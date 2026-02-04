#!/usr/bin/env bash
set -euo pipefail

# AES-256-CBC encrypt .env.plain using machine-derived key
# Usage: bash scripts/encrypt-env.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PLAIN_FILE="$PROJECT_DIR/.env.plain"
ENC_FILE="$PROJECT_DIR/.env.enc"
RUNTIME_ENV="$PROJECT_DIR/.openclaw/.env"

# --- Derive encryption key from machine UUID ---
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
    echo "ERROR: Cannot determine machine UUID for key derivation." >&2
    exit 1
  fi

  # Derive a 256-bit key using PBKDF2
  echo -n "$uuid" | openssl dgst -sha256 -binary | xxd -p -c 64
}

# --- Validate plaintext file ---
if [[ ! -f "$PLAIN_FILE" ]]; then
  echo "ERROR: $PLAIN_FILE not found."
  echo "Copy .env.template to .env.plain and fill in your credentials."
  exit 1
fi

# Check required vars are set
missing=()
while IFS='=' read -r key value; do
  [[ -z "$key" || "$key" =~ ^# ]] && continue
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)
  if [[ -z "$value" ]]; then
    missing+=("$key")
  fi
done < "$PLAIN_FILE"

if [[ ${#missing[@]} -gt 0 ]]; then
  echo "WARNING: The following variables are empty:"
  printf '  - %s\n' "${missing[@]}"
  read -rp "Continue anyway? (y/N) " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || exit 1
fi

# --- Encrypt ---
KEY=$(get_machine_key)
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
  -in "$PLAIN_FILE" \
  -out "$ENC_FILE" \
  -pass "pass:$KEY"

echo "Encrypted: $ENC_FILE"

# --- Set permissions ---
chmod 600 "$ENC_FILE"

# --- Delete plaintext ---
rm -f "$PLAIN_FILE"
echo "Deleted plaintext: $PLAIN_FILE"

# --- Decrypt to runtime location ---
openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 \
  -in "$ENC_FILE" \
  -out "$RUNTIME_ENV" \
  -pass "pass:$KEY"

chmod 600 "$RUNTIME_ENV"
echo "Runtime .env written: $RUNTIME_ENV (mode 600)"
echo "Done. Plaintext secrets removed from disk."
