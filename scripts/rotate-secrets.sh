#!/usr/bin/env bash
set -euo pipefail

# Secret rotation helper for Agent MVP
# Usage: bash scripts/rotate-secrets.sh [gateway|db|redis|all]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENC_FILE="$PROJECT_DIR/.env.enc"
RUNTIME_ENV="$PROJECT_DIR/.openclaw/.env"

TARGET="${1:-all}"

if [[ ! -f "$ENC_FILE" ]]; then
  echo "ERROR: No encrypted env found. Run encrypt-env.sh first."
  exit 1
fi

# Decrypt to temp
TEMP_ENV=$(mktemp)
trap 'rm -f "$TEMP_ENV"' EXIT

bash "$SCRIPT_DIR/decrypt-env.sh"
cp "$RUNTIME_ENV" "$TEMP_ENV"

rotate_value() {
  local key="$1"
  local new_value
  new_value=$(openssl rand -hex 32)
  if grep -q "^${key}=" "$TEMP_ENV"; then
    sed -i.bak "s|^${key}=.*|${key}=${new_value}|" "$TEMP_ENV"
    rm -f "${TEMP_ENV}.bak"
    echo "  Rotated: $key"
  else
    echo "  Skip: $key not found"
  fi
}

echo "=== Rotating secrets ($TARGET) ==="

case "$TARGET" in
  gateway)
    rotate_value "GATEWAY_TOKEN"
    ;;
  db)
    rotate_value "POSTGRES_PASSWORD"
    ;;
  redis)
    rotate_value "REDIS_PASSWORD"
    ;;
  all)
    rotate_value "GATEWAY_TOKEN"
    rotate_value "POSTGRES_PASSWORD"
    rotate_value "REDIS_PASSWORD"
    ;;
  *)
    echo "Usage: $0 [gateway|db|redis|all]"
    exit 1
    ;;
esac

# Write back as .env.plain for re-encryption
cp "$TEMP_ENV" "$PROJECT_DIR/.env.plain"

# Re-encrypt
bash "$SCRIPT_DIR/encrypt-env.sh"

echo ""
echo "Secrets rotated. Restart services to apply:"
echo "  docker compose -f $PROJECT_DIR/docker-compose.yml down"
echo "  bash $SCRIPT_DIR/bootstrap.sh"
