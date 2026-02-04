#!/usr/bin/env bash
set -euo pipefail

# Single-command startup for Agent MVP
# Usage: bash scripts/bootstrap.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Agent MVP Bootstrap ==="
echo ""

# --- Pre-flight checks ---
echo "[1/6] Pre-flight checks..."

if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker is not installed or not in PATH."
  exit 1
fi

if ! docker info &>/dev/null 2>&1; then
  echo "ERROR: Docker daemon is not running. Start Docker Desktop first."
  exit 1
fi

if ! command -v openssl &>/dev/null; then
  echo "ERROR: openssl is required."
  exit 1
fi

echo "  Docker: OK"
echo "  OpenSSL: OK"

# --- Ensure runtime .env exists ---
echo "[2/6] Checking credentials..."
RUNTIME_ENV="$PROJECT_DIR/.openclaw/.env"

if [[ ! -f "$RUNTIME_ENV" ]]; then
  if [[ -f "$PROJECT_DIR/.env.enc" ]]; then
    echo "  Decrypting credentials..."
    bash "$SCRIPT_DIR/decrypt-env.sh"
  elif [[ -f "$PROJECT_DIR/.env.plain" ]]; then
    echo "  Encrypting credentials..."
    bash "$SCRIPT_DIR/encrypt-env.sh"
  else
    echo "ERROR: No credentials found."
    echo "  1. Copy .env.template to .env.plain"
    echo "  2. Fill in your API keys"
    echo "  3. Run: bash scripts/encrypt-env.sh"
    exit 1
  fi
fi

echo "  Credentials: OK"

# --- Set directory permissions ---
echo "[3/6] Setting permissions..."
chmod 700 "$PROJECT_DIR/.openclaw"
chmod 600 "$RUNTIME_ENV"
chmod 600 "$PROJECT_DIR/.openclaw/openclaw.json" 2>/dev/null || true
echo "  Permissions: OK"

# --- Load env for docker-compose ---
set -a
# shellcheck source=/dev/null
source "$RUNTIME_ENV"
set +a

# --- Build gateway image ---
echo "[4/6] Building gateway container..."
docker compose -f "$PROJECT_DIR/docker-compose.yml" build --quiet gateway
echo "  Build: OK"

# --- Start services ---
echo "[5/6] Starting services..."
docker compose -f "$PROJECT_DIR/docker-compose.yml" up -d
echo "  Services: starting..."

# --- Wait for healthy ---
echo "[6/6] Waiting for health..."
TIMEOUT=60
ELAPSED=0

while [[ $ELAPSED -lt $TIMEOUT ]]; do
  PG_OK=$(docker inspect --format='{{.State.Health.Status}}' agent-mvp-postgres 2>/dev/null || echo "starting")
  RD_OK=$(docker inspect --format='{{.State.Health.Status}}' agent-mvp-redis 2>/dev/null || echo "starting")
  GW_OK=$(docker inspect --format='{{.State.Health.Status}}' agent-mvp-gateway 2>/dev/null || echo "starting")

  if [[ "$PG_OK" == "healthy" && "$RD_OK" == "healthy" && "$GW_OK" == "healthy" ]]; then
    break
  fi

  sleep 2
  ELAPSED=$((ELAPSED + 2))
  printf "\r  PostgreSQL: %-10s  Redis: %-10s  Gateway: %-10s" "$PG_OK" "$RD_OK" "$GW_OK"
done
echo ""

if [[ $ELAPSED -ge $TIMEOUT ]]; then
  echo ""
  echo "WARNING: Some services may not be fully healthy yet."
  echo "Check: docker compose -f $PROJECT_DIR/docker-compose.yml logs"
fi

echo ""
echo "=== Agent MVP is running ==="
echo ""
echo "  Gateway:    http://127.0.0.1:${GATEWAY_PORT:-18790}"
echo "  PostgreSQL: 127.0.0.1:${POSTGRES_PORT:-5433}"
echo "  Redis:      127.0.0.1:${REDIS_PORT:-6380}"
echo ""
echo "Next steps:"
echo "  1. Message your Telegram bot to get a pairing code"
echo "  2. Run: openclaw pairing approve telegram <CODE>"
echo "  3. Verify: bash scripts/health-check.sh"
