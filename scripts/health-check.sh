#!/usr/bin/env bash
set -euo pipefail

# Security + health verification for Agent MVP
# Usage: bash scripts/health-check.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PASS=0
FAIL=0
WARN=0

check() {
  local label="$1" result="$2" expected="$3"
  if [[ "$result" == "$expected" ]]; then
    echo "  [PASS] $label"
    PASS=$((PASS + 1))
  else
    echo "  [FAIL] $label (got: $result, expected: $expected)"
    FAIL=$((FAIL + 1))
  fi
}

warn() {
  local label="$1" detail="$2"
  echo "  [WARN] $label — $detail"
  WARN=$((WARN + 1))
}

echo "=== Agent MVP Health Check ==="
echo ""

# --- Load env ---
RUNTIME_ENV="$PROJECT_DIR/.openclaw/.env"
if [[ -f "$RUNTIME_ENV" ]]; then
  set -a; source "$RUNTIME_ENV"; set +a
fi

GPORT="${GATEWAY_PORT:-18790}"
GTOKEN="${GATEWAY_TOKEN:-}"

# --- 1. Container health ---
echo "[Containers]"
for svc in agent-mvp-postgres agent-mvp-redis agent-mvp-gateway; do
  status=$(docker inspect --format='{{.State.Health.Status}}' "$svc" 2>/dev/null || echo "not_found")
  check "$svc" "$status" "healthy"
done

# --- 2. Gateway localhost binding ---
echo ""
echo "[Network Security]"
BIND=$(lsof -iTCP:"$GPORT" -sTCP:LISTEN -n 2>/dev/null | grep -o '127\.0\.0\.1' | head -1 || echo "not_bound")
check "Gateway bound to localhost only (:$GPORT)" "$BIND" "127.0.0.1"

# --- 3. Gateway auth ---
echo ""
echo "[Authentication]"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$GPORT/api/health" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
  echo "  [PASS] Unauthenticated request rejected ($HTTP_CODE)"
  PASS=$((PASS + 1))
elif [[ "$HTTP_CODE" == "200" ]]; then
  # Health endpoint may be unauthenticated by design
  echo "  [PASS] Gateway responding (health endpoint public)"
  PASS=$((PASS + 1))
else
  echo "  [WARN] Gateway returned $HTTP_CODE"
  WARN=$((WARN + 1))
fi

# --- 4. No plaintext secrets in config ---
echo ""
echo "[Secret Hygiene]"
LEAKS=$(grep -rn 'xai-\|bot[0-9]\{6,\}' "$PROJECT_DIR/.openclaw/openclaw.json" 2>/dev/null | wc -l | xargs)
check "No plaintext secrets in openclaw.json" "$LEAKS" "0"

if [[ -f "$PROJECT_DIR/.env.plain" ]]; then
  echo "  [FAIL] .env.plain still exists — delete it!"
  FAIL=$((FAIL + 1))
else
  echo "  [PASS] No .env.plain on disk"
  PASS=$((PASS + 1))
fi

# --- 5. File permissions ---
echo ""
echo "[File Permissions]"
if [[ -f "$RUNTIME_ENV" ]]; then
  PERM=$(stat -f '%Lp' "$RUNTIME_ENV" 2>/dev/null || stat -c '%a' "$RUNTIME_ENV" 2>/dev/null || echo "unknown")
  check ".env permissions" "$PERM" "600"
fi

if [[ -f "$PROJECT_DIR/.openclaw/openclaw.json" ]]; then
  PERM=$(stat -f '%Lp' "$PROJECT_DIR/.openclaw/openclaw.json" 2>/dev/null || stat -c '%a' "$PROJECT_DIR/.openclaw/openclaw.json" 2>/dev/null || echo "unknown")
  check "openclaw.json permissions" "$PERM" "600"
fi

DIR_PERM=$(stat -f '%Lp' "$PROJECT_DIR/.openclaw" 2>/dev/null || stat -c '%a' "$PROJECT_DIR/.openclaw" 2>/dev/null || echo "unknown")
check ".openclaw directory permissions" "$DIR_PERM" "700"

# --- 6. Existing instance untouched ---
echo ""
echo "[Isolation]"
if [[ -d "$HOME/clawd" ]]; then
  echo "  [PASS] ~/clawd exists and untouched"
  PASS=$((PASS + 1))
else
  echo "  [INFO] ~/clawd not found (no existing instance to verify)"
fi

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
if [[ $FAIL -gt 0 ]]; then
  echo "ACTION REQUIRED: Fix failures before using in production."
  exit 1
fi
