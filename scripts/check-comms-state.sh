#!/usr/bin/env bash
# =============================================================
#  check-comms-state.sh — verify Comms is in the expected slice
# =============================================================
#  Module 3 has two slices that differ only in whether the Comms
#  agent's card enforcement is on or off. Without this check,
#  running Slice A's "observe the failure" step against a Comms
#  container that's still in Slice B state silently produces the
#  wrong outcome — a deny (403) instead of the expected egress
#  (200). That's confusing for learners.
#
#  This script queries Comms's /health (which now returns JSON
#  including the live enforce_card flag) and exits non-zero with
#  a clear message if the actual state doesn't match the expected.
#
#  Usage:
#    bash scripts/check-comms-state.sh enforce-off    # for Slice A
#    bash scripts/check-comms-state.sh enforce-on     # for Slice B
# =============================================================

set -euo pipefail

EXPECTED="${1:-}"
COMMS_URL="${COMMS_URL:-http://localhost:9100}"

case "$EXPECTED" in
  enforce-on)  WANT="true"  ;;
  enforce-off) WANT="false" ;;
  *)
    echo "Usage: $0 {enforce-on|enforce-off}" >&2
    exit 2
    ;;
esac

# Pull the live state from Comms.
if ! body="$(curl -fsS --max-time 3 "$COMMS_URL/health" 2>/dev/null)"; then
  echo "ERROR: cannot reach Comms at $COMMS_URL/health — is the container up and healthy?" >&2
  echo "  docker compose ps comms" >&2
  exit 1
fi

# Robust extraction: works with or without jq.
if command -v jq >/dev/null 2>&1; then
  actual="$(echo "$body" | jq -r '.enforce_card')"
else
  actual="$(echo "$body" | python3 -c 'import sys,json; print(str(json.load(sys.stdin).get("enforce_card")).lower())')"
fi

if [[ "$actual" != "$WANT" ]]; then
  echo "──────────────────────────────────────────────────────────"
  echo "ERROR: Comms slice state does not match what this step needs."
  echo "  Expected enforce_card = $WANT  (you asked for $EXPECTED)"
  echo "  Actually               $actual"
  echo
  if [[ "$WANT" = "false" ]]; then
    echo "Fix (turn enforcement OFF for Slice A):"
    cat <<'FIX'
  grep -q '^COMMS_ENFORCE_CARD=' .env \
    && sed -i 's/^COMMS_ENFORCE_CARD=.*/COMMS_ENFORCE_CARD=/' .env \
    || echo 'COMMS_ENFORCE_CARD=' >> .env
  docker compose stop comms
  docker compose rm -f comms
  docker compose up -d comms
FIX
  else
    echo "Fix (turn enforcement ON for Slice B):"
    cat <<'FIX'
  grep -q '^COMMS_ENFORCE_CARD=' .env \
    && sed -i 's/^COMMS_ENFORCE_CARD=.*/COMMS_ENFORCE_CARD=1/' .env \
    || echo 'COMMS_ENFORCE_CARD=1' >> .env
  docker compose stop comms
  docker compose rm -f comms
  docker compose up -d comms
FIX
  fi
  echo
  echo "Then re-run this check before continuing the lab step."
  echo "──────────────────────────────────────────────────────────"
  exit 1
fi

echo "[check-comms-state] OK — enforce_card = $actual (matches $EXPECTED)"
