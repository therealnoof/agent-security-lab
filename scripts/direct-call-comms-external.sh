#!/usr/bin/env bash
# =============================================================
#  direct-call-comms-external.sh
# =============================================================
#  Module 3 Slice B Reinforcement #3: bypass the LLM entirely.
#  Fetches a Keycloak access token for agent-triage and POSTs
#  directly to Comms's /a2a/skills/notify-external endpoint.
#
#  Expected outcomes:
#    With COMMS_ENFORCE_CARD=1 (Slice B):
#      HTTP 403 with body listing
#      allowed_callers=["agent-approver-attested"].
#      Proves the card is enforced server-side, not in the
#      caller — the deny fires regardless of who the caller is
#      (LLM-driven or curl).
#    With COMMS_ENFORCE_CARD=  (Slice A):
#      HTTP 200 with a "performed external-email" body. Proves
#      Comms otherwise accepts authenticated calls.
#
#  Why a script instead of a curl one-liner?
#    The original guide had this as a single nested command:
#      -H "Authorization: Bearer $(curl ... | python3 -c '...')"
#    The nested quoting is fragile across paste paths and
#    ${IFS}/locale defaults. Splitting into a script makes
#    diagnosis on failure obvious.
#
#  Usage:
#    bash scripts/direct-call-comms-external.sh
# =============================================================

set -euo pipefail

KC_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KC_REALM="${KEYCLOAK_REALM:-agent-lab}"
CLIENT_ID="${OAUTH_CLIENT_ID:-agent-triage}"
CLIENT_SECRET="${OAUTH_CLIENT_SECRET:-agent-triage-secret-change-me}"
COMMS_URL="${COMMS_URL:-http://localhost:9100}"

# --- Step 1: fetch an access token ------------------------
echo "[direct-call] fetching OAuth token from $KC_URL ..."
TOKEN_JSON="$(
  curl -fsS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -d grant_type=client_credentials \
    "$KC_URL/realms/$KC_REALM/protocol/openid-connect/token"
)" || {
  echo "[direct-call] !! token fetch FAILED — Keycloak unreachable or bad creds" >&2
  exit 1
}

TOKEN="$(printf '%s' "$TOKEN_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))')"

if [[ -z "$TOKEN" ]]; then
  echo "[direct-call] !! Keycloak response did not contain an access_token:" >&2
  echo "$TOKEN_JSON" | head -c 500 >&2
  echo >&2
  exit 1
fi

echo "[direct-call] token length=${#TOKEN}, prefix=${TOKEN:0:40}..."

# --- Step 2: call notify-external --------------------------
echo "[direct-call] POSTing to $COMMS_URL/a2a/skills/notify-external as ${CLIENT_ID} ..."
echo "──────────────── HTTP response ────────────────"
curl -i -sS -X POST "$COMMS_URL/a2a/skills/notify-external" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to":"vendor@x.com","subject":"smoke","body":"smoke"}'

echo
echo
echo "──────────────── Interpreting the result ─────────"
echo "  HTTP 403 + allowed_callers=['agent-approver-attested']"
echo "    → Slice B working: card enforced at receiver."
echo "  HTTP 200 + 'performed': 'external-email'"
echo "    → COMMS_ENFORCE_CARD is OFF (Slice A state)."
echo "  HTTP 401"
echo "    → Comms could not introspect the token; check"
echo "      'docker compose logs comms --since 1m' for the why."
echo "──────────────────────────────────────────────────"
