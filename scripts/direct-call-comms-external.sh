#!/usr/bin/env bash
# =============================================================
#  direct-call-comms-external.sh
# =============================================================
#  Module 3 Slice B Reinforcement #3: bypass the LLM entirely.
#  Fetches a Keycloak access token for agent-triage, then POSTs
#  to Comms's /a2a/skills/notify-external skill.
#
#  Why all the calls run inside the Docker network:
#    Tokens issued by Keycloak embed an `iss` claim derived
#    from the request's host. A token fetched via the host's
#    localhost:8080 has iss=http://localhost:8080/...; Comms
#    runs inside Docker and introspects via http://keycloak:8080/...
#    Keycloak compares the token's iss against its own canonical
#    issuer at the introspection URL and silently rejects the
#    mismatch with {"active": false}, which our middleware
#    surfaces as HTTP 401 "invalid or expired token". So we run
#    both curls (token fetch and skill POST) on the same
#    Docker network the agents use, guaranteeing the token's
#    iss matches Comms's introspection host.
#
#  Expected outcomes from the skill POST:
#    With COMMS_ENFORCE_CARD=1 (Slice B):
#      HTTP 403 + allowed_callers=["agent-approver-attested"]
#      → Slice B working: card enforced at receiver.
#    With COMMS_ENFORCE_CARD=  (Slice A):
#      HTTP 200 + "performed": "external-email"
#      → Comms accepts authenticated callers.
#    HTTP 401:
#      Comms could not introspect the token. Run the manual
#      diagnostic at the bottom of this script's stderr to see
#      what Keycloak's introspection actually returns.
#
#  Usage:
#    bash scripts/direct-call-comms-external.sh
# =============================================================

set -euo pipefail

NETWORK="${COMPOSE_NETWORK:-agent-security-lab_default}"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.10.0}"
KC_REALM="${KEYCLOAK_REALM:-agent-lab}"
CLIENT_ID="${OAUTH_CLIENT_ID:-agent-triage}"
CLIENT_SECRET="${OAUTH_CLIENT_SECRET:-agent-triage-secret-change-me}"

# --- Sanity: docker network must exist (i.e. lab is up) ---
if ! docker network ls --format '{{.Name}}' | grep -qx "$NETWORK"; then
  echo "[direct-call] Docker network '$NETWORK' not found." >&2
  echo "  Bring the lab up first:" >&2
  echo "    docker compose up -d keycloak comms" >&2
  exit 1
fi

# --- Step 1: fetch token INSIDE the docker network ---------
# Token is issued with iss=http://keycloak:8080/realms/agent-lab,
# matching what Comms uses for introspection.
echo "[direct-call] fetching OAuth token (inside $NETWORK) ..."
TOKEN_JSON="$(
  docker run --rm --network "$NETWORK" "$CURL_IMAGE" \
    -fsS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -d grant_type=client_credentials \
    "http://keycloak:8080/realms/${KC_REALM}/protocol/openid-connect/token"
)" || {
  echo "[direct-call] !! token fetch FAILED" >&2
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

# --- Step 2: call notify-external INSIDE the docker network ---
echo "[direct-call] POSTing to comms:9100/a2a/skills/notify-external as ${CLIENT_ID} ..."
echo "──────────────── HTTP response ────────────────"
docker run --rm --network "$NETWORK" "$CURL_IMAGE" \
  -i -sS -X POST "http://comms:9100/a2a/skills/notify-external" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"to":"vendor@x.com","subject":"smoke","body":"smoke"}' || true

echo
echo
cat <<LEGEND
──────────────── Interpreting the result ─────────
  HTTP 403 + allowed_callers=['agent-approver-attested']
    → Slice B working: card enforced at receiver.
  HTTP 200 + 'performed': 'external-email'
    → COMMS_ENFORCE_CARD is OFF (Slice A state).
  HTTP 401 'invalid or expired token'
    → Token was rejected at introspection. Almost always an
      issuer-vs-introspection-host mismatch, which is why this
      script runs everything inside the Docker network in the
      first place. If you still hit this, check:
        docker compose logs comms --since 1m | grep introspect
──────────────────────────────────────────────────
LEGEND
