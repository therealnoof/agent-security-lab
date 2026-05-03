#!/usr/bin/env bash
# =============================================================
#  agent-security-lab — clean.sh
# =============================================================
#  Wipe lab state so you can start over from Module 0.
#
#  Removes:
#   - all asl-* containers
#   - postgres-data volume      (sandbox tickets table state)
#   - keycloak-data volume      (so realm import re-runs on next start)
#   - any orphaned containers from previous compose definitions
#   - (with --full) locally-built images, forcing rebuild
#
#  Preserves:
#   - .env  (your CalypsoAI token + lab credentials)
#   - postgres/init/*.sql, mcp_server/capabilities.json,
#     agents/comms/agent-card.json, all agent code (these are
#     source, not state — versioned in git)
#
#  Usage:
#    bash scripts/clean.sh              # confirm prompt; quick reset
#    bash scripts/clean.sh -y           # skip the prompt
#    bash scripts/clean.sh --full -y    # also remove built images
#                                       # (slow rebuild on next run)
# =============================================================

set -euo pipefail

YES=0
FULL=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes)  YES=1 ;;
    --full)    FULL=1 ;;
    -h|--help)
      cat <<'HELP'
Usage: bash scripts/clean.sh [--full] [-y]

Wipes lab state so you can start over from Module 0.

  --full   Also remove locally-built images (slow rebuild after).
  -y       Skip the confirmation prompt.
  -h       This help.

Preserves: .env (your CalypsoAI token and lab credentials).
Removes:   all asl-* containers, postgres-data + keycloak-data
           volumes, orphaned containers from older compose
           definitions.

After cleaning you typically want to:
  1. Optionally reset .env toggles (e.g., COMMS_ENFORCE_CARD).
  2. docker compose up -d keycloak  (~30-45s for realm re-import).
  3. Follow docs/STUDENT_GUIDE.md from Module 0.
HELP
      exit 0
      ;;
    *)
      echo "Unknown arg: $arg (try -h)" >&2
      exit 1
      ;;
  esac
done

# Operate from the repo root no matter where the script was invoked from.
cd "$(dirname "$0")/.."

# --- Show plan ---------------------------------------------
echo "About to wipe lab state in: $(pwd)"
echo
echo "Will remove:"
echo "  - all containers from this compose project (asl-*)"
echo "  - named volumes: postgres-data, keycloak-data"
echo "  - orphaned containers from older compose definitions"
[[ $FULL -eq 1 ]] && echo "  - locally-built images for this project (slow rebuild after)"
echo
echo "PRESERVED:"
echo "  - .env  (your CalypsoAI token, Keycloak admin password, OAuth secrets)"
echo "  - all source: agents/, mcp_server/, postgres/init/, keycloak/realm/, scripts/"
echo

if [[ $YES -eq 0 ]]; then
  read -r -p "Proceed? [y/N] " ans
  case "${ans:-}" in
    y|Y|yes|YES) ;;
    *) echo "Aborted."; exit 0 ;;
  esac
fi

# --- Tear down --------------------------------------------
# `down -v` removes both containers AND the named volumes
# declared at the bottom of docker-compose.yml.
# `--remove-orphans` cleans up containers from old compose
# definitions (e.g., approver, comms when they were stubs).
docker compose down -v --remove-orphans

if [[ $FULL -eq 1 ]]; then
  # Also remove locally-built images. `--rmi local` only
  # touches images we built (mcp_server, agents/*, comms);
  # third-party pulls (keycloak, postgres, python-slim)
  # stay so we don't re-download them.
  docker compose down --rmi local 2>/dev/null || true
fi

echo
echo "Lab state cleaned."
echo
echo "Next steps (typical):"
echo "  1. Optional — reset toggles in .env so you start at Module 0 defaults:"
echo "       sed -i 's/^COMMS_ENFORCE_CARD=.*/COMMS_ENFORCE_CARD=/' .env"
echo "  2. Bring keycloak back up first (fresh realm import takes 30-45s):"
echo "       docker compose up -d keycloak"
echo "  3. Follow docs/STUDENT_GUIDE.md starting at Module 0."
