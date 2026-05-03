#!/usr/bin/env bash
# =============================================================
#  Show the current state of the sandbox tickets table.
# =============================================================
#  Useful between Module 1 demo runs:
#    - Before the destructive demo: rows present, table exists.
#    - After: error "relation \"tickets\" does not exist".
#  That contrast IS the lesson.
# =============================================================

set -euo pipefail

CONTAINER="${POSTGRES_CONTAINER:-asl-postgres}"
DB_USER="${POSTGRES_USER:-lab}"
DB_NAME="${POSTGRES_DB:-tickets}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "Postgres container '$CONTAINER' is not running. Start it with:" >&2
  echo "  docker compose up -d postgres" >&2
  exit 1
fi

echo "[show-tickets] tables in $DB_NAME:"
docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "\dt"

echo
echo "[show-tickets] tickets contents (will fail loudly if the table was dropped):"
docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT id, severity, status, subject FROM tickets ORDER BY id;" || true
