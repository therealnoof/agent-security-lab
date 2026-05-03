#!/usr/bin/env bash
# =============================================================
#  Reset the sandbox Postgres back to a clean seeded state.
# =============================================================
#  Use this AFTER the destructive Module 1 Slice A demo to
#  restore the `tickets` table so you can re-run the failure
#  (or move on to Slice B with a clean baseline).
#
#  Idempotent: the seed SQL drops-and-recreates everything.
#
#  Requirements: docker, the postgres container running and
#  healthy.
# =============================================================

set -euo pipefail

CONTAINER="${POSTGRES_CONTAINER:-asl-postgres}"
DB_USER="${POSTGRES_USER:-lab}"
DB_NAME="${POSTGRES_DB:-tickets}"
SEED_FILE="$(cd "$(dirname "$0")/.." && pwd)/postgres/init/01-tickets.sql"

if [[ ! -f "$SEED_FILE" ]]; then
  echo "Seed file not found: $SEED_FILE" >&2
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "Postgres container '$CONTAINER' is not running. Start it with:" >&2
  echo "  docker compose up -d postgres" >&2
  exit 1
fi

echo "[reset-db] re-seeding $DB_NAME via $CONTAINER…"
docker exec -i "$CONTAINER" psql -v ON_ERROR_STOP=1 -U "$DB_USER" -d "$DB_NAME" < "$SEED_FILE" >/dev/null

echo "[reset-db] done. Current tickets:"
docker exec "$CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -c "SELECT id, severity, status, subject FROM tickets ORDER BY id;"
