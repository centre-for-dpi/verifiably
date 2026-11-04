#!/bin/bash
# Convenience launcher for citizen_service.py.
#
# Two common modes:
#   ./run.sh                     — open, no auth, talks to localhost:5435
#                                  (assumes verifiably-go's docker compose
#                                  is up and citizens-postgres is reachable
#                                  on the host). URL to paste into the API
#                                  bulk form: http://host.docker.internal:8099/api/mortgage-simple
#
#   ./run.sh token               — same, but requires
#                                  `Authorization: Bearer token` on every /api/*
#                                  request. Paste "Bearer token" into the
#                                  bulk form's auth-header input.

set -euo pipefail

# The real password is CITIZENS_PG_PASSWORD from verifiably-go's own .env
# (generated on `deploy.sh setup`) — export it in your shell before running
# this, or pass CITIZENS_DSN directly. The "citizens" fallback below only
# matches a host that predates that variable.
export CITIZENS_DSN="${CITIZENS_DSN:-postgres://citizens:${CITIZENS_PG_PASSWORD:-citizens}@localhost:5435/citizens}"
if [[ $# -gt 0 ]]; then
  export CITIZENS_API_TOKEN="$1"
fi
export PORT="${PORT:-8099}"

if ! python3 -c 'import psycopg2' 2>/dev/null; then
  echo "psycopg2 missing — run: pip install psycopg2-binary" >&2
  exit 1
fi

exec python3 "$(dirname "$0")/citizen_service.py"
