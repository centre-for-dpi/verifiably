#!/usr/bin/env bash
# generate-federation-prometheus.sh
#
# Queries the Hub's trusted_issuers table and writes a Prometheus file_sd
# targets file so Prometheus can scrape each member's /metrics endpoint.
# The DB is the single source of truth; members managed via the admin UI at
# /admin/federation/members are picked up automatically.
#
# Usage (from verifiably-go/):
#   ./deploy/compose/monitoring/generate-federation-prometheus.sh [output-targets.json]
#
# Arguments:
#   output-targets.json   Destination for Prometheus targets file
#                         (default: deploy/compose/hub/federation-targets.json)
#                         Pass "-" to print to stdout.
#
# After running, trigger a Prometheus reload (no restart needed):
#   docker compose -f deploy/compose/hub/docker-compose.yml exec prometheus \
#       curl -sX POST http://localhost:9090/-/reload
#
# Requirements: docker compose running with hub-postgres container
#
set -euo pipefail

OUTPUT_FILE="${1:-deploy/compose/hub/federation-targets.json}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/compose/hub/docker-compose.yml}"

# Load hub .env for POSTGRES_USER / POSTGRES_DB credentials.
ENV_FILE="$(dirname "$COMPOSE_FILE")/.env"
if [ -f "$ENV_FILE" ]; then
  set -o allexport
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +o allexport
fi

POSTGRES_USER="${POSTGRES_USER:-verifiably}"
POSTGRES_DB="${POSTGRES_DB:-verifiably}"

_psql() {
  docker compose -f "$COMPOSE_FILE" exec -T postgres \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atq -c "$1" | tr -d '\r'
}

TARGETS_JSON=$(_psql "
SELECT COALESCE(
  json_agg(
    json_build_object(
      'targets', json_build_array(
        regexp_replace(service_endpoint, '^https?://', '')
      ),
      'labels', json_build_object(
        '__scheme__', CASE WHEN service_endpoint LIKE 'https://%' THEN 'https' ELSE 'http' END,
        'issuer_did',  did,
        'issuer_name', display_name
      )
    )
    ORDER BY did
  ),
  '[]'::json
)
FROM trusted_issuers
WHERE service_endpoint IS NOT NULL AND service_endpoint != '';
")

MEMBER_COUNT=$(_psql "
SELECT COUNT(*) FROM trusted_issuers
WHERE service_endpoint IS NOT NULL AND service_endpoint != '';
")

GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "Generated ${MEMBER_COUNT} target(s) from database at ${GENERATED_AT}" >&2

if [ "$OUTPUT_FILE" = "-" ]; then
  echo "$TARGETS_JSON"
else
  echo "$TARGETS_JSON" > "$OUTPUT_FILE"
  echo "Written to ${OUTPUT_FILE}" >&2
  printf '\nTo reload Prometheus without restart:\n' >&2
  echo "  docker compose -f $COMPOSE_FILE exec prometheus curl -sX POST http://localhost:9090/-/reload" >&2
fi
