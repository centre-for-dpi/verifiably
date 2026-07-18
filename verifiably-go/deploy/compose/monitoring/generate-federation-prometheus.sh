#!/usr/bin/env bash
# generate-federation-prometheus.sh
#
# Queries the Hub's trusted_issuers table and regenerates prometheus-hub.yml
# (base config + one scrape job per member, each with its own Bearer token)
# so Prometheus — and therefore Grafana — automatically reflects whatever is
# registered in trusted_issuers. The DB is the single source of truth;
# members managed via the admin UI at /admin/federation/members are picked
# up the next time this script runs.
#
# Usage (from verifiably-go/):
#   ./deploy/compose/monitoring/generate-federation-prometheus.sh
#
# Re-run this after adding, editing, or removing a federation member so the
# Grafana dashboards pick up the change. It rewrites prometheus-hub.yml in
# place from prometheus-hub.template.yml and reloads Prometheus without a
# restart (--web.enable-lifecycle is already on in the hub compose file).
#
# Requirements: docker compose running with hub-postgres container
#
set -euo pipefail

MONITORING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="$MONITORING_DIR/prometheus-hub.template.yml"
OUTPUT_FILE="$MONITORING_DIR/prometheus-hub.yml"
COMPOSE_FILE="${COMPOSE_FILE:-$MONITORING_DIR/../hub/docker-compose.yml}"

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
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atq -F $'\t' -c "$1" | tr -d '\r'
}

# One tab-separated row per member: did, display_name, service_endpoint, verifier_api_key
MEMBERS=$(_psql "
SELECT did, display_name, service_endpoint, verifier_api_key
FROM trusted_issuers
WHERE service_endpoint IS NOT NULL AND service_endpoint != ''
ORDER BY did;
")

cp "$TEMPLATE_FILE" "$OUTPUT_FILE"

MEMBER_COUNT=0
if [ -n "$MEMBERS" ]; then
  while IFS=$'\t' read -r did display_name service_endpoint api_key; do
    [ -z "$did" ] && continue
    MEMBER_COUNT=$((MEMBER_COUNT + 1))

    host=$(printf '%s' "$service_endpoint" | sed -E 's#^https?://##')
    scheme="http"
    case "$service_endpoint" in
      https://*) scheme="https" ;;
    esac
    job_slug=$(printf '%s' "$did" | tr -c 'a-zA-Z0-9' '-' | sed -E 's/-+/-/g; s/^-|-$//g')

    {
      echo ""
      echo "  - job_name: verifiably-federation-${job_slug}"
      echo "    scrape_interval: 30s"
      echo "    scrape_timeout: 15s"
      echo "    metrics_path: /metrics"
      echo "    scheme: ${scheme}"
      echo "    honor_labels: true"
      if [ -n "$api_key" ]; then
        echo "    authorization:"
        echo "      type: Bearer"
        echo "      credentials: ${api_key}"
      fi
      echo "    static_configs:"
      echo "      - targets: ['${host}']"
      echo "        labels:"
      printf '          issuer_did: "%s"\n' "$did"
      printf '          issuer_name: "%s"\n' "$display_name"
      echo "          component: member"
      echo "    relabel_configs:"
      echo "      - target_label: job"
      echo "        replacement: verifiably-federation"
    } >> "$OUTPUT_FILE"
  done <<< "$MEMBERS"
fi

GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "Generated ${MEMBER_COUNT} member job(s) from trusted_issuers at ${GENERATED_AT}" >&2
echo "Written to ${OUTPUT_FILE}" >&2

if docker compose -f "$COMPOSE_FILE" ps prometheus 2>/dev/null | grep -q Up; then
  docker compose -f "$COMPOSE_FILE" exec prometheus curl -sX POST http://localhost:9090/-/reload
  echo "Prometheus reloaded." >&2
else
  echo "Prometheus is not running; start the stack and it will pick up the new config." >&2
fi
