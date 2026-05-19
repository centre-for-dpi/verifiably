#!/usr/bin/env bash
# generate-federation-prometheus.sh
#
# Reads config/federation.json and writes a Prometheus file_sd targets file
# (JSON format) so the Hub's Prometheus can scrape each registered member's
# /metrics endpoint. Prometheus hot-reloads the file automatically via the
# file_sd_configs.refresh_interval in prometheus-hub.yml.
#
# Usage:
#   ./deploy/compose/monitoring/generate-federation-prometheus.sh \
#       [federation.json] [output-targets.json]
#
# Arguments:
#   federation.json       Path to federation config (default: config/federation.json)
#   output-targets.json   Destination for Prometheus targets file
#                         (default: deploy/compose/monitoring/federation-targets.json)
#                         Pass "-" to print to stdout.
#
# After running, trigger a Prometheus reload if it is already running:
#   docker compose exec prometheus curl -sX POST http://localhost:9090/-/reload
#
# Requirements: jq (https://jqlang.github.io/jq/)
#
set -euo pipefail

FEDERATION_JSON="${1:-config/federation.json}"
OUTPUT_FILE="${2:-deploy/compose/monitoring/federation-targets.json}"

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not found in PATH." >&2
  echo "       Install: https://jqlang.github.io/jq/download/" >&2
  exit 1
fi

if [ ! -f "$FEDERATION_JSON" ]; then
  echo "ERROR: federation.json not found at '$FEDERATION_JSON'" >&2
  echo "       Pass the correct path as the first argument." >&2
  exit 1
fi

# Build a Prometheus file_sd targets array.
# Each element:
#   {
#     "targets": ["<host>:<port>"],
#     "labels": {
#       "__scheme__": "https" | "http",
#       "issuer_did": "did:web:...",
#       "issuer_name": "Ministerio de X"
#     }
#   }
#
# Members without a service_endpoint are skipped (no endpoint to scrape).
TARGETS_JSON=$(jq -r '
  [
    .members[]
    | (.deploymentURL // .service_endpoint) as $url
    | select($url != null and $url != "")
    | {
        "targets": [
          (
            $url
            | ltrimstr("https://")
            | ltrimstr("http://")
            | split("/")[0]
          )
        ],
        "labels": {
          "__scheme__": (if $url | startswith("https") then "https" else "http" end),
          "issuer_did":  .did,
          "issuer_name": (.name // .id // .did)
        }
      }
  ]
' "$FEDERATION_JSON")

MEMBER_COUNT=$(echo "$TARGETS_JSON" | jq 'length')
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "Generated ${MEMBER_COUNT} target(s) from ${FEDERATION_JSON} at ${GENERATED_AT}" >&2

if [ "$OUTPUT_FILE" = "-" ]; then
  echo "$TARGETS_JSON"
else
  echo "$TARGETS_JSON" > "$OUTPUT_FILE"
  echo "Written to ${OUTPUT_FILE}" >&2
  echo "" >&2
  echo "To reload Prometheus without restart:" >&2
  echo "  docker compose exec prometheus curl -sX POST http://localhost:9090/-/reload" >&2
fi
