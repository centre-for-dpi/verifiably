#!/usr/bin/env bash
# Delegated-access status hairpin fix: the walt.id VERIFIER, when the "Status"
# policy is on, fetches the credential's status list at
# https://<verifiably-slug>.<domain>/status-list/{bitstring,token}/v1 — but that
# host resolves (via public DNS) to the box PUBLIC IP, which hairpins and fails
# from inside docker → StatusRetrievalError(Connect timeout) → the credential-
# status policy fails (looks "revoked"). This sidecar claims the network alias
# <verifiably-slug>.<domain> on <project>_default and TLS-passthrough forwards :443
# to the caddy-public container, so the verifier reaches the status list. Docker's
# embedded DNS prefers the alias over the public-DNS answer. Same pattern as
# credebl/jwks-hairpin.sh.
#
# Host-agnostic: the domain/slug/project come from the env (.env is sourced when
# not already set). Legacy host:port mode has no public DNS to hairpin — no-ops.
set -euo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${VERIFIABLY_PUBLIC_DOMAIN:-}" ]]; then
  for _envf in "$_here/../.env" "$_here/../../.env"; do
    [[ -f "$_envf" ]] && { set -a; source "$_envf"; set +a; break; }
  done
fi
DOMAIN="${VERIFIABLY_PUBLIC_DOMAIN:-}"
[[ -z "$DOMAIN" ]] && { echo "verifier-status-hairpin: no VERIFIABLY_PUBLIC_DOMAIN (legacy mode) — skipping."; exit 0; }
PROJECT="${COMPOSE_PROJECT:-waltid}"
ALIAS="${VERIFIABLY_SLUG_VERIFIABLY:-verifiably}.${DOMAIN}"
CADDY_IP="$(docker inspect "${PROJECT}-caddy-public-1" --format "{{(index .NetworkSettings.Networks \"${PROJECT}_default\").IPAddress}}")"
docker rm -f verifiably-status-hairpin 2>/dev/null || true
docker run -d --name verifiably-status-hairpin --restart unless-stopped \
  --network "${PROJECT}_default" --network-alias "$ALIAS" \
  alpine/socat TCP-LISTEN:443,fork,reuseaddr TCP:"${CADDY_IP}":443
echo "verifier-status-hairpin: aliased ${ALIAS} -> caddy-public (${CADDY_IP})"
