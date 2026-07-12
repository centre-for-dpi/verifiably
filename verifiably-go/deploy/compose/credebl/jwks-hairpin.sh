#!/usr/bin/env bash
# CREDEBL OID4VCI hairpin fix: the Credo agent verifies access tokens by fetching
# its own JWKS at https://<credebl-slug>.<domain>/oid4vci/.../jwks, but that host
# resolves (via DNS) to the box PUBLIC IP, which hairpins and fails from inside
# docker → invalid_token → 403 on every credential request. This sidecar claims
# the network alias <credebl-slug>.<domain> on <project>_default and TLS-passthrough
# forwards :443 to the caddy-public container, so the agent reaches its JWKS.
# Docker's embedded DNS prefers the alias over the public-DNS answer.
#
# Host-agnostic: the domain/slug/project come from the env (.env is sourced when
# not already set), so this works on any deployment. Legacy host:port mode has no
# public DNS to hairpin — the script no-ops.
set -euo pipefail
_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -z "${VERIFIABLY_PUBLIC_DOMAIN:-}" ]]; then
  for _envf in "$_here/../../.env" "$_here/../../../.env"; do
    [[ -f "$_envf" ]] && { set -a; source "$_envf"; set +a; break; }
  done
fi
DOMAIN="${VERIFIABLY_PUBLIC_DOMAIN:-}"
[[ -z "$DOMAIN" ]] && { echo "jwks-hairpin: no VERIFIABLY_PUBLIC_DOMAIN (legacy mode) — skipping."; exit 0; }
PROJECT="${COMPOSE_PROJECT:-waltid}"
ALIAS="${VERIFIABLY_SLUG_CREDEBL:-credebl}.${DOMAIN}"
CADDY_IP="$(docker inspect "${PROJECT}-caddy-public-1" --format "{{(index .NetworkSettings.Networks \"${PROJECT}_default\").IPAddress}}")"
docker rm -f credebl-jwks-hairpin 2>/dev/null || true
docker run -d --name credebl-jwks-hairpin --restart unless-stopped \
  --network "${PROJECT}_default" --network-alias "$ALIAS" \
  alpine/socat TCP-LISTEN:443,fork,reuseaddr TCP:"${CADDY_IP}":443
echo "jwks-hairpin: aliased ${ALIAS} -> caddy-public (${CADDY_IP})"
