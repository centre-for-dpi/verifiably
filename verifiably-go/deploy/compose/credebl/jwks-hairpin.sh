#!/usr/bin/env bash
# CREDEBL OID4VCI hairpin fix: the Credo agent verifies access tokens by fetching
# its own JWKS at https://credebl.in-labs.cdpi.dev/oid4vci/.../jwks, but that host
# resolves (via DNS) to the box PUBLIC IP, which hairpins and fails from inside
# docker → invalid_token → 403 on every credential request. This sidecar claims
# the network alias credebl.in-labs.cdpi.dev on waltid_default and TLS-passthrough
# forwards :443 to the caddy-public container, so the agent reaches its JWKS.
# Docker's embedded DNS prefers the alias over the public-DNS answer.
CADDY_IP="$(docker inspect waltid-caddy-public-1 --format '{{(index .NetworkSettings.Networks "waltid_default").IPAddress}}')"
docker rm -f credebl-jwks-hairpin 2>/dev/null
docker run -d --name credebl-jwks-hairpin --restart unless-stopped \
  --network waltid_default --network-alias credebl.in-labs.cdpi.dev \
  alpine/socat TCP-LISTEN:443,fork,reuseaddr TCP:"${CADDY_IP}":443
