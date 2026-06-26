#!/usr/bin/env bash
# Delegated-access status hairpin fix: the walt.id VERIFIER, when the "Status"
# policy is on, fetches the credential's status list at
# https://verifiably.in-labs.cdpi.dev/status-list/{bitstring,token}/v1 — but that
# host resolves (via public DNS) to the box PUBLIC IP, which hairpins and fails
# from inside docker → StatusRetrievalError(Connect timeout) → the credential-
# status policy fails (looks "revoked"). This sidecar claims the network alias
# verifiably.in-labs.cdpi.dev on waltid_default and TLS-passthrough forwards :443
# to the caddy-public container, so the verifier reaches the status list. Docker's
# embedded DNS prefers the alias over the public-DNS answer. Same pattern as
# credebl/jwks-hairpin.sh.
CADDY_IP="$(docker inspect waltid-caddy-public-1 --format '{{(index .NetworkSettings.Networks "waltid_default").IPAddress}}')"
docker rm -f verifiably-status-hairpin 2>/dev/null
docker run -d --name verifiably-status-hairpin --restart unless-stopped \
  --network waltid_default --network-alias verifiably.in-labs.cdpi.dev \
  alpine/socat TCP-LISTEN:443,fork,reuseaddr TCP:"${CADDY_IP}":443
