#!/usr/bin/env bash
# Ensure the vcplatform OIDC client in Keycloak has a redirect URI matching
# the current ${PUBLIC_HOST} on every ./deploy.sh up. Mirrors the role of
# bootstrap-wso2is.sh.
#
# Why this exists: Keycloak imports realms from /opt/keycloak/data/import/
# only when the realm doesn't already exist (Strategy: IGNORE_EXISTING).
# Once vcplatform is in the H2 DB, edits to keycloak-realm.json are stranded.
# Worse: Keycloak does NOT support `*` as a hostname wildcard in
# redirectUris — `*` only matches a path component. So the wildcards we
# inherited from upstream (http://*:8080/*, https://*/*) are functionally
# inert; only literal hostnames work. When the operator changes
# VERIFIABLY_PUBLIC_HOST and re-deploys, the new host's callback URL has
# to land in the client's redirectUris list explicitly or every login
# fails with "Invalid parameter: redirect_uri".
#
# This script reaches Keycloak's Admin REST API (auth via the master-realm
# admin user) and adds — set-union, not replace — three callback URIs:
#   - http://${PUBLIC_HOST}:${VERIFIABLY_HOST_PORT}/* (browser-direct on EC2)
#   - http://localhost:${VERIFIABLY_HOST_PORT}/*      (laptop dev fallback)
#   - https://${PUBLIC_HOST}/*                        (Caddy/HTTPS-fronted)
# Existing entries (literal localhost, 172.24.0.1, etc.) survive — set union
# means a host change is additive, not destructive.
#
# Idempotent: a second run finds the URIs already present and is a no-op.
#
# Required env (with defaults):
#   KEYCLOAK_BASE             http://localhost:8180
#   KEYCLOAK_REALM            vcplatform
#   KEYCLOAK_CLIENT_ID        vcplatform
#   KEYCLOAK_ADMIN_USER       admin
#   KEYCLOAK_ADMIN_PASSWORD   admin
#   PUBLIC_HOST               (no default — script aborts if unset and
#                              VERIFIABLY_PUBLIC_HOST also unset)
#   VERIFIABLY_HOST_PORT      8080
#
# Usage:
#   ./scripts/bootstrap-keycloak.sh
#   PUBLIC_HOST=ec2-1-2-3-4.compute.amazonaws.com ./scripts/bootstrap-keycloak.sh

set -euo pipefail

: "${KEYCLOAK_BASE:=http://localhost:8180}"
: "${KEYCLOAK_REALM:=vcplatform}"
: "${KEYCLOAK_CLIENT_ID:=vcplatform}"
: "${KEYCLOAK_ADMIN_USER:=admin}"
: "${KEYCLOAK_ADMIN_PASSWORD:=admin}"
: "${VERIFIABLY_HOST_PORT:=8080}"
: "${PUBLIC_HOST:=${VERIFIABLY_PUBLIC_HOST:-}}"
# VERIFIABLY_CALLBACK_URL is the browser-facing /auth/callback URL the
# OIDC flow returns to. Set by deploy.sh through url_for() so it picks up
# either:
#   legacy mode  → http://<PUBLIC_HOST>:<port>/auth/callback
#   pattern mode → https://verifiably.<domain>/auth/callback
# If unset (e.g. running this script standalone), we synthesise the
# legacy form below — keeps the old "PUBLIC_HOST is the only knob"
# UX working for users who haven't switched to subdomain mode.
: "${VERIFIABLY_CALLBACK_URL:=}"

if [[ -z "$PUBLIC_HOST" ]]; then
  echo "  bootstrap-keycloak: PUBLIC_HOST / VERIFIABLY_PUBLIC_HOST unset — abort"
  exit 1
fi

# Probe master realm first — it always exists once Keycloak finishes
# its boot-up cycle (the vcplatform realm is imported AFTER the master
# realm is up, so probing master gives us a stable readiness signal even
# while imports are still running). On slow VPS instances Keycloak's
# Quarkus runtime + H2 schema migration can take several minutes after
# the TCP port goes ready, so we wait up to 8 minutes.
echo "waiting for Keycloak master realm at ${KEYCLOAK_BASE}…"
for i in $(seq 1 240); do
  if curl -sf -o /dev/null "$KEYCLOAK_BASE/realms/master/.well-known/openid-configuration"; then
    echo "  master realm reachable"
    break
  fi
  sleep 2
  if [[ $i -eq 240 ]]; then
    echo "  Keycloak master realm not reachable after 8 minutes — abort"
    echo "  hint: check 'docker logs waltid-keycloak-1 --tail 40' for boot errors"
    exit 1
  fi
done

# Master-realm admin token. admin-cli is a built-in public client, no
# secret needed.
TOKEN=""
for i in $(seq 1 60); do
  TOKEN=$(curl -sS -X POST \
    "$KEYCLOAK_BASE/realms/master/protocol/openid-connect/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=password&client_id=admin-cli&username=$KEYCLOAK_ADMIN_USER&password=$KEYCLOAK_ADMIN_PASSWORD" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null || echo "")
  [[ -n "$TOKEN" ]] && break
  sleep 2
  if [[ $i -eq 60 ]]; then
    echo "  failed to obtain master-realm admin token after 2 minutes (user/pass wrong?)"
    exit 1
  fi
done

# Look up the vcplatform client by clientId. The vcplatform realm is
# imported asynchronously after Keycloak is up, so the realm or its
# clients may not exist for the first minute or two — retry until either
# success or 5-minute timeout.
CLIENT_UUID=""
for i in $(seq 1 150); do
  RESP=$(curl -sS -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_BASE/admin/realms/$KEYCLOAK_REALM/clients?clientId=$KEYCLOAK_CLIENT_ID" 2>/dev/null || echo '[]')
  CLIENT_UUID=$(echo "$RESP" | python3 -c 'import json,sys; arr=json.load(sys.stdin); print(arr[0]["id"]) if arr else print("")' 2>/dev/null || echo "")
  [[ -n "$CLIENT_UUID" ]] && break
  sleep 2
  if [[ $i -eq 150 ]]; then
    echo "  client $KEYCLOAK_CLIENT_ID not found in realm $KEYCLOAK_REALM after 5 minutes — was the realm imported?"
    echo "  hint: check 'docker logs waltid-keycloak-1 | grep -i import' for import errors"
    exit 1
  fi
done

# Pull current client config, fold new URIs into redirectUris + webOrigins,
# PUT back. Set-union via Python so re-runs don't keep growing the list.
CURRENT=$(curl -sS -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_BASE/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID")

UPDATED=$(PUBLIC_HOST="$PUBLIC_HOST" VERIFIABLY_HOST_PORT="$VERIFIABLY_HOST_PORT" \
  VERIFIABLY_CALLBACK_URL="$VERIFIABLY_CALLBACK_URL" \
  python3 -c '
import json, os, sys
from urllib.parse import urlparse
host = os.environ["PUBLIC_HOST"]
port = os.environ["VERIFIABLY_HOST_PORT"]
callback = os.environ.get("VERIFIABLY_CALLBACK_URL", "").strip()

client = json.load(sys.stdin)

# Legacy entries — present in every deploy so a fallback /etc/hosts
# entry pointed at the old host:port still completes a login.
want_redirect = {
    f"http://{host}:{port}/*",
    f"https://{host}/*",
    f"http://localhost:{port}/*",
}
want_origins = {
    f"http://{host}:{port}",
    f"https://{host}",
    f"http://localhost:{port}",
}

# Pattern-mode entries — derived from VERIFIABLY_CALLBACK_URL when set.
# Adds both the exact /* path-wildcard (Keycloak treats * as a path
# component, NOT a hostname wildcard, so the literal subdomain has to
# appear) and the bare origin for webOrigins. No-op when the callback
# is just the legacy form (entries collapse into want_redirect by union).
if callback:
    p = urlparse(callback)
    if p.scheme and p.netloc:
        origin = f"{p.scheme}://{p.netloc}"
        want_redirect.add(f"{origin}/*")
        want_origins.add(origin)

existing_redirect = set(client.get("redirectUris") or [])
existing_origins  = set(client.get("webOrigins") or [])

client["redirectUris"] = sorted(existing_redirect | want_redirect)
client["webOrigins"]   = sorted(existing_origins  | want_origins)

print(json.dumps(client))
' <<<"$CURRENT")

curl -sS -X PUT -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  "$KEYCLOAK_BASE/admin/realms/$KEYCLOAK_REALM/clients/$CLIENT_UUID" \
  -d "$UPDATED" > /dev/null

echo "  $KEYCLOAK_CLIENT_ID redirectUris now include http://$PUBLIC_HOST:$VERIFIABLY_HOST_PORT/* + https://$PUBLIC_HOST/*${VERIFIABLY_CALLBACK_URL:+ + ${VERIFIABLY_CALLBACK_URL%/auth/callback}/*}"
