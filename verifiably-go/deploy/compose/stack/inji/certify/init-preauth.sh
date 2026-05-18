#!/bin/bash
# init-preauth.sh — certify-preauth-postgres initializer.
#
# When ISSUER_DID_DOMAIN is set (production/federation), both the primary and
# pre-auth Certify instances use the SAME public DID (did:web:{domain}) because
# they represent the same issuing organization. The inji_proxy handler in
# verifiably-go merges both instances' keys into a single DID Document at
# /.well-known/did.json, so verifiers see one DID with multiple verification
# methods — no kid collision. In dev (no domain set), the preauth instance
# retains its own did:web:certify-preauth-nginx to keep the two Docker-internal
# DID Documents independent.
set -euo pipefail

if [ -n "${ISSUER_DID_DOMAIN:-}" ]; then
    DID="did:web:${ISSUER_DID_DOMAIN}"
else
    DID="did:web:certify-preauth-nginx"
fi

echo "certify-preauth-postgres init: issuer DID = ${DID}"

sed "s|did:web:certify-preauth-nginx|${DID}|g" \
    /var/init-templates/certify_init.sql \
    | psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"
