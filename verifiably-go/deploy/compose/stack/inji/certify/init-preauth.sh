#!/bin/bash
# init-preauth.sh — certify-preauth-postgres initializer.
#
# The seeded credential_config.did_url rows carry the pre-auth instance's issuer
# DID. PREAUTH_DID_DOMAIN (set by deploy.sh in subdomain mode = this instance's
# OWN public host) takes precedence so did_url is a PUBLICLY-resolvable did:web
# an external wallet can dereference (https://<host>/.well-known/did.json, served
# by certify-preauth-nginx from the pre-auth backend's key). This is decoupled
# from the shared ISSUER_DID_DOMAIN on purpose — moving that var would also point
# the internal primary auth-code instance at this subdomain's did.json (pre-auth
# key only) and break it. Falls back to ISSUER_DID_DOMAIN, then to the
# docker-internal did:web:certify-preauth-nginx (dev). Keep this DID consistent
# with the backend's CERTIFY_ISSUER_DID so issued VCs and the did.json agree.
set -euo pipefail

if [ -n "${PREAUTH_DID_DOMAIN:-}" ]; then
    DID="did:web:${PREAUTH_DID_DOMAIN}"
elif [ -n "${ISSUER_DID_DOMAIN:-}" ]; then
    DID="did:web:${ISSUER_DID_DOMAIN}"
else
    DID="did:web:certify-preauth-nginx"
fi

echo "certify-preauth-postgres init: issuer DID = ${DID}"

sed "s|did:web:certify-preauth-nginx|${DID}|g" \
    /var/init-templates/certify_init.sql \
    | psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"

# Ensure the postgres password is stored as SCRAM-SHA-256 (not md5).
# PostgreSQL 15 requires scram-sha-256 for network connections but a pre-existing
# volume may carry an md5 hash from an older run, causing HikariCP auth failures.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -c "ALTER USER postgres WITH PASSWORD '${POSTGRES_PASSWORD}';"
