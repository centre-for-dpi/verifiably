#!/bin/bash
# init.sh — certify-postgres initializer.
#
# When ISSUER_DID_DOMAIN is set (production/federation), all did_url rows in
# credential_config are written as did:web:{ISSUER_DID_DOMAIN} so issued
# credentials reference a publicly resolvable DID Document. Without it, the
# default did:web:certify-nginx is used (Docker-internal, dev only).
#
# The sed substitution only rewrites the did:web:certify-nginx literal, so
# credential VC templates that contain ${_issuer}, ${fullName}, etc. are
# untouched — those dollar braces are Certify's own template syntax.
set -euo pipefail

DID="did:web:${ISSUER_DID_DOMAIN:-certify-nginx}"

echo "certify-postgres init: issuer DID = ${DID}"

sed "s|did:web:certify-nginx|${DID}|g" \
    /var/init-templates/certify_init.sql \
    | psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"

# Ensure the postgres password is stored as SCRAM-SHA-256 (not md5).
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -c "ALTER USER postgres WITH PASSWORD '${POSTGRES_PASSWORD}';"
