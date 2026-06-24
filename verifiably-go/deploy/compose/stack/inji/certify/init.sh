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

# The schema template is mounted under different names per scenario
# (certify_init.sql for the base/pre-auth stacks, certify_init-authcode.sql for
# the auth-code stack). Apply whichever is present. CRITICAL: never abort on a
# missing template — with `set -e` an abort exits this script, which exits the
# container; docker then restarts it and inji-certify's
# `depends_on: condition: service_healthy` aborts the whole first `up all`.
# If no template is mounted, deploy.sh's idempotent post-up fallback seeds it.
TEMPLATE=""
for _f in /var/init-templates/certify_init-authcode.sql /var/init-templates/certify_init.sql; do
    [[ -f "$_f" ]] && { TEMPLATE="$_f"; break; }
done
if [[ -n "$TEMPLATE" ]]; then
    echo "certify-postgres init: applying ${TEMPLATE}"
    sed "s|did:web:certify-nginx|${DID}|g" "$TEMPLATE" \
        | psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"
else
    echo "certify-postgres init: no schema template mounted — deferring to deploy.sh fallback"
fi

# Ensure the postgres password is stored as SCRAM-SHA-256 (not md5).
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -c "ALTER USER postgres WITH PASSWORD '${POSTGRES_PASSWORD}';"
