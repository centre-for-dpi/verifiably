#!/usr/bin/env bash
# bootstrap-credebl.sh — CREDEBL platform bootstrap functions.
# Sourced by deploy.sh. Can also be sourced standalone after common.sh.
[[ "${_VERIFIABLY_COMMON_LOADED:-}" == "1" ]] || source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/common.sh"
# =============================================================================
# CREDEBL helpers
# =============================================================================

# ensure_credebl_env auto-generates secrets for any empty CREDEBL_* vars and
# writes deploy/compose/credebl/config/credebl.env with all the variables
# that CREDEBL services need. Called before docker compose up.
ensure_credebl_env() {
  # In subdomain mode, CREDEBL api-gateway and MinIO are fronted by Caddy
  # (credebl.<domain> and credebl-minio.<domain>) — compute their public URLs
  # the same way url_for() does for every other service.
  local _credebl_public_url _credebl_minio_public_url
  _credebl_public_url=$(url_for credebl "$VERIFIABLY_PUBLIC_HOST" "$CREDEBL_API_PORT")
  _credebl_minio_public_url=$(url_for credebl-minio "$VERIFIABLY_PUBLIC_HOST" "9002")

  local env_dir="$SCRIPT_DIR/deploy/compose/credebl/config"
  mkdir -p "$env_dir"
  local env_file="$env_dir/credebl.env"

  # On re-runs, reload previously-generated secrets so we don't regenerate
  # them and break the already-initialized postgres/minio volumes.
  # Use a line-by-line parser instead of `source` — values like "Inji Wallet"
  # contain spaces that bash would try to execute as commands when sourced.
  if [[ -f "$env_file" ]]; then
    while IFS='=' read -r _key _val; do
      # skip blank lines and comments
      [[ "$_key" =~ ^[[:space:]]*(#|$) ]] && continue
      [[ -z "${_key// /}" ]] && continue
      export "${_key}=${_val}"
    done < "$env_file"
  fi

  # Auto-generate any missing secrets
  [[ -z "$CREDEBL_POSTGRES_PASSWORD" ]]        && CREDEBL_POSTGRES_PASSWORD=$(openssl rand -hex 16)
  [[ -z "$CREDEBL_MINIO_ROOT_PASSWORD" ]]      && CREDEBL_MINIO_ROOT_PASSWORD=$(openssl rand -hex 16)
  [[ -z "$CREDEBL_MINIO_SECRET_KEY" ]]         && CREDEBL_MINIO_SECRET_KEY=$(openssl rand -hex 16)
  [[ -z "$CREDEBL_JWT_SECRET" ]]               && CREDEBL_JWT_SECRET=$(openssl rand -hex 32)
  [[ -z "$CREDEBL_JWT_TOKEN_SECRET" ]]         && CREDEBL_JWT_TOKEN_SECRET=$(openssl rand -hex 32)
  [[ -z "$CREDEBL_PLATFORM_SEED" ]]            && CREDEBL_PLATFORM_SEED=$(openssl rand -hex 16)
  [[ -z "$CREDEBL_AGENT_API_KEY" ]]            && CREDEBL_AGENT_API_KEY=$(openssl rand -hex 16)
  [[ -z "$CREDEBL_PLATFORM_WALLET_PASSWORD" ]] && CREDEBL_PLATFORM_WALLET_PASSWORD=$(openssl rand -hex 16)
  [[ -z "$CREDEBL_NEXTAUTH_SECRET" ]]          && CREDEBL_NEXTAUTH_SECRET=$(openssl rand -hex 32)
  [[ -z "$CREDEBL_KEYCLOAK_CLIENT_SECRET" ]]   && CREDEBL_KEYCLOAK_CLIENT_SECRET=$(openssl rand -hex 16)
  [[ -z "$CREDEBL_SCHEMA_FILE_SERVER_TOKEN" ]] && CREDEBL_SCHEMA_FILE_SERVER_TOKEN=$(openssl rand -hex 32)
  # schema-file-server needs CRYPTO_PRIVATE_KEY as base64 of the raw key.
  # Export so the compose environment: block can substitute it via ${VAR}.
  export CREDEBL_SCHEMA_FILE_SERVER_CRYPTO_KEY
  CREDEBL_SCHEMA_FILE_SERVER_CRYPTO_KEY=$(printf '%s' "$CREDEBL_CRYPTO_PRIVATE_KEY" | base64 | tr -d '\n')

  # KEYCLOAK_ADMIN_PASSWORD comes from the shared compose Keycloak (compose default is "admin")
  local _kc_admin_pass="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

  cat > "$env_file" <<EOF
POSTGRES_USER=credebl
POSTGRES_PASSWORD=${CREDEBL_POSTGRES_PASSWORD}
POSTGRES_DB=credebl
DATABASE_URL=postgresql://credebl:${CREDEBL_POSTGRES_PASSWORD}@credebl-postgres:5432/credebl
POOL_DATABASE_URL=postgresql://credebl:${CREDEBL_POSTGRES_PASSWORD}@credebl-postgres:5432/credebl
REDIS_HOST=credebl-redis
REDIS_PORT=6379
REDIS_PASSWORD=
NATS_AUTH_TYPE=none
NATS_URL=nats://credebl-nats:4222
HIDE_EXPERIMENTAL_OIDC_CONTROLLERS=false
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=${_kc_admin_pass}
KEYCLOAK_DOMAIN=http://keycloak:${KEYCLOAK_PORT}/
KEYCLOAK_ADMIN_URL=http://keycloak:${KEYCLOAK_PORT}
KEYCLOAK_MASTER_REALM=master
KEYCLOAK_REALM=credebl-realm
KEYCLOAK_CLIENT_ID=credebl-client
KEYCLOAK_CLIENT_SECRET=${CREDEBL_KEYCLOAK_CLIENT_SECRET}
KEYCLOAK_MANAGEMENT_CLIENT_ID=adminClient
KEYCLOAK_MANAGEMENT_CLIENT_SECRET=${CREDEBL_KEYCLOAK_CLIENT_SECRET}
PLATFORM_ADMIN_KEYCLOAK_ID=credebl-client
PLATFORM_ADMIN_KEYCLOAK_SECRET=${CREDEBL_KEYCLOAK_CLIENT_SECRET}
ADMIN_KEYCLOAK_ID=adminClient
ADMIN_KEYCLOAK_SECRET=${CREDEBL_KEYCLOAK_CLIENT_SECRET}
PLATFORM_ADMIN_OLD_CLIENT_ID=
SUPPORTED_SSO_CLIENTS=CREDEBL
PLATFORM_ADMIN_INITIAL_PASSWORD=changeme
KEYCLOAK_PUBLIC_URL=http://${VERIFIABLY_PUBLIC_HOST}:${KEYCLOAK_PORT}
KEYCLOAK_HOST=${CREDEBL_KEYCLOAK_HOST}
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=${CREDEBL_MINIO_ROOT_PASSWORD}
MINIO_CONSOLE_PORT=${CREDEBL_MINIO_CONSOLE_PORT}
AWS_ACCESS_KEY_ID=${CREDEBL_MINIO_ACCESS_KEY}
AWS_SECRET_ACCESS_KEY=${CREDEBL_MINIO_SECRET_KEY}
AWS_ACCESS_KEY=${CREDEBL_MINIO_ACCESS_KEY}
AWS_SECRET_KEY=${CREDEBL_MINIO_SECRET_KEY}
AWS_PUBLIC_ACCESS_KEY=${CREDEBL_MINIO_ACCESS_KEY}
AWS_PUBLIC_SECRET_KEY=${CREDEBL_MINIO_SECRET_KEY}
AWS_PUBLIC_REGION=us-east-1
AWS_ENDPOINT=http://credebl-minio:9000
AWS_REGION=us-east-1
S3_BUCKET_NAME=credebl-bucket
S3_STOREOBJECT_BUCKET=credebl-bucket
AWS_BUCKET=credebl-bucket
AWS_S3_STOREOBJECT_ACCESS_KEY=${CREDEBL_MINIO_ACCESS_KEY}
AWS_S3_STOREOBJECT_SECRET_KEY=${CREDEBL_MINIO_SECRET_KEY}
AWS_S3_STOREOBJECT_REGION=us-east-1
AWS_S3_STOREOBJECT_BUCKET=credebl-bucket
AWS_S3_STOREOBJECT_ENDPOINT=http://credebl-minio:9000
EMAIL_PROVIDER=smtp
SENDGRID_API_KEY=SG.mock-not-used
SMTP_HOST=credebl-mailpit
SMTP_PORT=1025
SMTP_SECURE=false
SMTP_USER=mailpit
SMTP_PASS=mailpit
EMAIL_FROM=noreply@cdpi-poc.local
API_GATEWAY_PROTOCOL=http
API_GATEWAY_HOST=0.0.0.0
API_GATEWAY_PORT=5000
PLATFORM_SEED=${CREDEBL_PLATFORM_SEED}
JWT_SECRET=${CREDEBL_JWT_SECRET}
JWT_EXPIRY=1d
NEXTAUTH_SECRET=${CREDEBL_NEXTAUTH_SECRET}
NEXTAUTH_COOKIE_DOMAIN=
API_ENDPOINT=${_credebl_public_url#http://}
VPS_IP=${VERIFIABLY_PUBLIC_HOST}
PLATFORM_WEB_URL=${_credebl_public_url}
FRONT_END_URL=${_credebl_public_url}
STUDIO_URL=${_credebl_public_url}
SOCKET_HOST=http://credebl-api-gateway:5000
ENABLE_CORS_IP_LIST=${_credebl_public_url},http://localhost:${CREDEBL_API_PORT}
SHORTENED_URL_DOMAIN=${_credebl_public_url}
DEEPLINK_DOMAIN=${_credebl_minio_public_url}/credebl-bucket
MOBILE_APP=Inji Wallet
MOBILE_APP_NAME=Inji Wallet
MOBILE_APP_DOWNLOAD_URL=https://inji.io
PLAY_STORE_DOWNLOAD_LINK=https://play.google.com/store/apps/details?id=io.mosip.residentapp
IOS_DOWNLOAD_LINK=https://apps.apple.com/in/app/inji-wallet/id1631979601
APP_PROTOCOL=http
BRAND_LOGO=http://${VERIFIABLY_PUBLIC_HOST}:9002/credebl-bucket/orgLogos/credebl-logo.png
PLATFORM_NAME=CREDEBL
PUBLIC_PLATFORM_SUPPORT_EMAIL=support@cdpi-poc.local
POWERED_BY=CDPI
POWERED_BY_URL=https://cdpi.dev
ORGANIZATION=credebl
CONTEXT=platform
APP=api
CONSOLE_LOG_FLAG=true
ELK_LOG=false
LOG_LEVEL=info
NEXT_PUBLIC_ACTIVE_THEME=credebl
OOB_BATCH_SIZE=50
PROOF_REQ_CONN_LIMIT=50
PLATFORM_ADMIN_EMAIL=${CREDEBL_ADMIN_EMAIL}
CRYPTO_PRIVATE_KEY=${CREDEBL_CRYPTO_PRIVATE_KEY}
PLATFORM_WALLET_NAME=platformadminwallet
PLATFORM_WALLET_PASSWORD=${CREDEBL_PLATFORM_WALLET_PASSWORD}
AGENT_API_KEY=${CREDEBL_AGENT_API_KEY}
AGENT_PROTOCOL=http
WALLET_STORAGE_HOST=172.17.0.1
WALLET_STORAGE_PORT=5432
WALLET_STORAGE_USER=credebl
WALLET_STORAGE_PASSWORD=${CREDEBL_POSTGRES_PASSWORD}
GEO_LOCATION_MASTER_DATA_IMPORT_SCRIPT=libs/prisma-service/prisma/scripts/geo_location_data_import.sh
UPDATE_CLIENT_CREDENTIAL_SCRIPT=libs/prisma-service/prisma/scripts/update_client_credential_data.sh
LEDGER_URL=http://test.bcovrin.vonx.io
GENESIS_URL=http://test.bcovrin.vonx.io/genesis
AGENT_PORT_START=8200
AGENT_PORT_END=8299
INBOUND_PORT_START=9200
AFJ_VERSION=ghcr.io/credebl/credo-controller:latest
AFJ_AGENT_SPIN_UP=/agent-provisioning/AFJ/scripts/docker_start_agent.sh
AFJ_AGENT_ENDPOINT_PATH=/agent-provisioning/AFJ/endpoints/
TAILS_FILE_SERVER=https://tails.vonx.io
SCHEMA_FILE_SERVER_PORT=4000
SCHEMA_FILE_SERVER_URL=http://credebl-schema-file-server:4000/schemas/
NEXT_PUBLIC_SCHEMA_FILE_SERVER_URL=http://credebl-schema-file-server:4000/schemas/
SCHEMA_FILE_SERVER_TOKEN=${CREDEBL_SCHEMA_FILE_SERVER_TOKEN}
JWT_TOKEN_SECRET=${CREDEBL_JWT_TOKEN_SECRET}
ISSUER=Credebl
CREDENTIAL_FORMAT=SD_JWT_VC
# Internal deploy.sh names — reloaded on re-runs so secrets are not regenerated
CREDEBL_POSTGRES_PASSWORD=${CREDEBL_POSTGRES_PASSWORD}
CREDEBL_MINIO_ROOT_PASSWORD=${CREDEBL_MINIO_ROOT_PASSWORD}
CREDEBL_MINIO_SECRET_KEY=${CREDEBL_MINIO_SECRET_KEY}
CREDEBL_JWT_SECRET=${CREDEBL_JWT_SECRET}
CREDEBL_JWT_TOKEN_SECRET=${CREDEBL_JWT_TOKEN_SECRET}
CREDEBL_PLATFORM_SEED=${CREDEBL_PLATFORM_SEED}
CREDEBL_AGENT_API_KEY=${CREDEBL_AGENT_API_KEY}
CREDEBL_PLATFORM_WALLET_PASSWORD=${CREDEBL_PLATFORM_WALLET_PASSWORD}
CREDEBL_NEXTAUTH_SECRET=${CREDEBL_NEXTAUTH_SECRET}
CREDEBL_KEYCLOAK_CLIENT_SECRET=${CREDEBL_KEYCLOAK_CLIENT_SECRET}
CREDEBL_SCHEMA_FILE_SERVER_TOKEN=${CREDEBL_SCHEMA_FILE_SERVER_TOKEN}
EOF
  green "  wrote $env_file"
}

# write_credebl_agent_runtime_env creates the .agent-runtime/ directory structure
# and writes agent.env for the agent-provisioning + agent-service bind mounts.
write_credebl_agent_runtime_env() {
  local base="$SCRIPT_DIR/deploy/compose/credebl/.agent-runtime"
  mkdir -p "$base/agent-config" "$base/token" "$base/endpoints"
  # Guard against previous run leaving agent.env as a directory
  [[ -d "$base/agent.env" ]] && rm -rf "$base/agent.env"

  # Clean up stale agent endpoint/config files from prior runs.
  # agent-provisioning tracks allocated ports via these files and increments to
  # the next available one on each run; stale entries (orphaned from resets or
  # failed runs) push the port ever higher, causing a mismatch between the
  # nginx proxy_pass target and the port the newly-provisioned agent actually
  # listens on. Delete any file whose corresponding Credo container is gone.
  local _stale _stale_uuid
  for _stale in "$base/endpoints/"*_Platform-admin.json "$base/agent-config/"*_Platform-admin.json; do
    [[ -f "$_stale" ]] || continue
    _stale_uuid="$(basename "$_stale" | grep -oE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' || true)"
    if [[ -n "$_stale_uuid" ]] && ! docker ps --filter "name=${_stale_uuid}_" --format '{{.Names}}' 2>/dev/null | grep -q .; then
      rm -f "$_stale"
    fi
  done
  # Always compute the IP-based URLs first.
  local _ip_http_url="http://${VERIFIABLY_PUBLIC_HOST}"
  local _ip_ws_url="ws://${VERIFIABLY_PUBLIC_HOST}"
  local _agent_api_port="${CREDEBL_AGENT_API_PORT:-8001}"

  # In domain mode, AGENT_HTTP_URL is set to the public HTTPS domain URL so that:
  #   1. The Credo agent embeds the domain in OID4VCI metadata natively.
  #   2. DPoP htu validation succeeds: wallet sends htu=https://credebl.domain/...
  #      and the agent expects the same URL — they must match exactly.
  # agent-service uses CONTROLLER_ENDPOINT (IP:port from endpoints JSON), not
  # AGENT_HTTP_URL, so changing to the domain URL is safe for inter-service calls.
  local _agent_http_url="$_ip_http_url"
  local _agent_ws_url="$_ip_ws_url"
  local _public_base=""
  if [[ -n "$VERIFIABLY_PUBLIC_DOMAIN" ]]; then
    local _cslug
    _cslug=$(resolve_slug "credebl" 2>/dev/null || echo "credebl")
    if [[ -n "$_cslug" ]]; then
      _public_base="https://${_cslug}.${VERIFIABLY_PUBLIC_DOMAIN}"
      _agent_http_url="$_public_base"
      _agent_ws_url="wss://${_cslug}.${VERIFIABLY_PUBLIC_DOMAIN}"
    fi
  fi
  : "${_public_base:=$_ip_http_url}"  # fallback: IP (nginx sub_filter becomes a no-op)

  # Ledger config: operator can override via env vars; BCovrin test is the
  # safe demo default. Production deployments MUST set CREDEBL_LEDGER_URL and
  # CREDEBL_GENESIS_URL to a production-grade ledger (Sovrin MainNet, etc.).
  local _ledger_url="${CREDEBL_LEDGER_URL:-http://test.bcovrin.vonx.io}"
  local _genesis_url="${CREDEBL_GENESIS_URL:-http://test.bcovrin.vonx.io/genesis}"
  local _tails_url="${CREDEBL_TAILS_FILE_SERVER:-https://tails.vonx.io}"

  # Session limits: default to reasonable values tuned for a single-server
  # demo/pilot. Operator can override via CREDEBL_SESSION_LIMIT and
  # CREDEBL_SESSION_ACQUIRE_TIMEOUT (ms). 2147483647 (Int32.MAX) was the
  # previous placeholder — effectively unbounded, which risks memory exhaustion.
  local _session_limit="${CREDEBL_SESSION_LIMIT:-500}"
  local _session_acquire_timeout="${CREDEBL_SESSION_ACQUIRE_TIMEOUT:-30000}"

  # ALLOW_INSECURE_HTTP_URLS: only needed in IP-only (non-TLS) mode.
  # In domain mode the agent communicates over HTTPS, so insecure URLs are not
  # required and should be disabled for security.
  local _allow_insecure="true"
  [[ -n "$VERIFIABLY_PUBLIC_DOMAIN" ]] && _allow_insecure="false"

  cat > "$base/agent.env" <<EOF
LEDGER_URL=${_ledger_url}
GENESIS_URL=${_genesis_url}
TAILS_FILE_SERVER=${_tails_url}
AGENT_HTTP_URL=${_agent_http_url}
AGENT_WS_URL=${_agent_ws_url}
CONNECT_TIMEOUT=10
MAX_CONNECTIONS=1000
IDLE_TIMEOUT=30000
SESSION_ACQUIRE_TIMEOUT=${_session_acquire_timeout}
SESSION_LIMIT=${_session_limit}
INMEMORY_LRU_CACHE_LIMIT=${_session_limit}
TRUST_SERVICE_AUTH_TYPE=NoAuth
TRUST_LIST_URL=http://credebl-api-gateway:5000/orgs/agent-invitation/trust
ALLOW_INSECURE_HTTP_URLS=${_allow_insecure}
EOF
  green "  wrote $base/agent.env (AGENT_HTTP_URL=${_agent_http_url}, ALLOW_INSECURE=${_allow_insecure}, SESSION_LIMIT=${_session_limit})"

  # Generate nginx-oid4vci.conf — mounts into credebl-oid4vci-rewriter.
  # In domain mode the agent already embeds the domain URL natively, so
  # sub_filter '_ip_http_url' → '_public_base' is a transparent no-op (nothing
  # to replace). In IP-only mode _public_base == _ip_http_url, also a no-op.
  # The nginx sidecar remains as a passthrough safety net in both modes.
  # Rate limit: allow operator to tune; defaults are conservative for a demo
  # server. Each wallet session makes ~3 requests (auth + VP + poll), so
  # 10r/s per IP with a burst of 30 handles ~10 concurrent wallet sessions
  # without tripping over normal usage. Raise for higher-traffic pilots.
  local _rate_limit="${CREDEBL_NGINX_RATE_LIMIT:-10r/s}"
  local _rate_burst="${CREDEBL_NGINX_RATE_BURST:-30}"

  cat > "$base/nginx-oid4vci.conf" <<NGINXEOF
# Rate-limit zone: keyed by client IP, 10 MB shared memory (~160k IPs).
limit_req_zone \$binary_remote_addr zone=oid4vc:10m rate=${_rate_limit};
limit_req_status 429;

server {
    listen 80;

    # Only expose OID4VCI and OID4VP wallet-facing paths.
    # The Credo agent's control-plane and admin endpoints are NOT forwarded.
    location ~ ^/(oid4vci|oid4vp|openid4vc)/ {
        limit_req zone=oid4vc burst=${_rate_burst} nodelay;

        proxy_pass http://host.docker.internal:${_agent_api_port};
        proxy_http_version 1.1;
        # Disable upstream compression so sub_filter can read the plain body.
        proxy_set_header Accept-Encoding "";

        sub_filter_once off;
        sub_filter_types application/json text/plain;
        sub_filter '${_ip_http_url}' '${_public_base}';
    }

    # Block all other paths — return 404 rather than proxying agent internals.
    location / {
        return 404;
    }
}
NGINXEOF
  green "  wrote $base/nginx-oid4vci.conf (${_ip_http_url} → ${_public_base})"
}

# _credebl_configure_oid4vci_rewriter detects the actual admin port of the
# running Credo agent (assigned dynamically by agent-provisioning), updates
# nginx-oid4vci.conf's proxy_pass target to match, then starts or restarts
# credebl-oid4vci-rewriter. Called after ensure_credebl_platform_admin_shared_agent
# because the Credo container doesn't exist until provisioning completes.
_credebl_configure_oid4vci_rewriter() {
  local base="$SCRIPT_DIR/deploy/compose/credebl/.agent-runtime"
  local nginx_conf="$base/nginx-oid4vci.conf"

  # Find the running Credo agent container (UUID-named pattern).
  local credo_container
  credo_container="$(docker ps --format '{{.Names}}' \
    | grep -E '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_' \
    | head -1)"
  if [[ -z "$credo_container" ]]; then
    red "  No Credo agent container running — skipping OID4VCI rewriter config"
    return 1
  fi

  # Look up adminPort in the agent-config JSON for this container.
  local config_file="$base/agent-config/${credo_container}.json"
  if [[ ! -f "$config_file" ]]; then
    red "  Agent config not found: $config_file"
    return 1
  fi
  local actual_port
  # python3 -c open() fails on Windows/Git Bash because the bash /c/... path
  # is not a valid Windows path; use grep instead which follows the shell's CWD.
  actual_port="$(grep -o '"adminPort":[[:space:]]*[0-9]*' "$config_file" | grep -o '[0-9]*$')"
  if [[ -z "$actual_port" ]]; then
    red "  Could not read adminPort from $config_file"
    return 1
  fi

  # Patch the proxy_pass line if the port has changed.
  local current_port
  current_port="$(grep 'proxy_pass' "$nginx_conf" 2>/dev/null \
    | grep -oE ':[0-9]+;' | tr -d ':;' || true)"
  if [[ "$current_port" != "$actual_port" ]]; then
    sed -i "s|proxy_pass http://host.docker.internal:[0-9]*;|proxy_pass http://host.docker.internal:${actual_port};|" "$nginx_conf"
    green "  Updated nginx-oid4vci.conf: port ${current_port:-?} → ${actual_port}"
  else
    green "  nginx-oid4vci.conf already using port ${actual_port}"
  fi

  # Start or restart the rewriter so it picks up the patched config.
  local _profile_args=()
  [[ -n "${VERIFIABLY_HOSTS_PATTERN:-}" ]] && _profile_args+=( --profile subdomain )
  if docker ps --format '{{.Names}}' | grep -q '^credebl-oid4vci-rewriter$'; then
    compose "${_profile_args[@]}" restart credebl-oid4vci-rewriter >/dev/null \
      && green "  Restarted credebl-oid4vci-rewriter (port ${actual_port})"
  else
    compose "${_profile_args[@]}" up -d credebl-oid4vci-rewriter \
      && green "  Started credebl-oid4vci-rewriter (port ${actual_port})"
  fi
}

# bootstrap_credebl_keycloak_realm imports the credebl-realm into the shared
# Keycloak. Idempotent — skips import when the realm already exists, but always
# patches redirectUris and client-scope links so they reflect the current domain.
bootstrap_credebl_keycloak_realm() {
  local kc_base="http://localhost:${KEYCLOAK_PORT}"
  local realm_file="$SCRIPT_DIR/deploy/compose/credebl/config/keycloak-realm.json"
  local _kc_admin_pass="${KEYCLOAK_ADMIN_PASSWORD:-admin}"

  # Use the canonical public URL computed by url_for via common.sh.
  # When VERIFIABLY_PUBLIC_DOMAIN=verifiably.ysalabs.work, the "verifiably"
  # slug matches the first label so url_for returns the bare domain
  # (https://verifiably.ysalabs.work), not a double-prefixed subdomain.
  local _verifiably_url="${VERIFIABLY_PUBLIC_URL:-}"

  # Helper: fetch a fresh admin-cli token. Called at start and again after
  # the realm import which can take > 60 s (KC default token TTL).
  _kc_token() {
    curl -sf --max-time 15 -X POST \
      "$kc_base/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "client_id=admin-cli&username=admin&password=${_kc_admin_pass}&grant_type=password" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' 2>/dev/null
  }

  # Wait for Keycloak
  local tries=0
  while ! curl -sf --max-time 5 "$kc_base/realms/master/.well-known/openid-configuration" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [[ $tries -gt 60 ]]; then
      red "  Keycloak not reachable after 60s — skipping CREDEBL realm import"
      return 1
    fi
    sleep 2
  done

  local token
  token=$(_kc_token) || true
  if [[ -z "$token" ]]; then
    red "  Could not get Keycloak admin token — skipping CREDEBL realm import"
    return 1
  fi

  # Check if realm already exists (use HTTP status directly — avoids python3 pipe failures on Windows)
  local realm_http
  realm_http=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    "$kc_base/admin/realms/credebl-realm" \
    -H "Authorization: Bearer ${token}" 2>/dev/null) || realm_http=""

  if [[ "$realm_http" == "200" ]]; then
    green "  credebl-realm already exists in Keycloak — skipping import"
  else
    green "  Importing credebl-realm into Keycloak"
    # Patch redirectUris to include both the IP-based studio URL and, when in
    # domain mode, the verifiably-go domain URL so the OIDC callback succeeds.
    local patched_realm
    patched_realm=$(python3 - "$realm_file" "${VERIFIABLY_PUBLIC_HOST}" "${CREDEBL_API_PORT}" "${CREDEBL_KEYCLOAK_CLIENT_SECRET}" "${_verifiably_url}" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    realm = json.load(f)
host, port, client_secret, verifiably_url = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
studio_url = f"http://{host}:{port}"
redirect_uris = [f"{studio_url}/*", "http://localhost/*"]
web_origins   = [studio_url, "http://localhost"]
if verifiably_url:
    redirect_uris += [f"{verifiably_url}/*", f"{verifiably_url}/auth/callback"]
    web_origins.append(verifiably_url)
for client in realm.get("clients", []):
    if client.get("clientId") in ("credebl-client", "adminClient"):
        client["redirectUris"] = redirect_uris
        client["webOrigins"]   = web_origins
        # Replace the ${KEYCLOAK_CLIENT_SECRET} placeholder with the actual secret
        if client.get("secret", "").startswith("${"):
            client["secret"] = client_secret
print(json.dumps(realm))
PY
) || true
    if [[ -n "$patched_realm" ]]; then
      curl -sf --max-time 30 -X POST \
        "$kc_base/admin/realms" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$patched_realm" >/dev/null \
        && green "  credebl-realm imported successfully" \
        || red "  Realm import failed — check Keycloak logs"
    else
      red "  Failed to patch realm JSON — importing as-is"
      curl -sf --max-time 30 -X POST \
        "$kc_base/admin/realms" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        --data-binary "@$realm_file" >/dev/null \
        && green "  credebl-realm imported" \
        || red "  Realm import failed — check Keycloak logs"
    fi
  fi

  # Refresh token — the realm import above can take > 60 s (KC default TTL),
  # which would silently break every subsequent API call.
  token=$(_kc_token) || true
  if [[ -z "$token" ]]; then
    red "  Could not refresh KC token after realm import — scope/redirect fixes skipped"
    return 0
  fi

  # Idempotently sync client secret and (in domain mode) redirectUris/webOrigins.
  # Runs unconditionally so a fresh token after realm import never leaves the
  # client with a blank secret or stale redirect URIs.
  local _kc_client_secret="${CREDEBL_KEYCLOAK_CLIENT_SECRET:-}"
  # Fall back to reading credebl.env directly (e.g. when called standalone).
  if [[ -z "$_kc_client_secret" ]]; then
    local _credebl_env="$SCRIPT_DIR/deploy/compose/credebl/config/credebl.env"
    [[ -f "$_credebl_env" ]] && \
      _kc_client_secret=$(grep '^CREDEBL_KEYCLOAK_CLIENT_SECRET=' "$_credebl_env" \
        | cut -d= -f2- | tr -d '\r')
  fi
  for client_name in credebl-client adminClient; do
    local client_id
    client_id=$(curl -sf --max-time 10 \
      "$kc_base/admin/realms/credebl-realm/clients?clientId=${client_name}" \
      -H "Authorization: Bearer ${token}" \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")' 2>/dev/null) || true
    [[ -z "$client_id" ]] && continue
    # Write current client JSON to a temp file to avoid pipe+heredoc conflict.
    local tmp_client
    tmp_client=$(mktemp /tmp/kc_client_XXXXXX.json)
    curl -sf --max-time 10 \
      "$kc_base/admin/realms/credebl-realm/clients/${client_id}" \
      -H "Authorization: Bearer ${token}" \
      -o "$tmp_client" 2>/dev/null || true
    local patched_client
    patched_client=$(python3 - "${_verifiably_url}" "${_kc_client_secret}" "$tmp_client" <<'PY'
import json, sys
verifiably_url, client_secret, client_file = sys.argv[1], sys.argv[2], sys.argv[3]
with open(client_file) as f:
    client = json.load(f)
# Always sync the client secret so a realm re-import never leaves it blank.
if client_secret:
    client["secret"] = client_secret
# Add domain redirect URIs when in domain mode.
if verifiably_url:
    uris = client.get("redirectUris", [])
    for u in [f"{verifiably_url}/*", f"{verifiably_url}/auth/callback"]:
        if u not in uris:
            uris.append(u)
    client["redirectUris"] = uris
    origins = client.get("webOrigins", [])
    if verifiably_url not in origins:
        origins.append(verifiably_url)
    client["webOrigins"] = origins
print(json.dumps(client))
PY
) || true
    rm -f "$tmp_client"
    if [[ -n "$patched_client" ]]; then
      curl -sf --max-time 10 -X PUT \
        "$kc_base/admin/realms/credebl-realm/clients/${client_id}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$patched_client" >/dev/null || true
    fi
  done
  [[ -n "$_verifiably_url" ]] && \
    green "  client secret + redirectUris synced (domain: $_verifiably_url)" || \
    green "  client secret synced"

  # Helper: fetch or create a client-scope by name; prints the scope UUID.
  _kc_ensure_scope() {
    local scope_name="$1" scope_body="$2"
    local sid
    sid=$(curl -sf --max-time 10 \
      "$kc_base/admin/realms/credebl-realm/client-scopes" \
      -H "Authorization: Bearer ${token}" \
      | python3 -c "import json,sys; s=[x['id'] for x in json.load(sys.stdin) if x['name']=='${scope_name}']; print(s[0] if s else '')" 2>/dev/null) || true
    if [[ -z "$sid" ]]; then
      curl -sf --max-time 15 -X POST \
        "$kc_base/admin/realms/credebl-realm/client-scopes" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$scope_body" >/dev/null || true
      sid=$(curl -sf --max-time 10 \
        "$kc_base/admin/realms/credebl-realm/client-scopes" \
        -H "Authorization: Bearer ${token}" \
        | python3 -c "import json,sys; s=[x['id'] for x in json.load(sys.stdin) if x['name']=='${scope_name}']; print(s[0] if s else '')" 2>/dev/null) || true
      [[ -n "$sid" ]] && green "  ${scope_name} scope created (id: $sid)"
    fi
    echo "$sid"
  }

  # Ensure openid scope with sub claim (required for keycloakUserId lookup)
  local openid_scope_id
  openid_scope_id=$(_kc_ensure_scope "openid" '{
    "name": "openid",
    "description": "OpenID Connect built-in scope",
    "protocol": "openid-connect",
    "attributes": {"include.in.token.scope": "true"},
    "protocolMappers": [{"name": "sub", "protocol": "openid-connect",
      "protocolMapper": "oidc-sub-mapper", "consentRequired": false,
      "config": {"access.token.sub.claim": "true", "id.token.sub.claim": "true"}}]
  }')

  # Ensure profile scope (name/given_name/family_name/preferred_username)
  local profile_scope_id
  profile_scope_id=$(_kc_ensure_scope "profile" '{
    "name": "profile",
    "description": "OpenID Connect built-in scope: user profile",
    "protocol": "openid-connect",
    "attributes": {"include.in.token.scope": "true"},
    "protocolMappers": [
      {"name": "full name", "protocol": "openid-connect",
       "protocolMapper": "oidc-full-name-mapper", "consentRequired": false,
       "config": {"id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}},
      {"name": "given name", "protocol": "openid-connect",
       "protocolMapper": "oidc-usermodel-attribute-mapper", "consentRequired": false,
       "config": {"userinfo.token.claim": "true", "user.attribute": "firstName",
         "id.token.claim": "true", "access.token.claim": "true",
         "claim.name": "given_name", "jsonType.label": "String"}},
      {"name": "family name", "protocol": "openid-connect",
       "protocolMapper": "oidc-usermodel-attribute-mapper", "consentRequired": false,
       "config": {"userinfo.token.claim": "true", "user.attribute": "lastName",
         "id.token.claim": "true", "access.token.claim": "true",
         "claim.name": "family_name", "jsonType.label": "String"}},
      {"name": "username", "protocol": "openid-connect",
       "protocolMapper": "oidc-usermodel-attribute-mapper", "consentRequired": false,
       "config": {"userinfo.token.claim": "true", "user.attribute": "username",
         "id.token.claim": "true", "access.token.claim": "true",
         "claim.name": "preferred_username", "jsonType.label": "String"}}
    ]
  }')

  # Ensure email scope
  local email_scope_id
  email_scope_id=$(_kc_ensure_scope "email" '{
    "name": "email",
    "description": "OpenID Connect built-in scope: email address",
    "protocol": "openid-connect",
    "attributes": {"include.in.token.scope": "true"},
    "protocolMappers": [
      {"name": "email", "protocol": "openid-connect",
       "protocolMapper": "oidc-usermodel-attribute-mapper", "consentRequired": false,
       "config": {"userinfo.token.claim": "true", "user.attribute": "email",
         "id.token.claim": "true", "access.token.claim": "true",
         "claim.name": "email", "jsonType.label": "String"}},
      {"name": "email verified", "protocol": "openid-connect",
       "protocolMapper": "oidc-usermodel-property-mapper", "consentRequired": false,
       "config": {"userinfo.token.claim": "true", "user.attribute": "emailVerified",
         "id.token.claim": "true", "access.token.claim": "true",
         "claim.name": "email_verified", "jsonType.label": "boolean"}}
    ]
  }')

  # Link all scopes to credebl-client and adminClient
  for client_name in credebl-client adminClient; do
    local client_id
    client_id=$(curl -sf --max-time 10 \
      "$kc_base/admin/realms/credebl-realm/clients?clientId=${client_name}" \
      -H "Authorization: Bearer ${token}" \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")' 2>/dev/null) || true
    if [[ -n "$client_id" ]]; then
      for sid in "$openid_scope_id" "$profile_scope_id" "$email_scope_id"; do
        [[ -z "$sid" ]] && continue
        curl -sf --max-time 10 -X PUT \
          "$kc_base/admin/realms/credebl-realm/clients/${client_id}/default-client-scopes/${sid}" \
          -H "Authorization: Bearer ${token}" >/dev/null || true
      done
    fi
  done
  green "  openid/profile/email scopes linked to credebl-client and adminClient"
}

# ---- CREDEBL container patch functions ----
# Each function is idempotent (checks for guard string before patching).
# These are ported from cdpi-poc/credebl/init-credebl.sh.

_credebl_patch_utility_s3() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_utility_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/utility/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('s3ForcePathStyle')) { process.stdout.write('already patched\n'); process.exit(0); }
const marker = 'new aws_sdk_1.S3({';
let count = 0;
let idx = 0;
while ((idx = content.indexOf(marker, idx)) >= 0) {
  const insertAt = idx + marker.length;
  const inject = 'endpoint:process.env.AWS_ENDPOINT,s3ForcePathStyle:true,';
  content = content.substring(0, insertAt) + inject + content.substring(insertAt);
  idx = insertAt + inject.length;
  count++;
}
if (count === 0) { process.stderr.write('ERROR: aws_sdk_1.S3 constructor not found\n'); process.exit(1); }
fs.writeFileSync(path, content);
process.stdout.write('patched (' + count + ' occurrences)\n');
JSEOF
  docker cp "$patch_script" credebl-utility:/tmp/patch_utility.js
  rm -f "$patch_script"
  docker exec --user root credebl-utility node //tmp/patch_utility.js
}

_credebl_patch_api_gateway_context_validator() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_api_gw_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/api-gateway/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('PATCH2: require_tld+normalize')) { process.stdout.write('already patched\n'); process.exit(0); }
const funcIdx = content.indexOf('function IsCredentialJsonLdContext');
if (funcIdx < 0) { process.stderr.write('ERROR: function IsCredentialJsonLdContext not found\n'); process.exit(1); }
const target = '(0, class_validator_1.isURL)(v)';
const after = content.indexOf(target, funcIdx);
if (after < 0 || after > funcIdx + 1000) { process.stderr.write('ERROR: isURL(v) call not found near function\n'); process.exit(1); }
const replacement = '/*PATCH2: require_tld+normalize*/(function(u){while(u&&u.indexOf("://http")>0){u=u.slice(u.indexOf("://http")+3);}return (0,class_validator_1.isURL)(u,{require_tld:false});})(v)';
content = content.substring(0, after) + replacement + content.substring(after + target.length);
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" credebl-api-gateway:/tmp/patch_api_gw.js
  rm -f "$patch_script"
  docker exec --user root credebl-api-gateway node //tmp/patch_api_gw.js
}

_credebl_patch_credo_credential_events() {
  local credo_container
  # Credo containers are named <UUID>_<org-name> (e.g. 70b082ae-..._Platform-admin)
  credo_container="$(docker ps --format '{{.Names}}' | grep -E '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_' | head -1)"
  if [[ -z "$credo_container" ]]; then
    echo "no Credo container yet — skipping"
    return 0
  fi
  local patch_script
  patch_script="$(mktemp /tmp/patch_credo_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/build/events/CredentialEvents.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('getFormatData unavailable')) { process.stdout.write('already patched\n'); process.exit(0); }
if (content.includes('withTenantAgent')) { process.stdout.write('new API (no patch needed)\n'); process.exit(0); }
const pattern = /^(\s+)const data = await agent\.modules\.credentials\.getFormatData\(record\.id\);\n\s+body\.credentialData = data;/m;
const m = content.match(pattern);
if (!m) { process.stderr.write('ERROR: patch target not found in CredentialEvents.js\n'); process.exit(1); }
const indent = m[1];
const replacement = `${indent}try {\n${indent}    if (agent.modules && agent.modules.credentials) {\n${indent}        const data = await agent.modules.credentials.getFormatData(record.id);\n${indent}        body.credentialData = data;\n${indent}    }\n${indent}} catch (e) {\n${indent}    // getFormatData unavailable in this agent context (e.g. multi-tenancy root agent)\n${indent}}`;
content = content.replace(pattern, replacement);
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" "${credo_container}:/tmp/patch_credo.js"
  rm -f "$patch_script"
  local result
  result="$(docker exec --user root "$credo_container" node //tmp/patch_credo.js)"
  printf '%s\n' "$result"
  if [[ "$result" == "patched" ]]; then
    docker restart "$credo_container" >/dev/null
  fi
}

_credebl_patch_credo_proof_events() {
  local credo_container
  credo_container="$(docker ps --format '{{.Names}}' | grep -E '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_' | head -1)"
  if [[ -z "$credo_container" ]]; then
    echo "no Credo container yet — skipping"
    return 0
  fi
  local patch_script
  patch_script="$(mktemp /tmp/patch_proof_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/build/events/ProofEvents.js';
let c = fs.readFileSync(path, 'utf8');
if (c.includes('proofData try-catch guard')) { process.stdout.write('already patched\n'); process.exit(0); }
if (c.includes(".split('tenant-')")) { process.stdout.write('new API (no patch needed)\n'); process.exit(0); }
const tenantIdTarget = 'tenantId: event.metadata.contextCorrelationId,';
if (c.indexOf(tenantIdTarget) >= 0) {
  c = c.replace(tenantIdTarget,
    "tenantId: event.metadata.contextCorrelationId.indexOf('tenant-') === 0 ? event.metadata.contextCorrelationId.slice(7) : event.metadata.contextCorrelationId, // tenant- prefix guard");
}
const getFormatTarget = 'const data = await tenantAgent.proofs.getFormatData(record.id);\n            body.proofData = data;';
if (c.indexOf(getFormatTarget) >= 0) {
  c = c.replace(getFormatTarget,
    'try { if (tenantAgent && tenantAgent.proofs) { const data = await tenantAgent.proofs.getFormatData(record.id); body.proofData = data; } } catch (e) { /* proofData try-catch guard */ }');
}
if (!c.includes('proofData try-catch guard')) { process.stderr.write('ERROR: patch target not found in ProofEvents.js\n'); process.exit(1); }
fs.writeFileSync(path, c);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" "${credo_container}:/tmp/patch_proof.js"
  rm -f "$patch_script"
  local result
  result="$(docker exec --user root "$credo_container" node //tmp/patch_proof.js)"
  printf '%s\n' "$result"
  if [[ "$result" == "patched" ]]; then
    docker restart "$credo_container" >/dev/null
  fi
}

_credebl_patch_issuance_schema_url() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_issuance_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/issuance/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('indexOf("://http")')) { process.stdout.write('already patched\n'); process.exit(0); }
const target = 'async getW3CSchemaAttributes(schemaUrl) {';
if (!content.includes(target)) { process.stderr.write('ERROR: patch target not found\n'); process.exit(1); }
const fixLines = ' while (schemaUrl && schemaUrl.indexOf("://http") > 0) { schemaUrl = schemaUrl.slice(schemaUrl.indexOf("://") + 3); }';
content = content.replace(target, target + fixLines);
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" credebl-issuance:/tmp/patch_issuance.js
  rm -f "$patch_script"
  docker exec --user root credebl-issuance node //tmp/patch_issuance.js
}

_credebl_patch_issuance_context_urls() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_issuance_ctx_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/issuance/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('_ctx.map(function(url)')) { process.stdout.write('already patched\n'); process.exit(0); }
const target = "'Validated/Updated Issuance dates credential offer'";
const idx = content.indexOf(target);
if (idx < 0) { process.stderr.write('ERROR: patch target not found in issuance/main.js\n'); process.exit(1); }
const insertAfter = content.indexOf(';', idx) + 1;
const normCode = ' if(credentialOffer){for(const _co of credentialOffer){const _ctx=_co&&_co.credential&&_co.credential["@context"];if(Array.isArray(_ctx)){_co.credential["@context"]=_ctx.map(function(url){while(typeof url==="string"&&url.indexOf("://http")>0){url=url.slice(url.indexOf("://")+3);}return url;});}}}';
content = content.substring(0, insertAfter) + normCode + content.substring(insertAfter);
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" credebl-issuance:/tmp/patch_issuance_ctx.js
  rm -f "$patch_script"
  docker exec --user root credebl-issuance node //tmp/patch_issuance_ctx.js
}

_credebl_patch_issuance_oob_credential_save() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_issuance_oob_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/issuance/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('PATCH9B: fallback UUID')) { process.stdout.write('already patched\n'); process.exit(0); }

if (!content.includes('PATCH9: oob credential upsert')) {
  const oldSig = 'async updateSchemaIdByThreadId(threadId, schemaId) {';
  if (!content.includes(oldSig)) { process.stderr.write('ERROR: fn signature not found\n'); process.exit(1); }
  content = content.replace(oldSig, 'async updateSchemaIdByThreadId(threadId, schemaId, orgId) { /*PATCH9: oob credential upsert*/');

  const oldUpdate = 'await this.prisma.credentials.update({\n                where: { threadId },\n                data: {\n                    schemaId\n                }\n            });';
  if (!content.includes(oldUpdate)) { process.stderr.write('ERROR: credentials.update block not found\n'); process.exit(1); }
  const newUpsert = "await this.prisma.credentials.upsert({\n                where: { threadId },\n                update: { schemaId },\n                create: {\n                    threadId: threadId,\n                    schemaId: schemaId,\n                    orgId: orgId || null,\n                    createdBy: orgId || '00000000-0000-0000-0000-000000000000', /*PATCH9B: fallback UUID*/\n                    lastChangedBy: orgId || '00000000-0000-0000-0000-000000000000',\n                    state: 'offer-sent',\n                    credentialExchangeId: '',\n                    credDefId: ''\n                }\n            });";
  content = content.replace(oldUpdate, newUpsert);

  const oldCall1 = 'this.issuanceRepository.updateSchemaIdByThreadId((_b = record === null || record === void 0 ? void 0 : record.value) === null || _b === void 0 ? void 0 : _b.threadId, schemaId);';
  if (content.includes(oldCall1)) {
    content = content.replace(oldCall1, 'this.issuanceRepository.updateSchemaIdByThreadId((_b = record === null || record === void 0 ? void 0 : record.value) === null || _b === void 0 ? void 0 : _b.threadId, schemaId, orgId);');
  }
}

const old9b = 'this.issuanceRepository.updateSchemaIdByThreadId(credentialCreateOfferDetails.response.credentialRequestThId, schemaId);';
if (content.includes(old9b)) {
  content = content.replace(old9b, 'this.issuanceRepository.updateSchemaIdByThreadId(credentialCreateOfferDetails.response.credentialRequestThId, schemaId, orgId); /*PATCH9B: orgId in OOB call*/');
}

if (content.includes('createdBy: orgId,')) {
  content = content.replace('createdBy: orgId,', "createdBy: orgId || '00000000-0000-0000-0000-000000000000', /*PATCH9B: fallback UUID*/");
}
if (content.includes('lastChangedBy: orgId,')) {
  content = content.replace('lastChangedBy: orgId,', "lastChangedBy: orgId || '00000000-0000-0000-0000-000000000000',");
}

if (!content.includes('PATCH9B: fallback UUID')) { process.stderr.write('ERROR: final guard verification failed\n'); process.exit(1); }
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" credebl-issuance:/tmp/patch_issuance_oob.js
  rm -f "$patch_script"
  docker exec --user root credebl-issuance node //tmp/patch_issuance_oob.js
}

_credebl_patch_issuance_qr_encoding() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_issuance_qr_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/issuance/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('PATCH10: qr encoding')) { process.stdout.write('already patched\n'); process.exit(0); }
const old = "{\n                    filename: 'qrcode.png',\n                    content: outOfBandIssuanceQrCode.split(';base64,')[1],\n                    contentType: 'image/png',\n                    disposition: 'attachment'\n                }";
const nw  = "{\n                    filename: 'qrcode.png',\n                    content: outOfBandIssuanceQrCode.split(';base64,')[1],\n                    contentType: 'image/png',\n                    encoding: 'base64', /*PATCH10: qr encoding*/\n                    contentDisposition: 'attachment'\n                }";
if (!content.includes(old)) { process.stderr.write('ERROR: attachment pattern not found\n'); process.exit(1); }
content = content.replace(old, nw);
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" credebl-issuance:/tmp/patch_issuance_qr.js
  rm -f "$patch_script"
  docker exec --user root credebl-issuance node //tmp/patch_issuance_qr.js
}

_credebl_patch_issuance_qr_deeplink() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_issuance_qrl_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/issuance/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('PATCH12: qr uses deepLinkURL')) { process.stdout.write('already patched\n'); process.exit(0); }
const old = 'const outOfBandIssuanceQrCode = await QRCode.toDataURL(shortenUrl, qrCodeOptions);';
const nw  = 'const outOfBandIssuanceQrCode = await QRCode.toDataURL(deepLinkURL, qrCodeOptions); /*PATCH12: qr uses deepLinkURL*/';
if (!content.includes(old)) { process.stderr.write('ERROR: QR deeplink pattern not found\n'); process.exit(1); }
content = content.replace(old, nw);
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" credebl-issuance:/tmp/patch_issuance_qrl.js
  rm -f "$patch_script"
  docker exec --user root credebl-issuance node //tmp/patch_issuance_qrl.js
}

_credebl_patch_verification_qr_encoding() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_verif_qr_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/verification/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('PATCH11: qr encoding')) { process.stdout.write('already patched\n'); process.exit(0); }
const old = "outOfBandVerificationQrCode.split(';base64,')[1],\n                contentType: 'image/png',\n                disposition: 'attachment'";
const nw  = "outOfBandVerificationQrCode.split(';base64,')[1],\n                contentType: 'image/png',\n                encoding: 'base64', /*PATCH11: qr encoding*/\n                contentDisposition: 'attachment'";
if (!content.includes(old)) { process.stderr.write('ERROR: attachment pattern not found in verification main.js\n'); process.exit(1); }
content = content.replace(old, nw);
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" credebl-verification:/tmp/patch_verif_qr.js
  rm -f "$patch_script"
  docker exec --user root credebl-verification node //tmp/patch_verif_qr.js
}

_credebl_patch_agent_service_create_tenant() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_agent_ct_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/agent-service/main.js';
let content = fs.readFileSync(path, 'utf8');
if (content.includes('PATCH: create-tenant needs root JWT')) { process.stdout.write('already patched\n'); process.exit(0); }
const target = 'const tenantDetails = await this.commonService.httpPost(`${endpoint}${common_constant_1.CommonConstants.URL_SHAGENT_CREATE_TENANT}`, createTenantOptions, { headers: { authorization: agentApiKey } });\n        return tenantDetails;\n    }\n    async handleCreateDid';
if (!content.includes(target)) { process.stderr.write('ERROR: patch target not found in agent-service/main.js\n'); process.exit(1); }
const replacement = 'const rootTokenResp = await this.commonService.httpPost(endpoint + "/agent/token", {}, { headers: { authorization: process.env.AGENT_API_KEY } }); // PATCH: create-tenant needs root JWT\n        const rootJwt = "Bearer " + ((rootTokenResp && rootTokenResp.token) || (rootTokenResp && rootTokenResp.access_token) || "");\n        const tenantDetails = await this.commonService.httpPost(`${endpoint}${common_constant_1.CommonConstants.URL_SHAGENT_CREATE_TENANT}`, createTenantOptions, { headers: { authorization: rootJwt } });\n        return tenantDetails;\n    }\n    async handleCreateDid';
content = content.replace(target, replacement);
fs.writeFileSync(path, content);
process.stdout.write('patched\n');
JSEOF
  docker cp "$patch_script" credebl-agent-service:/tmp/patch_agent_ct.js
  rm -f "$patch_script"
  docker exec --user root credebl-agent-service node //tmp/patch_agent_ct.js
}

_credebl_patch_agent_service_normalize_url() {
  local patch_script
  patch_script="$(mktemp /tmp/patch_agent_nu_XXXXXX.js)"
  cat > "$patch_script" << 'JSEOF'
const fs = require('fs');
const path = '/app/dist/apps/agent-service/main.js';
let content = fs.readFileSync(path, 'utf8');
const guardA = 'PATCH8: normalizeUrlWithProtocol uses AGENT_PROTOCOL';
const guardB = 'PATCH8b: https to http for Credo';
const needsA = !content.includes(guardA);
const needsB = !content.includes(guardB);
if (!needsA && !needsB) { process.stdout.write('already patched\n'); process.exit(0); }
let changed = false;
if (needsA) {
  const targetA = 'return `${process.env.API_GATEWAY_PROTOCOL}://${baseUrl}`;';
  if (!content.includes(targetA)) { process.stderr.write('ERROR: PATCH8a target not found\n'); process.exit(1); }
  content = content.replace(targetA, '/* ' + guardA + ' */ return `${process.env.AGENT_PROTOCOL || "http"}://${baseUrl}`;');
  changed = true;
}
if (needsB) {
  const targetB = "if (baseUrl.startsWith('http://') || baseUrl.startsWith('https://')) {\n            return baseUrl;\n        }";
  if (!content.includes(targetB)) { process.stderr.write('ERROR: PATCH8b target not found\n'); process.exit(1); }
  const repB = "/* " + guardB + " */ if (baseUrl.startsWith('https://')) { return 'http://' + baseUrl.slice(8); }\n        if (baseUrl.startsWith('http://')) { return baseUrl; }";
  content = content.replace(targetB, repB);
  changed = true;
}
if (changed) { fs.writeFileSync(path, content); process.stdout.write('patched\n'); }
JSEOF
  docker cp "$patch_script" credebl-agent-service:/tmp/patch_agent_nu.js
  rm -f "$patch_script"
  docker exec --user root credebl-agent-service node //tmp/patch_agent_nu.js
}

# _credebl_patch_agent_spin_up_script patches docker_start_agent.sh inside
# credebl-agent-provisioning to attach spawned Credo containers to waltid_default
# and use the postgres container hostname instead of 172.17.0.1.
# On Docker Desktop (Windows/Mac) spawned Credo containers land on afj_default,
# not docker0, so 172.17.0.1 is unreachable and credebl-postgres:5432 must be used.
_credebl_patch_agent_spin_up_script() {
  local guard="PATCH-WALTID-NET"
  local script_path="/app/agent-provisioning/AFJ/scripts/docker_start_agent.sh"

  if docker exec credebl-agent-provisioning grep -q "$guard" "$script_path" 2>/dev/null; then
    echo "already patched"
    return 0
  fi

  # Write helper: patch_compose.sh — fixes config JSON + appends network to compose YAML
  local helper_script
  helper_script="$(mktemp /tmp/patch_compose_helper_XXXXXX.sh)"
  cat > "$helper_script" << 'SHEOF'
#!/bin/sh
CONFIG_FILE="$1"
COMPOSE_FILE="$2"
python3 - "$CONFIG_FILE" << 'PYEOF'
import json, sys
fname = sys.argv[1]
with open(fname) as f:
    cfg = json.load(f)
port = cfg.get('walletUrl', ':5432').split(':')[-1]
agency_id = cfg.get('webhookUrl', '').rsplit('/wh/', 1)[-1]
cfg['walletUrl'] = 'credebl-postgres:' + port
if agency_id:
    cfg['webhookUrl'] = 'http://credebl-agent-service:5001/wh/' + agency_id
with open(fname, 'w') as f:
    json.dump(cfg, f, indent=2)
PYEOF
python3 - "$COMPOSE_FILE" << 'PYEOF'
import sys
fname = sys.argv[1]
with open(fname) as f:
    c = f.read()
if 'waltid_default' not in c:
    c = c.replace('    command:', '    networks:\n      - waltid_default\n    command:')
    c += '\nnetworks:\n  waltid_default:\n    external: true\n'
    with open(fname, 'w') as f:
        f.write(c)
PYEOF
SHEOF
  docker cp "$helper_script" credebl-agent-provisioning:/tmp/patch_compose_helper.sh
  rm -f "$helper_script"
  docker exec --user root credebl-agent-provisioning sh -c \
    "chmod +x /tmp/patch_compose_helper.sh && mv /tmp/patch_compose_helper.sh /app/agent-provisioning/AFJ/scripts/patch_compose.sh"

  # Patch docker_start_agent.sh to call the helper after both files are generated
  local patcher
  patcher="$(mktemp /tmp/patch_spin_up_XXXXXX.py)"
  cat > "$patcher" << 'PYEOF'
import sys

with open('/app/agent-provisioning/AFJ/scripts/docker_start_agent.sh') as f:
    content = f.read()

GUARD = 'PATCH-WALTID-NET'
if GUARD in content:
    sys.stdout.write('already patched\n')
    sys.exit(0)

anchor = '  echo "docker-compose generated successfully!"\n'
if anchor not in content:
    sys.stderr.write('ERROR: anchor not found in docker_start_agent.sh\n')
    sys.exit(1)

fix = ('  # ' + GUARD + ': attach Credo to waltid_default; use credebl-postgres hostname\n'
       '  sh /app/agent-provisioning/AFJ/scripts/patch_compose.sh "${CONFIG_FILE}" "${DOCKER_COMPOSE}"\n')
content = content.replace(anchor, anchor + fix, 1)

with open('/app/agent-provisioning/AFJ/scripts/docker_start_agent.sh', 'w') as f:
    f.write(content)
sys.stdout.write('patched\n')
PYEOF
  docker cp "$patcher" credebl-agent-provisioning:/tmp/patch_spin_up.py
  rm -f "$patcher"
  docker exec --user root credebl-agent-provisioning python3 //tmp/patch_spin_up.py
}

# _credebl_patch_agent_port_range patches docker_start_agent.sh to use
# AGENT_PORT_START and INBOUND_PORT_START env vars as defaults instead of
# hardcoded 8001/9001. Without this, Credo picks port 9002 which conflicts
# with MinIO's 9002:9000 mapping on the waltid_default compose project.
_credebl_patch_agent_port_range() {
  local guard="PATCH-PORT-RANGE"
  local script_path="/app/agent-provisioning/AFJ/scripts/docker_start_agent.sh"

  if MSYS_NO_PATHCONV=1 docker exec credebl-agent-provisioning grep -q "$guard" "$script_path" 2>/dev/null; then
    echo "already patched"
    return 0
  fi

  local patcher
  patcher="$(mktemp /tmp/patch_port_range_XXXXXX.py)"
  cat > "$patcher" << 'PYEOF'
import sys

with open('/app/agent-provisioning/AFJ/scripts/docker_start_agent.sh', 'rb') as f:
    content = f.read()

GUARD = b'PATCH-PORT-RANGE'
if GUARD in content:
    sys.stdout.write('already patched\n')
    sys.exit(0)

old_admin  = b'ADMIN_PORT=8001\n'
new_admin  = b'ADMIN_PORT=${AGENT_PORT_START:-8001}  # PATCH-PORT-RANGE\n'
old_inbound = b'INBOUND_PORT=9001\n'
new_inbound = b'INBOUND_PORT=${INBOUND_PORT_START:-9001}\n'

if old_admin not in content:
    sys.stderr.write('ERROR: ADMIN_PORT=8001 not found\n')
    sys.exit(1)
if old_inbound not in content:
    sys.stderr.write('ERROR: INBOUND_PORT=9001 not found\n')
    sys.exit(1)

content = content.replace(old_admin, new_admin, 1)
content = content.replace(old_inbound, new_inbound, 1)

with open('/app/agent-provisioning/AFJ/scripts/docker_start_agent.sh', 'wb') as f:
    f.write(content)
sys.stdout.write('patched\n')
PYEOF
  docker cp "$patcher" credebl-agent-provisioning:/tmp/patch_port_range.py
  rm -f "$patcher"
  MSYS_NO_PATHCONV=1 docker exec --user root credebl-agent-provisioning python3 /tmp/patch_port_range.py
}

# _credebl_patch_ledger_schema_jwt replaces the raw hex SCHEMA_FILE_SERVER_TOKEN
# with a valid HS256 JWT signed with JWT_TOKEN_SECRET.
# The schema file server (oak_middleware_jwt) validates Bearer tokens as JWTs —
# the raw hex string is not a JWT and is rejected with 401, blocking schema creation.
_credebl_patch_ledger_schema_jwt() {
  local guard="PATCH-SCHEMA-JWT"
  local js_path="/app/dist/apps/ledger/main.js"
  if MSYS_NO_PATHCONV=1 docker exec credebl-ledger node -e "
    const fs=require('fs');
    const c=fs.readFileSync('$js_path','utf8');
    process.exit(c.includes('$guard') ? 0 : 1);
  " 2>/dev/null; then
    echo "already patched"
    return 0
  fi

  local jwt_token_secret
  jwt_token_secret="$(docker exec credebl-schema-file-server env 2>/dev/null \
    | grep '^JWT_TOKEN_SECRET=' | cut -d= -f2-)"
  if [[ -z "$jwt_token_secret" ]]; then
    echo "ERROR: could not read JWT_TOKEN_SECRET from schema-file-server"
    return 1
  fi

  local jwt_token
  jwt_token="$(python3 - "$jwt_token_secret" << 'PYEOF'
import sys, base64, hmac, hashlib, json
secret = sys.argv[1]
padding = "=" * (4 - len(secret) % 4) if len(secret) % 4 else ""
key = base64.b64decode(secret + padding)
def b64u(data):
    if isinstance(data, dict):
        data = json.dumps(data, separators=(',',':')).encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
h = b64u({"alg":"HS256","typ":"JWT"})
p = b64u({"iss":"Credebl","id":"cdpi-fixed-token"})
msg = f"{h}.{p}"
sig = hmac.new(key, msg.encode(), hashlib.sha256).digest()
print(f"{msg}.{b64u(sig)}")
PYEOF
)"
  if [[ -z "$jwt_token" ]]; then
    echo "ERROR: failed to generate JWT"
    return 1
  fi

  local patcher
  patcher="$(mktemp /tmp/patch_schema_jwt_XXXXXX.js)"
  # Note: $js_path and $guard expand here; $jwt_token expands here.
  # The outer quotes on EOF are intentional (no single-quoting) so variables expand.
  cat > "$patcher" << EOF
const fs = require('fs');
const content = fs.readFileSync('$js_path', 'utf8');
const GUARD = '$guard';
if (content.includes(GUARD)) { process.stdout.write('already patched\n'); process.exit(0); }
const OLD = 'process.env.SCHEMA_FILE_SERVER_TOKEN';
if (!content.includes(OLD)) { process.stderr.write('ERROR: pattern not found\n'); process.exit(1); }
const NEW = '"$jwt_token" /* $guard */';
fs.writeFileSync('$js_path', content.split(OLD).join(NEW));
process.stdout.write('patched\n');
EOF
  docker cp "$patcher" credebl-ledger:/tmp/patch_schema_jwt.js
  rm -f "$patcher"
  MSYS_NO_PATHCONV=1 docker exec --user root credebl-ledger node /tmp/patch_schema_jwt.js 2>&1
}

# apply_credebl_patches applies all container patches in the correct order.
apply_credebl_patches() {
  echo "  Applying CREDEBL container patches..."

  echo -n "  [1/14] Utility service S3→MinIO endpoint: "
  _credebl_patch_utility_s3
  docker restart credebl-utility >/dev/null

  echo -n "  [2/14] API gateway @context validator: "
  _credebl_patch_api_gateway_context_validator
  docker restart credebl-api-gateway >/dev/null

  echo -n "  [3/14] Issuance schema URL dedup: "
  _credebl_patch_issuance_schema_url
  echo -n "  [4/14] Issuance @context URL normalization: "
  _credebl_patch_issuance_context_urls
  echo -n "  [5/14] Issuance OOB credential DB save (upsert): "
  _credebl_patch_issuance_oob_credential_save
  echo -n "  [6/14] Issuance QR code attachment encoding: "
  _credebl_patch_issuance_qr_encoding
  echo -n "  [7/14] Issuance QR uses full deeplink URL: "
  _credebl_patch_issuance_qr_deeplink
  docker restart credebl-issuance >/dev/null

  echo -n "  [8/14] Verification QR code attachment encoding: "
  _credebl_patch_verification_qr_encoding
  docker restart credebl-verification >/dev/null

  echo -n "  [9/14] Ledger service SCHEMA_FILE_SERVER_TOKEN (valid JWT): "
  _credebl_patch_ledger_schema_jwt
  docker restart credebl-ledger >/dev/null

  echo -n "  [10/14] Agent-service shared wallet create-tenant (root JWT): "
  _credebl_patch_agent_service_create_tenant
  echo -n "  [11/14] Agent-service normalizeUrlWithProtocol (http for Credo): "
  _credebl_patch_agent_service_normalize_url
  docker restart credebl-agent-service >/dev/null

  echo -n "  [12/14] Agent-provisioning docker_start_agent.sh (waltid_default network): "
  _credebl_patch_agent_spin_up_script
  echo -n "  [13/14] Agent-provisioning port range (AGENT_PORT_START/INBOUND_PORT_START): "
  _credebl_patch_agent_port_range

  # Credo patches — only if Credo is running
  echo -n "  [14/14] Credo CredentialEvents guard: "
  _credebl_patch_credo_credential_events
  echo -n "  [15/14] Credo ProofEvents guard: "
  _credebl_patch_credo_proof_events

  echo "  Waiting for restarted containers to be ready (up to 90s)..."
  local deadline=$(( $(date +%s) + 90 ))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    local gw_health as_log
    gw_health="$(docker inspect credebl-api-gateway --format '{{.State.Health.Status}}' 2>/dev/null || true)"
    as_log="$(docker logs credebl-agent-service --tail=5 2>/dev/null || true)"
    if [[ "$gw_health" == "healthy" ]] && printf '%s' "$as_log" | grep -q 'listening to NATS'; then
      break
    fi
    sleep 3
  done
  green "  CREDEBL patches applied."
}

# ensure_credebl_platform_admin_shared_agent waits for the platform-admin
# shared agent to be provisioned (agentSpinUpStatus=2, endpoint set, Credo responding).
# Retries up to 6 times with full re-provision on each attempt.
ensure_credebl_platform_admin_shared_agent() {
  local _db_pw="$CREDEBL_POSTGRES_PASSWORD"
  local _agent_key="$CREDEBL_AGENT_API_KEY"

  _credebl_pg() {
    docker exec -i credebl-postgres env PGPASSWORD="$_db_pw" \
      psql -U credebl -d credebl "$@"
  }

  _platform_admin_agent_ready() {
    local row status endpoint token_url
    row="$(_credebl_pg -Atqc "
      SELECT COALESCE(oa.\"agentSpinUpStatus\"::text, ''),
             COALESCE(oa.\"agentEndPoint\", '')
      FROM organisation o
      LEFT JOIN org_agents oa ON oa.\"orgId\" = o.id
      WHERE o.name = 'Platform-admin'
      LIMIT 1;" 2>/dev/null | tr -d '\r')"
    status="${row%%|*}"
    endpoint="${row#*|}"
    [[ "$status" != "2" ]] && return 1
    [[ -z "$endpoint" ]] && return 1
    [[ "$endpoint" =~ ^https?:// ]] \
      && token_url="${endpoint%/}/agent/token" \
      || token_url="http://${endpoint}/agent/token"
    # Docker bridge IPs (172.x.x.1) are not routable from Windows host —
    # replace with 127.0.0.1 (port is published on all interfaces).
    token_url="${token_url//172.24.0.1/127.0.0.1}"
    token_url="${token_url//172.17.0.1/127.0.0.1}"
    curl -sf --max-time 8 -X POST -H "Authorization: $_agent_key" "$token_url" >/dev/null
  }

  echo "  Waiting for platform-admin-bootstrap to complete..."
  local tries=0
  while ! docker inspect credebl-platform-admin-bootstrap --format '{{.State.Status}}' 2>/dev/null | grep -qE '^exited$'; do
    tries=$((tries + 1))
    [[ $tries -gt 90 ]] && { red "  platform-admin-bootstrap timed out"; return 1; }
    sleep 2
  done
  local exit_code
  exit_code=$(docker inspect credebl-platform-admin-bootstrap --format '{{.State.ExitCode}}' 2>/dev/null || echo "1")
  if [[ "$exit_code" != "0" ]]; then
    red "  platform-admin-bootstrap exited with code $exit_code"
    return 1
  fi

  if _platform_admin_agent_ready; then
    green "  Platform-admin shared agent is ready."
    return 0
  fi

  local attempt=1
  while [[ $attempt -le 6 ]]; do
    echo "  Not ready (attempt $attempt/6). Restarting agent-provisioning + agent-service..."
    # Clear stale org_agents record
    _credebl_pg -q -c "
      DELETE FROM org_agents oa
      USING organisation o
      WHERE oa.\"orgId\" = o.id
        AND o.name = 'Platform-admin'
        AND (oa.\"agentSpinUpStatus\" <> 2 OR COALESCE(oa.\"agentEndPoint\", '') = '');" 2>/dev/null || true
    # Drop stale wallet DB if it exists
    _credebl_pg -d postgres -q -c "
      SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'platformadminwallet';
      DROP DATABASE IF EXISTS \"platformadminwallet\";" 2>/dev/null || true
    # Remove stale Credo containers
    docker ps -a --format '{{.Names}}' 2>/dev/null | while IFS= read -r cname; do
      [[ "$cname" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_ ]] \
        && docker rm -f "$cname" 2>/dev/null || true
    done

    docker restart credebl-agent-provisioning >/dev/null
    # Wait for agent-provisioning NATS subscription
    local nats_wait=0
    while [[ $nats_wait -lt 45 ]]; do
      sleep 5; nats_wait=$((nats_wait + 5))
      if docker logs --since 45s credebl-agent-provisioning 2>/dev/null | grep -q "Microservice is listening"; then
        echo "  agent-provisioning NATS ready (${nats_wait}s)"
        break
      fi
    done

    docker restart credebl-agent-service >/dev/null
    echo "  Waiting 130s for full provisioning cycle..."
    sleep 130

    if _platform_admin_agent_ready; then
      green "  Platform-admin shared agent is ready."
      return 0
    fi
    local extra=0
    while [[ $extra -lt 90 ]]; do
      sleep 15; extra=$((extra + 15))
      _platform_admin_agent_ready && { green "  Platform-admin shared agent is ready."; return 0; }
      echo "  Still waiting... (${extra}s extra)"
    done
    attempt=$((attempt + 1))
  done
  red "  Platform-admin shared agent did not reach ready state — check: docker logs credebl-agent-service"
  return 1
}

# ensure_credebl_platform_admin_tenant creates a Credo multi-tenancy tenant for
# Platform-admin and stores the encrypted tenant JWT in org_agents.apiKey.
ensure_credebl_platform_admin_tenant() {
  local _db_pw="$CREDEBL_POSTGRES_PASSWORD"
  local _agent_key="$CREDEBL_AGENT_API_KEY"

  _credebl_pg2() {
    docker exec -i credebl-postgres env PGPASSWORD="$_db_pw" \
      psql -U credebl -d credebl "$@"
  }

  # Get agent endpoint from DB
  local endpoint
  endpoint="$(_credebl_pg2 -Atqc "
    SELECT oa.\"agentEndPoint\" FROM org_agents oa
    JOIN organisation o ON o.id = oa.\"orgId\"
    WHERE o.name = 'Platform-admin' AND oa.\"agentSpinUpStatus\" = 2
    LIMIT 1;" 2>/dev/null | tr -d '\r')"

  if [[ -z "$endpoint" ]]; then
    red "  Error: Platform-admin agent endpoint not found in DB."
    return 1
  fi

  # Normalize to http:// (Credo admin ports only serve HTTP)
  [[ "$endpoint" == https://* ]] && endpoint="http://${endpoint#https://}"
  [[ "$endpoint" =~ ^http:// ]] || endpoint="http://${endpoint}"
  # Fix DB record if stored with https://
  _credebl_pg2 -q -c "UPDATE org_agents SET \"agentEndPoint\" = replace(\"agentEndPoint\", 'https://', 'http://') WHERE \"agentEndPoint\" LIKE 'https://%';" 2>/dev/null || true

  # On Docker Desktop (Windows/Mac), Docker bridge IPs (172.x.x.1) are not reachable
  # from the host — use 127.0.0.1 instead (port is published on all interfaces).
  local curl_endpoint="${endpoint//172.24.0.1/127.0.0.1}"
  curl_endpoint="${curl_endpoint//172.17.0.1/127.0.0.1}"

  # Get root JWT (retry up to 8 times — Credo may still be starting)
  local root_jwt attempt=1
  while [[ $attempt -le 8 ]]; do
    root_jwt="$(curl -sf --max-time 10 -X POST \
      -H "Authorization: $_agent_key" \
      "${curl_endpoint}/agent/token" 2>/dev/null \
      | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token', d.get('access_token','')))" 2>/dev/null || true)"
    [[ -n "$root_jwt" ]] && break
    echo "  Credo not ready (attempt ${attempt}/8), waiting 5s..."
    sleep 5
    attempt=$((attempt + 1))
  done

  if [[ -z "$root_jwt" ]]; then
    red "  Error: Failed to get root JWT from Credo at ${endpoint}"
    return 1
  fi

  # Check if tenant already exists in DB
  local tenant_id
  tenant_id="$(_credebl_pg2 -Atqc "
    SELECT COALESCE(oa.\"tenantId\", '') FROM org_agents oa
    JOIN organisation o ON o.id = oa.\"orgId\"
    WHERE o.name = 'Platform-admin'
    LIMIT 1;" 2>/dev/null | tr -d '\r')"

  if [[ -z "$tenant_id" ]]; then
    echo "  Creating Platform-admin tenant in Credo multi-tenant agent..."
    local create_resp
    create_resp="$(curl -sf --max-time 15 -X POST \
      -H "Authorization: Bearer ${root_jwt}" \
      -H "Content-Type: application/json" \
      -d '{"config":{"label":"Platform-admin"}}' \
      "${curl_endpoint}/multi-tenancy/create-tenant" 2>/dev/null || true)"
    tenant_id="$(printf '%s' "$create_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || true)"
    if [[ -z "$tenant_id" ]]; then
      red "  Error: Failed to create tenant. Response: $create_resp"
      return 1
    fi
    echo "  Tenant created: $tenant_id"
  else
    echo "  Tenant already exists: $tenant_id"
  fi

  # Get fresh tenant JWT
  local tenant_jwt
  tenant_jwt="$(curl -sf --max-time 10 -X POST \
    -H "Authorization: Bearer ${root_jwt}" \
    "${curl_endpoint}/multi-tenancy/get-token/${tenant_id}" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token', d.get('access_token','')))" 2>/dev/null || true)"

  if [[ -z "$tenant_jwt" ]]; then
    red "  Error: Failed to get tenant JWT for tenant ${tenant_id}"
    return 1
  fi

  # Encrypt tenant JWT with CryptoJS AES (same as CREDEBL's dataEncryption method)
  local encrypted_jwt
  encrypted_jwt="$(docker exec -i credebl-agent-service node -e "
const CryptoJS = require('crypto-js');
const token = '${tenant_jwt}';
const key = process.env.CRYPTO_PRIVATE_KEY;
const encrypted = CryptoJS.AES.encrypt(JSON.stringify(token), key).toString();
process.stdout.write(encrypted);
" 2>/dev/null)"

  if [[ -z "$encrypted_jwt" ]]; then
    red "  Error: Failed to encrypt tenant JWT"
    return 1
  fi

  # Store tenantId + encrypted apiKey in DB
  _credebl_pg2 -v ON_ERROR_STOP=1 -q -c "
    UPDATE org_agents oa
    SET \"tenantId\" = '${tenant_id}',
        \"apiKey\"   = '${encrypted_jwt}'
    FROM organisation o
    WHERE oa.\"orgId\" = o.id
      AND o.name = 'Platform-admin';" >/dev/null

  green "  Platform-admin tenant wallet configured (tenantId=${tenant_id})"

  # Restart agent-service so it picks up the new apiKey.
  # Wait until it logs "listening to NATS" before returning — callers depend on
  # NATS subscriptions being active (e.g. ensure_credebl_oid4vc_issuer).
  docker restart credebl-agent-service >/dev/null

  # Wait for Docker to report the container as running, then capture StartedAt
  # so we can poll logs --since <start_ts> and avoid false positives from
  # "listening to NATS" lines emitted by a PREVIOUS restart cycle.
  local start_ts=""
  local wait_tries=0
  while [[ $wait_tries -lt 30 ]]; do
    local ctr_status
    ctr_status=$(docker inspect credebl-agent-service --format '{{.State.Status}}' 2>/dev/null || echo "")
    if [[ "$ctr_status" == "running" ]]; then
      start_ts=$(docker inspect credebl-agent-service --format '{{.State.StartedAt}}' 2>/dev/null || echo "")
      break
    fi
    sleep 1; wait_tries=$(( wait_tries + 1 ))
  done

  local nats_ready=false
  local deadline=$(( $(date +%s) + 90 ))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    local log_output
    if [[ -n "$start_ts" ]]; then
      log_output=$(docker logs credebl-agent-service --since "$start_ts" 2>/dev/null || true)
    else
      log_output=$(docker logs credebl-agent-service --tail=30 2>/dev/null || true)
    fi
    if printf '%s' "$log_output" | grep -q "listening to NATS"; then
      nats_ready=true
      break
    fi
    sleep 3
  done
  if [[ "$nats_ready" == "true" ]]; then
    green "  Agent-service restarted and listening to NATS."
  else
    red "  Agent-service did not reach NATS-ready state in 90s — proceeding anyway"
  fi
}

# ensure_credebl_oid4vc_issuer ensures Platform-admin has:
#   1. A did:key (creates one if absent)
#   2. An OID4VCI issuer record in oidc_issuer (creates one if absent)
#   3. At least one credential template on that issuer (creates one if absent)
# Exports CREDEBL_ISSUER_ID with the issuer DB UUID.
# Idempotent — skips creation steps when existing rows are found.
ensure_credebl_oid4vc_issuer() {
  local _db_pw="$CREDEBL_POSTGRES_PASSWORD"
  local _org_id
  _org_id="$(docker exec -i credebl-postgres env PGPASSWORD="$_db_pw" \
    psql -U credebl -d credebl -Atqc "SELECT id FROM organisation WHERE name='Platform-admin' LIMIT 1;" \
    2>/dev/null | tr -d '\r')"
  if [[ -z "$_org_id" ]]; then
    red "  Could not determine Platform-admin org UUID from DB"
    return 1
  fi
  local _api="http://127.0.0.1:${CREDEBL_API_PORT:-5001}"
  local _email="${CREDEBL_ADMIN_EMAIL:-admin@cdpi.dev}"
  local _kc_port="${KEYCLOAK_PORT:-8080}"

  _credebl_pg3() {
    docker exec -i credebl-postgres env PGPASSWORD="$_db_pw" \
      psql -U credebl -d credebl "$@"
  }

  # --- Sign in — use Python helper to avoid quoting issues ------------------
  local tmp_py
  tmp_py="$(mktemp /tmp/credebl_issuer_XXXXXX.py)"
  cat > "$tmp_py" << 'PYEOF'
import sys, json, subprocess, urllib.request, os

org_id   = sys.argv[1]
api      = sys.argv[2]
email    = sys.argv[3]
kc_port  = sys.argv[4]

# Encrypt password via CryptoJS in agent-service container
enc_pass = subprocess.check_output(
    ['docker', 'exec', '-i', 'credebl-agent-service', 'node', '-e',
     "const C=require('crypto-js');process.stdout.write(C.AES.encrypt(JSON.stringify('changeme'),process.env.CRYPTO_PRIVATE_KEY).toString())"],
    stderr=subprocess.DEVNULL).decode().strip()

# Sign in
req = urllib.request.Request(
    f'{api}/v1/auth/signin',
    data=json.dumps({'email': email, 'password': enc_pass}).encode(),
    headers={'Content-Type': 'application/json'},
    method='POST')
with urllib.request.urlopen(req, timeout=15) as r:
    d = json.load(r)
jwt = d['data']['access_token']
headers = {'Authorization': f'Bearer {jwt}', 'Content-Type': 'application/json'}

def api_get(path):
    req = urllib.request.Request(f'{api}{path}', headers={'Authorization': f'Bearer {jwt}'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except Exception:
        return {}

def api_post(path, body):
    req = urllib.request.Request(f'{api}{path}', data=json.dumps(body).encode(), headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

import subprocess as sp

# --- DID ---
def pg(sql):
    out = sp.run(['docker','exec','-i','credebl-postgres','env',
                  f'PGPASSWORD={os.environ["CREDEBL_POSTGRES_PASSWORD"]}',
                  'psql','-U','credebl','-d','credebl','-Atqc',sql],
                 capture_output=True, text=True).stdout.strip()
    return out

org_did = pg(f"SELECT COALESCE(\"orgDid\",'') FROM org_agents WHERE \"orgId\"='{org_id}' LIMIT 1;")
if not org_did:
    import os as _os
    seed = _os.urandom(16).hex()
    did_payload = {'seed': seed, 'keyType': 'ed25519', 'method': 'key',
                   'ledger': '', 'privatekey': '', 'network': '', 'domain': '',
                   'role': '', 'endorserDid': '', 'clientSocketId': '', 'isPrimaryDid': True}
    api_post(f'/v1/orgs/{org_id}/agents/did', did_payload)
    import time
    for _ in range(20):
        time.sleep(3)
        org_did = pg(f"SELECT COALESCE(\"orgDid\",'') FROM org_agents WHERE \"orgId\"='{org_id}' LIMIT 1;")
        if org_did:
            break
    if not org_did:
        print('ERROR:did_timeout', flush=True)
        sys.exit(1)
    print(f'INFO:did_created:{org_did}', flush=True)
else:
    print(f'INFO:did_exists:{org_did}', flush=True)

# --- OID4VCI issuer ---
issuer_id = pg(f"SELECT id FROM oidc_issuer WHERE \"orgId\"='{org_id}' LIMIT 1;")
if not issuer_id:
    iss_body = {
        'issuerId': 'platform-admin-issuer',
        'credentialIssuerHost': api,
        'orgId': org_id,
        'orgDid': org_did,
        'authorizationServerUrl': f'http://127.0.0.1:{kc_port}/realms/credebl-realm',
        'batchCredentialIssuanceSize': 1,
        'display': [{'name': 'Platform Admin Issuer', 'locale': 'en'}]
    }
    resp = api_post(f'/v1/orgs/{org_id}/oid4vc/issuers', iss_body)
    issuer_id = (resp.get('data') or {}).get('id', '')
    if not issuer_id:
        print(f'ERROR:issuer_create:{json.dumps(resp)}', flush=True)
        sys.exit(1)
    print(f'INFO:issuer_created:{issuer_id}', flush=True)
else:
    print(f'INFO:issuer_exists:{issuer_id}', flush=True)

# --- credential template ---
tmpl_resp = api_get(f'/v1/orgs/{org_id}/oid4vc/{issuer_id}/template')
tmpl_count = len((tmpl_resp.get('data') or []))
if tmpl_count == 0:
    # Create schema
    schema_body = {
        'type': 'json',
        'schemaPayload': {
            'schemaName': 'Employment',
            'schemaType': 'no_ledger',
            'attributes': [
                {'attributeName':'given_name',            'schemaDataType':'string','displayName':'Given Name',       'isRequired':True},
                {'attributeName':'family_name',           'schemaDataType':'string','displayName':'Family Name',      'isRequired':True},
                {'attributeName':'employer_name',         'schemaDataType':'string','displayName':'Employer Name',    'isRequired':True},
                {'attributeName':'employment_status',     'schemaDataType':'string','displayName':'Employment Status','isRequired':True},
                {'attributeName':'position_title',        'schemaDataType':'string','displayName':'Position Title',   'isRequired':True},
                {'attributeName':'employment_start_date', 'schemaDataType':'string','displayName':'Start Date',       'isRequired':True},
                {'attributeName':'document_number',       'schemaDataType':'string','displayName':'Document Number',  'isRequired':False},
            ],
            'description': 'Employment Credential',
            'orgId': org_id
        }
    }
    sr = api_post(f'/v1/orgs/{org_id}/schemas', schema_body)
    schema_id = (sr.get('data') or {}).get('schemaLedgerId') or \
                (sr.get('data') or {}).get('schemaId') or \
                (sr.get('data') or {}).get('id', '')
    if not schema_id:
        print(f'ERROR:schema_create:{json.dumps(sr)}', flush=True)
        sys.exit(1)
    print(f'INFO:schema_created:{schema_id}', flush=True)
    # Create template
    tmpl_body = {
        'name': 'Employment Credential',
        'format': 'dc+sd-jwt',
        'signerOption': 'DID',
        'canBeRevoked': False,
        'template': {
            'vct': schema_id,
            'attributes': [
                {'key':'given_name',            'value_type':'string','disclose':False},
                {'key':'employer_name',         'value_type':'string','disclose':False},
                {'key':'employment_status',     'value_type':'string','disclose':False},
                {'key':'family_name',           'value_type':'string','disclose':True},
                {'key':'document_number',       'value_type':'string','disclose':True},
                {'key':'position_title',        'value_type':'string','disclose':True},
                {'key':'employment_start_date', 'value_type':'string','disclose':True},
            ]
        }
    }
    tr = api_post(f'/v1/orgs/{org_id}/oid4vc/{issuer_id}/template', tmpl_body)
    tmpl_id = (tr.get('data') or {}).get('id', '')
    if not tmpl_id:
        print(f'ERROR:template_create:{json.dumps(tr)}', flush=True)
        sys.exit(1)
    print(f'INFO:template_created:{tmpl_id}', flush=True)
else:
    print(f'INFO:templates_exist:{tmpl_count}', flush=True)

print(f'ISSUER_ID:{issuer_id}', flush=True)
PYEOF

  local py_out
  py_out="$(CREDEBL_POSTGRES_PASSWORD="$_db_pw" python3 "$tmp_py" "$_org_id" "$_api" "$_email" "$_kc_port" 2>&1)"
  local py_exit=$?
  rm -f "$tmp_py"

  # Print INFO lines as progress, stop on ERROR
  local issuer_db_id=""
  while IFS= read -r line; do
    case "$line" in
      INFO:did_created:*)   green "  DID created: ${line#INFO:did_created:}" ;;
      INFO:did_exists:*)    echo  "  DID already exists: ${line#INFO:did_exists:}" ;;
      INFO:issuer_created:*) green "  OID4VCI issuer created: ${line#INFO:issuer_created:}" ;;
      INFO:issuer_exists:*) echo  "  OID4VCI issuer already exists: ${line#INFO:issuer_exists:}" ;;
      INFO:schema_created:*) echo "  Schema created: ${line#INFO:schema_created:}" ;;
      INFO:template_created:*) green "  Credential template created: ${line#INFO:template_created:}" ;;
      INFO:templates_exist:*) echo "  Credential templates already exist (${line#INFO:templates_exist:})" ;;
      ERROR:*)              red "  $line"; py_exit=1 ;;
      ISSUER_ID:*)          issuer_db_id="${line#ISSUER_ID:}" ;;
      *)                    echo "  $line" ;;
    esac
  done <<< "$py_out"

  if [[ $py_exit -ne 0 ]] || [[ -z "$issuer_db_id" ]]; then
    red "  ensure_credebl_oid4vc_issuer failed (exit=$py_exit)"
    return 1
  fi

  export CREDEBL_ISSUER_ID="$issuer_db_id"
  green "  CREDEBL OID4VCI issuer ready (issuerId=${issuer_db_id})"
}
