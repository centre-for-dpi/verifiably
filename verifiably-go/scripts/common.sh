#!/usr/bin/env bash
# common.sh — shared config, env loading, and helper functions for verifiably-go
# deploy scripts. Sourced by deploy.sh and by each modular sub-script when run
# standalone. Idempotent: guarded by _VERIFIABLY_COMMON_LOADED.
[[ "${_VERIFIABLY_COMMON_LOADED:-}" == "1" ]] && return 0
# Resolve verifiably-go root when sourced standalone (from a sub-script).
: "${SCRIPT_DIR:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Source the .env if present. Honors an operator-provided
# VERIFIABLY_ENV_FILE so a single invocation can target a different file
# (e.g. .env.ec2). Otherwise falls back to ./.env, then to ./.env.example
# so a fresh checkout boots on the example defaults.
if [[ -z "${VERIFIABLY_ENV_FILE:-}" ]]; then
    if [[ -f "$SCRIPT_DIR/.env" ]]; then
        VERIFIABLY_ENV_FILE="$SCRIPT_DIR/.env"
    elif [[ -f "$SCRIPT_DIR/.env.example" ]]; then
        VERIFIABLY_ENV_FILE="$SCRIPT_DIR/.env.example"
    fi
fi
if [[ -n "${VERIFIABLY_ENV_FILE:-}" && -f "$VERIFIABLY_ENV_FILE" ]]; then
    set -o allexport
    # shellcheck disable=SC1090
    source "$VERIFIABLY_ENV_FILE"
    set +o allexport
fi
export VERIFIABLY_ENV_FILE

: "${VERIFIABLY_COMPOSE_FILE:=$SCRIPT_DIR/deploy/compose/stack/docker-compose.yml}"
: "${VERIFIABLY_COMPOSE_OVERRIDE:=$SCRIPT_DIR/deploy/docker-compose.injiweb-fix.yml}"
: "${VERIFIABLY_PUBLIC_HOST:=localhost}"
: "${PUBLIC_HOST:=$VERIFIABLY_PUBLIC_HOST}"
: "${VERIFIABLY_ADDR:=:8080}"
: "${VERIFIABLY_HOST_PORT:=8080}"
# VERIFIABLY_HOSTS_PATTERN — optional printf-style pattern that overrides
# the per-service "$HOST:$PORT" URL when set. The "%s" placeholder is the
# service slug (wso2, walt-issuer, walt-wallet, walt-verifier, inji-certify,
# inji-certify-preauth, inji-verify, inji-verify-ui, inji-web, esignet,
# mimoto, verifiably). Example for the bootcamp.cdpi.dev fleet:
#   VERIFIABLY_HOSTS_PATTERN=https://%s.bootcamp.cdpi.dev
# Empty (the default) preserves the legacy http://$VERIFIABLY_PUBLIC_HOST:$PORT
# behaviour so localhost / docker-bridge deployments work unchanged. The
# pattern is consumed by url_for() below; verifiably-go itself stays
# backend-agnostic — the same binary runs in either mode.
# PostgreSQL for verifiably-go's own persistence (sessions, issuance log,
# status lists). Leave unset to use the file-backed stores (default for
# single-node / dev deployments). Set to enable HA / multi-replica.
# Example: postgres://verifiably:verifiably@localhost:5439/verifiably?sslmode=disable
: "${VERIFIABLY_PG_USER:=verifiably}"
: "${VERIFIABLY_PG_PASSWORD:=verifiably}"
: "${VERIFIABLY_PG_DB:=verifiably}"
: "${VERIFIABLY_PG_PORT:=5439}"
: "${VERIFIABLY_DATABASE_URL:=}"   # empty = file-backed stores
# Redis for multi-replica session sharing. Takes priority over PostgreSQL
# sessions when set. Pair with Caddy lb_policy=cookie for sticky L7.
: "${VERIFIABLY_REDIS_PORT:=6380}"
: "${VERIFIABLY_REDIS_URL:=}"     # empty = no Redis session store

: "${VERIFIABLY_HOSTS_PATTERN:=}"

# resolve_slug picks the actual subdomain label for a service. The default
# is the canonical internal name (walt-issuer, keycloak, verifiably, ...);
# operators who want a custom subdomain naming scheme set
# VERIFIABLY_SLUG_<UPPER_SNAKE> to override on a per-service basis.
# Examples:
#   VERIFIABLY_SLUG_VERIFIABLY=vc        → vc.<domain>
#   VERIFIABLY_SLUG_KEYCLOAK=auth        → auth.<domain>
#   VERIFIABLY_SLUG_INJI_VERIFY_UI=inji-verify
# Empty override = "skip this service in the public Caddyfile" — useful
# for services that don't need browser exposure (e.g. an inji-verify
# backend that only verifiably-go itself talks to over docker DNS).
resolve_slug() {
  local default="$1"
  local upper
  upper=$(printf '%s' "$default" | tr '[:lower:]-' '[:upper:]_')
  local var="VERIFIABLY_SLUG_${upper}"
  # ${!var} = indirect expansion. Returns "" if unset, the override otherwise.
  if [[ -v "$var" ]]; then
    printf '%s' "${!var}"
  else
    printf '%s' "$default"
  fi
}

# url_for picks between the per-subdomain pattern and the legacy
# host:port form. Centralising the choice means every service URL
# below is one helper call and a slug — adding the next deployment
# style won't require touching backends_for + auth_providers_for +
# bootstrap-* in lockstep.
#
# Args: <internal-name> <fallback-host> <fallback-port> [path-suffix]
# Returns: stdout, no trailing slash. path-suffix is appended verbatim
# when supplied so callers that need a trailing path (e.g. /realms/foo)
# don't have to handle the conditional themselves.
#
# In pattern mode the slug used in the URL is the operator's override
# (resolve_slug above) when set, otherwise the internal name. Empty
# override falls back to host:port — useful for services the operator
# doesn't want at a subdomain.
url_for() {
  local name="$1" host="$2" port="$3" suffix="${4:-}"
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    local slug
    slug=$(resolve_slug "$name")
    if [[ -n "$slug" ]]; then
      # Avoid double-prefix: if slug == first label of VERIFIABLY_PUBLIC_DOMAIN
      # (e.g. slug "verifiably" + domain "verifiably.ysalabs.work"), use the
      # bare domain URL instead of prepending the slug again.
      local _first_label="${VERIFIABLY_PUBLIC_DOMAIN%%.*}"
      if [[ -n "$VERIFIABLY_PUBLIC_DOMAIN" && "$slug" == "$_first_label" ]]; then
        printf "https://%s%s" "$VERIFIABLY_PUBLIC_DOMAIN" "$suffix"
      else
        printf "${VERIFIABLY_HOSTS_PATTERN}%s" "$slug" "$suffix"
      fi
      return
    fi
  fi
  printf "http://%s:%s%s" "$host" "$port" "$suffix"
}

# VERIFIABLY_PUBLIC_SLUGS — the service subdomains verifiably-go talks to
# server-side. Kept as an overridable space-separated list so compute_host_aliases
# (and its unit test) stay in sync with the slugs gen-caddy.sh routes.
: "${VERIFIABLY_PUBLIC_SLUGS:=verifiably keycloak wso2 credebl walt-issuer walt-wallet walt-verifier inji-certify inji-certify-preauth inji-certify-authcode inji-verify inji-verify-ui inji-web mimoto esignet}"

# compute_host_aliases <domain> <caddy_ip>
# Prints `docker run --add-host` arguments — one token per line, so a caller can
# read them straight into an array — pinning every public service subdomain to
# the caddy-public container IP. This is the subdomain hairpin-NAT fix: it lets
# verifiably-go reach the public https://<slug>.<domain> URLs from inside the
# container, where they otherwise resolve to the host's own public IP and fail
# to hairpin back to the published :443 (see scripts/start-container.sh).
#
# Prints NOTHING in legacy host:port mode (empty domain or empty ip). Pure — no
# Docker, no network, no globals mutated — so it is unit-testable on its own
# (scripts/ci/test-host-aliases.sh).
compute_host_aliases() {
  local domain="$1" ip="$2" slug
  [[ -n "$domain" && -n "$ip" ]] || return 0
  for slug in $VERIFIABLY_PUBLIC_SLUGS; do
    printf -- '--add-host\n%s.%s:%s\n' "$slug" "$domain" "$ip"
  done
}

: "${VERIFIABLY_PUBLIC_URL:=$(url_for verifiably "$VERIFIABLY_PUBLIC_HOST" "$VERIFIABLY_HOST_PORT")}"

# Purpose-named registry subdomains. verifiably splits its registry surfaces by
# purpose: the national ID registry (identity/eSignet-auth data) and the
# credential-registry admin console. The defaults give the dotted forms
# identity.registry.<domain> and admin.registry.<domain> so a fresh deployment
# reads them by name; they resolve via the *.registry.<domain> wildcard the
# agency registries already use. `=` (not `:=`) preserves the "empty = skip this
# subdomain" escape hatch resolve_slug honours; set to another label to rename.
: "${VERIFIABLY_SLUG_IDENTITY_REGISTRY=identity.registry}"
: "${VERIFIABLY_SLUG_REGISTRY_ADMIN=admin.registry}"
export VERIFIABLY_SLUG_IDENTITY_REGISTRY VERIFIABLY_SLUG_REGISTRY_ADMIN

# Registry Admin console — the data-source tier UI (deploy/registry-admin/).
# REGISTRY_ADMIN_HOST_PORT is the published host port; VERIFIABLY_REGISTRY_ADMIN_URL
# is the browser-facing URL verifiably-go surfaces in its navbar ("Registry"
# link). Resolved through url_for so it is per-host: subdomain mode ->
# https://registry-admin.<domain> (fronted by caddy-public), legacy mode ->
# http://<host>:<REGISTRY_ADMIN_HOST_PORT>. Computed here (not just in cmd_up)
# so `deploy.sh run <scenario>` — which doesn't run cmd_up's URL-export block —
# also passes it to the container via scripts/start-container.sh. Exported so
# docker compose / sub-shells inherit it.
: "${REGISTRY_ADMIN_HOST_PORT:=18095}"
: "${VERIFIABLY_REGISTRY_ADMIN_URL:=$(url_for registry-admin "$VERIFIABLY_PUBLIC_HOST" "$REGISTRY_ADMIN_HOST_PORT")}"
# The Sunbird RC API endpoint the registry-admin console POSTs to (published on
# the host at :18091). Derived from the deployment host so it is not hardcoded to
# any one box; override REGISTRY_ADMIN_SUNBIRD_URL in .env for a different host.
: "${SUNBIRD_RC_HOST_PORT:=18091}"
: "${REGISTRY_ADMIN_SUNBIRD_URL:=http://${VERIFIABLY_PUBLIC_HOST:-localhost}:${SUNBIRD_RC_HOST_PORT}}"
export REGISTRY_ADMIN_HOST_PORT VERIFIABLY_REGISTRY_ADMIN_URL REGISTRY_ADMIN_SUNBIRD_URL

: "${LIBRETRANSLATE_PORT:=5000}"
: "${VERIFIABLY_IMAGE:=verifiably-go:local}"
: "${VERIFIABLY_CONTAINER:=verifiably-go}"

# Per-service ports used in the stanzas + URL rewrite map.
: "${WALTID_ISSUER_PORT:=7002}"
# CREDEBL — compose-managed DPG stack (deploy/compose/credebl/).
# `./deploy.sh up credebl` spins up all CREDEBL services locally.
# To use an EXTERNAL CREDEBL instead, set CREDEBL_API_URL and friends.
: "${CREDEBL_API_PORT:=5001}"             # host port for api-gateway (5000 conflicts with LibreTranslate)
: "${CREDEBL_MINIO_CONSOLE_PORT:=9013}"
: "${CREDEBL_POSTGRES_PASSWORD:=}"        # auto-generated in ensure_credebl_env if empty
: "${CREDEBL_MINIO_ROOT_PASSWORD:=}"
: "${CREDEBL_MINIO_ACCESS_KEY:=credebls3}"
: "${CREDEBL_MINIO_SECRET_KEY:=}"
: "${CREDEBL_JWT_SECRET:=}"
: "${CREDEBL_JWT_TOKEN_SECRET:=}"
: "${CREDEBL_PLATFORM_SEED:=}"
: "${CREDEBL_AGENT_API_KEY:=}"
: "${CREDEBL_PLATFORM_WALLET_PASSWORD:=}"
: "${CREDEBL_NEXTAUTH_SECRET:=}"
: "${CREDEBL_KEYCLOAK_CLIENT_SECRET:=}"
: "${CREDEBL_SCHEMA_FILE_SERVER_TOKEN:=}"
: "${CREDEBL_CRYPTO_PRIVATE_KEY:=}"       # auto-generated in ensure_credebl_env if empty
: "${CREDEBL_ADMIN_EMAIL:=admin@cdpi.dev}"
: "${CREDEBL_KEYCLOAK_HOST:=${VERIFIABLY_PUBLIC_HOST}}"    # bare hostname of shared Keycloak (for extra_hosts)
: "${CREDEBL_COMPOSE_DIR:=$SCRIPT_DIR/deploy/compose/credebl}"
export CREDEBL_COMPOSE_DIR
# External CREDEBL (legacy): set CREDEBL_API_URL to point at an external CREDEBL instance
: "${CREDEBL_API_URL:=}"             # e.g. http://161.97.152.40:5000 or https://credebl.example.com
: "${CREDEBL_EMAIL:=}"               # platform-admin email
: "${CREDEBL_PASSWORD:=}"            # plaintext; encrypted by adapter at sign-in
: "${CREDEBL_ORG_ID:=}"              # org UUID provisioned by init-credebl.sh
: "${CREDEBL_ISSUER_ID:=}"           # OID4VCI issuer DB ID from init-credebl.sh
: "${CREDEBL_VERIFIER_ID:=}"         # optional — auto-provisioned on first verify
: "${CREDEBL_DEFAULT_PIN:=1234}"
: "${CREDEBL_INTERNAL_BASE_URL:=}"   # optional — Docker-internal host the Credo
                                     # controller advertises in offer URIs. Set
                                     # when offers embed a Docker service name that
                                     # wallets can't resolve. Leave empty otherwise.
: "${WALTID_WALLET_PORT:=7001}"
: "${WALTID_VERIFIER_PORT:=7003}"
: "${CERTIFY_NGINX_PORT:=8091}"
: "${CERTIFY_PREAUTH_PORT:=8094}"
: "${INJI_VERIFY_UI_PORT:=3001}"
: "${INJI_VERIFY_SERVICE_PORT:=8082}"
: "${INJIWEB_UI_PUBLIC_PORT:=3004}"
: "${ESIGNET_PUBLIC_PORT:=3005}"
: "${MIMOTO_PORT:=8099}"
: "${KEYCLOAK_PORT:=8180}"
: "${KEYCLOAK_REALM:=vcplatform}"
: "${KEYCLOAK_CLIENT_ID:=vcplatform}"
: "${WSO2_PORT:=9443}"
: "${WSO2_CLIENT_ID:=verifiably_go_client}"
# The `waltid_` prefix on volumes + network is load-bearing in the shared
# compose (pinned via `name: waltid`). Every compose subcommand we issue
# must point at the same project name so we line up with the existing state.
: "${COMPOSE_PROJECT:=waltid}"

# Service lists per scenario. Kept here (not inside the compose file) so
# this script is the single source of truth for "what belongs to which
# scenario" and can evolve without touching the shared compose.

# ── Walt ID — role-specific service arrays ───────────────────────────────────
WALTID_ISSUER_SVCS=(postgres caddy issuer-api)
WALTID_VERIFIER_SVCS=(postgres caddy verifier-api)
WALTID_HOLDER_SVCS=(postgres caddy wallet-api)
# Backward-compat aliases (not used internally — kept for external scripts)
WALTID_SERVICES=(postgres caddy issuer-api verifier-api wallet-api)
# When VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL is set, the operator is
# pointing verifiably-go at an external Keycloak (one they don't host
# themselves — e.g. an upstream realm shared by another team). In that
# case we don't run a local keycloak container, don't try to bootstrap
# its client list (we have no admin creds anyway), and write the
# external URL + client into auth-providers.json so the picker tile
# routes through the external server.
: "${VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL:=}"
: "${VERIFIABLY_KEYCLOAK_EXTERNAL_CLIENT_ID:=}"
: "${VERIFIABLY_KEYCLOAK_EXTERNAL_CLIENT_SECRET:=}"
if [[ -n "$VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL" ]]; then
  IDP_KEYCLOAK=()       # skip local container
else
  IDP_KEYCLOAK=( keycloak )
fi
# WSO2IS adds a second IdP card alongside Keycloak. It's optional — set
# VERIFIABLY_SKIP_WSO2IS=1 (or =true) to drop it. The container needs ~1.2 GiB
# of heap and ~1.5 GiB total, which is the difference between fitting inji
# into a 4 GiB Docker Desktop allocation and OOM-killing on bring-up.
# Set VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL to also skip the Keycloak
# container if you're pointing at an upstream realm.
: "${VERIFIABLY_SKIP_WSO2IS:=}"
case "$VERIFIABLY_SKIP_WSO2IS" in
  1|true|TRUE|yes|YES) IDP_WSO2IS=() ;;
  *) IDP_WSO2IS=( wso2is ) ;;
esac
TRANSLATOR_SERVICES=( libretranslate )
# Backward-compat alias (not used internally — kept for external scripts)
INJI_CORE_SERVICES=(
  certify-postgres inji-certify
  certify-preauth-postgres inji-certify-preauth-backend inji-preauth-proxy
  certify-nginx certify-preauth-nginx
  inji-verify-postgres inji-verify-service inji-verify-ui
  citizens-postgres vc-adapter
  registry-admin
)

# ── Inji — role-specific service arrays ──────────────────────────────────────
INJI_ISSUER_SVCS=(
  certify-postgres inji-certify
  certify-preauth-postgres inji-certify-preauth-backend inji-preauth-proxy
  certify-nginx certify-preauth-nginx
  citizens-postgres
)
INJI_VERIFIER_SVCS=(
  inji-verify-postgres inji-verify-service inji-verify-ui
  vc-adapter
)
# INJI holder = INJIWEB_SERVICES defined below

INJIWEB_SERVICES=(
  injiweb-postgres injiweb-redis
  injiweb-mock-identity injiweb-esignet injiweb-oidc-ui
  injiweb-minio injiweb-datashare injiweb-mimoto injiweb-ui
)

# ── CREDEBL — role-specific service arrays ────────────────────────────────────
# Infra: required for every CREDEBL role
CREDEBL_INFRA_SVCS=(
  credebl-postgres credebl-redis credebl-nats
)
# Shared: lightweight orchestration services needed by all roles
CREDEBL_SHARED_SVCS=(
  credebl-seed credebl-platform-admin-bootstrap
  credebl-api-gateway credebl-user credebl-utility
  credebl-agent-provisioning credebl-agent-service
  credebl-ecosystem
)
# Issuer-specific: schema storage, notification, issuance pipeline
CREDEBL_ISSUER_SVCS=(
  credebl-minio credebl-minio-setup
  credebl-mailpit
  credebl-schema-file-server credebl-oob-redirector
  credebl-connection credebl-issuance credebl-ledger
  credebl-organization
  credebl-oid4vc-issuance
  credebl-oid4vci-rewriter
)
# Verifier-specific
CREDEBL_VERIFIER_SVCS=(
  credebl-connection credebl-verification
  credebl-oid4vc-verification
)
# Holder-specific
CREDEBL_HOLDER_SVCS=(
  credebl-cloud-wallet
)
# Backward-compat alias (union of all roles)
CREDEBL_SERVICES=(
  credebl-postgres credebl-redis credebl-nats
  credebl-minio credebl-minio-setup
  credebl-mailpit
  credebl-schema-file-server credebl-oob-redirector
  credebl-seed credebl-platform-admin-bootstrap
  credebl-api-gateway credebl-user credebl-utility
  credebl-connection credebl-issuance credebl-ledger
  credebl-organization credebl-verification
  credebl-agent-provisioning credebl-agent-service
  credebl-cloud-wallet credebl-oid4vc-issuance
  credebl-oid4vc-verification credebl-ecosystem
  credebl-oid4vci-rewriter
)

# ── Role helpers ─────────────────────────────────────────────────────────────

# resolve_role: returns the active role string.
# Precedence: CLI_ROLE (set by deploy.sh --role flag)
#           > VERIFIABLY_ROLES (from .env)
#           > default "issuer,verifier,holder" (full deployment, backward-compat)
resolve_role() {
  printf '%s' "${CLI_ROLE:-${VERIFIABLY_ROLES:-issuer,verifier,holder}}"
}

# validate_roles <role-string>
# Exits non-zero on unknown roles or empty string.
# Warns (with interactive prompt) if 'holder' is requested without 'issuer'.
validate_roles() {
  local role_str="$1"
  if [[ -z "${role_str// /}" ]]; then
    red "VERIFIABLY_ROLES cannot be empty. Valid values: issuer, verifier, holder"
    return 1
  fi
  local r
  IFS=',' read -ra _roles <<< "$role_str"
  local has_issuer=0 has_holder=0
  for r in "${_roles[@]}"; do
    r="${r// /}"
    case "$r" in
      issuer|verifier|holder) ;;
      # trust/schemas/hub are valid roles for the Go app (see
      # internal/roles/roles.go) but don't affect container selection here —
      # accept them as no-ops so a VERIFIABLY_ROLES value that's legitimate
      # for the Go app layer (e.g. .env.example's issuer,verifier,schemas)
      # doesn't get rejected at the bash layer.
      trust|schemas|hub) ;;
      *) red "unknown role '$r'. Valid: issuer, verifier, holder (container selection); trust, schemas, hub also accepted as no-ops for Go-app compatibility"; return 1 ;;
    esac
    [[ "$r" == "issuer" ]] && has_issuer=1
    [[ "$r" == "holder" ]] && has_holder=1
  done
  if [[ "$has_holder" == "1" && "$has_issuer" == "0" ]]; then
    yellow "  Warning: deploying 'holder' without 'issuer' — wallet cannot receive new credentials."
    if [[ -t 0 ]]; then
      printf '  Continue? [y/N] '
      local _ans; read -r _ans
      [[ "$_ans" =~ ^[Yy]$ ]] || { red "Aborted."; return 1; }
    fi
  fi
}

# role_services <dpg> <role-string>
# Prints service names (one per line) for the given DPG × role combination.
# <role-string> may be comma-separated (e.g. "issuer,verifier").
# Output is deduplicated preserving first-occurrence order.
role_services() {
  local dpg="$1" role_str="$2"
  local -a _svc=()
  local r
  IFS=',' read -ra _roles <<< "$role_str"
  for r in "${_roles[@]}"; do
    r="${r// /}"
    case "${dpg}:${r}" in
      waltid:issuer)    _svc+=( "${WALTID_ISSUER_SVCS[@]}" ) ;;
      waltid:verifier)  _svc+=( "${WALTID_VERIFIER_SVCS[@]}" ) ;;
      waltid:holder)    _svc+=( "${WALTID_HOLDER_SVCS[@]}" ) ;;
      inji:issuer)      _svc+=( "${INJI_ISSUER_SVCS[@]}" ) ;;
      inji:verifier)    _svc+=( "${INJI_VERIFIER_SVCS[@]}" ) ;;
      inji:holder)      _svc+=( "${INJIWEB_SERVICES[@]}" ) ;;
      credebl:issuer)   _svc+=( "${CREDEBL_INFRA_SVCS[@]}" "${CREDEBL_SHARED_SVCS[@]}" "${CREDEBL_ISSUER_SVCS[@]}" ) ;;
      credebl:verifier) _svc+=( "${CREDEBL_INFRA_SVCS[@]}" "${CREDEBL_SHARED_SVCS[@]}" "${CREDEBL_VERIFIER_SVCS[@]}" ) ;;
      credebl:holder)   _svc+=( "${CREDEBL_INFRA_SVCS[@]}" "${CREDEBL_SHARED_SVCS[@]}" "${CREDEBL_HOLDER_SVCS[@]}" ) ;;
      waltid:trust|waltid:schemas|waltid:hub) ;;
      inji:trust|inji:schemas|inji:hub) ;;
      credebl:trust|credebl:schemas|credebl:hub) ;;
      *)
        red "unknown DPG:role '${dpg}:${r}' (valid roles: issuer, verifier, holder; trust, schemas, hub also accepted as no-ops)"
        return 1
        ;;
    esac
  done
  printf '%s\n' "${_svc[@]}" | awk '!seen[$0]++'
}

# infra_services
# Returns IdP and translator services shared across roles. wso2is is
# opt-out via VERIFIABLY_SKIP_WSO2IS regardless of role count — it's a
# shared IdP, not tied to any specific role's presence — so we just
# respect the already-computed IDP_WSO2IS array (see VERIFIABLY_SKIP_WSO2IS
# case statement above) instead of re-deriving the skip decision here.
infra_services() {
  printf '%s\n' "${IDP_KEYCLOAK[@]}" "${TRANSLATOR_SERVICES[@]}" "${IDP_WSO2IS[@]}"
}

# ------------------------------------------------------------------ helpers

red()    { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

# set_env_var <file> <VAR> <value>
# Upserts VAR=value in an existing .env file. Replaces existing line or
# appends.
#
# Why awk + tmp file instead of sed -i: BSD sed (macOS) interprets the
# argument after -i as the backup-file extension; the same `sed -i "expr"`
# that's a no-op on GNU breaks the wizard with "command a expects \..."
# on every Mac. awk works the same on both platforms and avoids any
# in-place quoting traps.
set_env_var() {
  local file="$1" var="$2" val="$3"
  [[ -f "$file" ]] || return 0
  if grep -q "^${var}=" "$file" 2>/dev/null; then
    local tmp
    tmp=$(mktemp "${file}.XXXXXX")
    awk -v var="$var" -v val="$val" '
      BEGIN { prefix = var "=" }
      index($0, prefix) == 1 { print prefix val; next }
      { print }
    ' "$file" > "$tmp" && mv "$tmp" "$file"
  else
    printf '\n%s=%s\n' "$var" "$val" >> "$file"
  fi
}

require() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || { red "missing dependency: $cmd"; exit 1; }
}

compose() {
  local extra=()
  # --env-file points compose at verifiably-go/.env (one source of truth).
  # Without this, compose falls back to deploy/compose/stack/.env next to
  # the compose file — which would drift from the top-level .env. Only
  # attach if the file actually exists; compose errors out on missing.
  if [[ -n "${VERIFIABLY_ENV_FILE:-}" && -f "$VERIFIABLY_ENV_FILE" ]]; then
    extra+=( --env-file "$VERIFIABLY_ENV_FILE" )
  fi
  if [[ -f "$VERIFIABLY_COMPOSE_OVERRIDE" ]]; then
    # When docker compose layers multiple files, relative paths inside
    # each file are resolved relative to the FIRST -f argument, not the
    # file that declared them. That breaks our override — it ends up
    # looking for the patched bootstrap under deploy/compose/stack/verifiably-go/…
    # which doesn't exist. Materialise a rendered override with an
    # absolute path instead.
    local rendered="$SCRIPT_DIR/config/docker-compose.injiweb-fix.rendered.yml"
    sed "s|{{VERIFIABLY_GO_DIR}}|$SCRIPT_DIR|g" "$VERIFIABLY_COMPOSE_OVERRIDE" > "$rendered"
    extra+=( -f "$rendered" )
  fi
  # Always include the CREDEBL compose file when it exists. Docker compose
  # profiles (--profile credebl) control which services actually start — the
  # file being present doesn't start anything on its own.
  local credebl_compose="$SCRIPT_DIR/deploy/compose/credebl/docker-compose.yml"
  if [[ -f "$credebl_compose" ]]; then
    extra+=( -f "$credebl_compose" )
  fi
  docker compose -p "$COMPOSE_PROJECT" -f "$VERIFIABLY_COMPOSE_FILE" "${extra[@]}" "$@"
}

scenario_services() {
  local scenario="$1"
  local _role
  _role=$(resolve_role)
  case "$scenario" in
    all)
      { role_services waltid "$_role"; role_services inji "$_role"; } \
        | awk '!seen[$0]++'
      infra_services
      if [[ -z "$CREDEBL_API_URL" ]]; then
        role_services credebl "$_role"
      fi
      ;;
    waltid)
      role_services waltid "$_role"
      infra_services
      ;;
    inji)
      role_services inji "$_role"
      infra_services
      ;;
    credebl)
      role_services credebl "$_role"
      infra_services
      ;;
    *)
      red "unknown scenario: $scenario (want: all | waltid | inji | credebl)"; return 1;;
  esac
}

# scenario_needs_injiweb prints "yes" if the scenario includes any injiweb-*
# service — that decides whether we need to pass `--profile injiweb` to
# docker compose.
#
# Captures scenario_services' output into a variable before grepping it,
# rather than piping directly into `grep -q`: since scenario_services runs
# role_services/infra_services as separate sequential commands (not one
# printf), `grep -q` can find its match on an early line and close the pipe
# while a later producer is still writing, killing it with SIGPIPE — which
# `set -e` then treats as scenario_services itself having failed, masking a
# real "yes" as "no".
scenario_needs_injiweb() {
  local _out
  _out=$(scenario_services "$1")
  grep -q '^injiweb-' <<< "$_out" && echo yes || echo no
}

# scenario_needs_credebl prints "yes" if the scenario includes any credebl-*
# service — that decides whether we need to pass `--profile credebl` to
# docker compose and run the CREDEBL bootstrap functions.
# See scenario_needs_injiweb's comment for why this captures to a variable
# instead of piping directly into `grep -q`.
scenario_needs_credebl() {
  local _out
  _out=$(scenario_services "$1")
  grep -q '^credebl-' <<< "$_out" && echo yes || echo no
}

# backends_for writes a scenario-specific config/backends.json. The content
# is assembled by including scenario-relevant stanzas; anything not in the
# scenario gets omitted so the UI never offers a DPG whose backend isn't up.
_VERIFIABLY_COMMON_LOADED=1
