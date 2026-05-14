#!/usr/bin/env bash
# verifiably-go deploy script
#
# Single entry point for three scenarios, each of which brings up a curated
# subset of the shared compose stack and launches verifiably-go with a
# backends.json tailored to that subset.
#
#   ./deploy.sh up all     — every DPG (walt.id + inji stack + inji web)
#                            plus Keycloak + WSO2IS + LibreTranslate.
#   ./deploy.sh up waltid  — verifiably-go + walt.id + Keycloak + LibreTranslate.
#   ./deploy.sh up inji    — verifiably-go + Inji Certify (auth-code + pre-auth)
#                            + Inji Verify + Inji Web + WSO2IS + LibreTranslate.
#
# Other subcommands:
#   ./deploy.sh down [scenario]    — stop the services for a scenario (or all).
#   ./deploy.sh status             — summarise what's running.
#   ./deploy.sh config <scenario>  — print the backends.json that would be used.
#   ./deploy.sh run <scenario>     — generate backends.json + start verifiably-go
#                                    (without touching compose — for when the
#                                     stack is already up).
#
# The script does NOT modify the shared compose file; it selects services
# explicitly via `docker compose up <service> ...` and opts into the injiweb
# profile when the scenario needs it.

set -euo pipefail

# ------------------------------------------------------------------ config

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
: "${VERIFIABLY_PUBLIC_HOST:=172.24.0.1}"
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
: "${VERIFIABLY_HOSTS_PATTERN:=}"
: "${VERIFIABLY_PUBLIC_URL:=$(
    if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
      printf "$VERIFIABLY_HOSTS_PATTERN" verifiably
    else
      echo "http://${VERIFIABLY_PUBLIC_HOST}:$VERIFIABLY_HOST_PORT"
    fi
  )}"

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
      printf "${VERIFIABLY_HOSTS_PATTERN}%s" "$slug" "$suffix"
      return
    fi
  fi
  printf "http://%s:%s%s" "$host" "$port" "$suffix"
}
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
: "${CREDEBL_CRYPTO_PRIVATE_KEY:=cdpi-poc-crypto-key-change-me}"
: "${CREDEBL_ADMIN_EMAIL:=admin@cdpi.dev}"
: "${CREDEBL_KEYCLOAK_HOST:=localhost}"    # bare hostname of shared Keycloak (for extra_hosts)
: "${CREDEBL_COMPOSE_DIR:=}"              # set by deploy.sh to deploy/compose/credebl abs path
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

WALTID_SERVICES=(
  postgres caddy issuer-api verifier-api wallet-api
)
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
IDP_WSO2IS=( wso2is )
TRANSLATOR_SERVICES=( libretranslate )
INJI_CORE_SERVICES=(
  certify-postgres inji-certify
  certify-preauth-postgres inji-certify-preauth-backend inji-preauth-proxy
  certify-nginx certify-preauth-nginx
  inji-verify-postgres inji-verify-service inji-verify-ui
  citizens-postgres vc-adapter
)
INJIWEB_SERVICES=(
  injiweb-postgres injiweb-redis
  injiweb-mock-identity injiweb-esignet injiweb-oidc-ui
  injiweb-minio injiweb-datashare injiweb-mimoto injiweb-ui
)
# CREDEBL compose services — started when `./deploy.sh up credebl` is used
# without an external CREDEBL_API_URL.
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
)

# ------------------------------------------------------------------ helpers

red()    { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

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
  # Both IdPs are included in every scenario so the auth page always offers
  # BOTH Keycloak and WSO2IS regardless of which DPG stack the user is
  # driving. The translator is always on for the same reason (i18n in the
  # topbar).
  case "$scenario" in
    all)
      printf '%s\n' \
        "${WALTID_SERVICES[@]}" \
        "${IDP_KEYCLOAK[@]}" "${IDP_WSO2IS[@]}" \
        "${TRANSLATOR_SERVICES[@]}" \
        "${INJI_CORE_SERVICES[@]}" \
        "${INJIWEB_SERVICES[@]}"
      # Include CREDEBL compose services when no external URL is configured.
      if [[ -z "$CREDEBL_API_URL" && -n "$CREDEBL_POSTGRES_PASSWORD" ]]; then
        printf '%s\n' "${CREDEBL_SERVICES[@]}"
      fi
      ;;
    waltid)
      printf '%s\n' \
        "${WALTID_SERVICES[@]}" \
        "${IDP_KEYCLOAK[@]}" "${IDP_WSO2IS[@]}" \
        "${TRANSLATOR_SERVICES[@]}"
      ;;
    inji)
      printf '%s\n' \
        "${INJI_CORE_SERVICES[@]}" \
        "${INJIWEB_SERVICES[@]}" \
        "${IDP_KEYCLOAK[@]}" "${IDP_WSO2IS[@]}" \
        "${TRANSLATOR_SERVICES[@]}"
      ;;
    credebl)
      # CREDEBL compose-managed: all CREDEBL services + shared IdP + translator.
      printf '%s\n' \
        "${CREDEBL_SERVICES[@]}" \
        "${IDP_KEYCLOAK[@]}" "${IDP_WSO2IS[@]}" \
        "${TRANSLATOR_SERVICES[@]}"
      ;;
    *)
      red "unknown scenario: $scenario (want: all | waltid | inji | credebl)"; return 1;;
  esac
}

# scenario_needs_injiweb prints "yes" if the scenario includes any injiweb-*
# service — that decides whether we need to pass `--profile injiweb` to
# docker compose.
scenario_needs_injiweb() {
  scenario_services "$1" | grep -q '^injiweb-' && echo yes || echo no
}

# scenario_needs_credebl prints "yes" if the scenario includes any credebl-*
# service — that decides whether we need to pass `--profile credebl` to
# docker compose and run the CREDEBL bootstrap functions.
scenario_needs_credebl() {
  scenario_services "$1" | grep -q '^credebl-' && echo yes || echo no
}

# backends_for writes a scenario-specific config/backends.json. The content
# is assembled by including scenario-relevant stanzas; anything not in the
# scenario gets omitted so the UI never offers a DPG whose backend isn't up.
backends_for() {
  local scenario="$1"
  local out="$SCRIPT_DIR/config/backends.json"

  # Per-service URLs resolved through url_for() so a single env var
  # (VERIFIABLY_HOSTS_PATTERN) flips between localhost:port and
  # https://<service>.<domain>. Slugs match the 11 A records the
  # operator typically configures: wso2, walt-issuer, walt-wallet,
  # walt-verifier, inji-certify, inji-certify-preauth, inji-verify,
  # inji-verify-ui, inji-web, esignet, mimoto. Verifiably-go itself
  # consumes these as opaque URLs — same binary, both modes.
  local walt_issuer_url   walt_wallet_url   walt_verifier_url
  local certify_url       certify_preauth_url
  local inji_verify_svc_url inji_verify_ui_url
  local injiweb_url       mimoto_url        esignet_url
  walt_issuer_url=$(url_for walt-issuer "$VERIFIABLY_PUBLIC_HOST" "$WALTID_ISSUER_PORT")
  walt_wallet_url=$(url_for walt-wallet "$VERIFIABLY_PUBLIC_HOST" "$WALTID_WALLET_PORT")
  walt_verifier_url=$(url_for walt-verifier "$VERIFIABLY_PUBLIC_HOST" "$WALTID_VERIFIER_PORT")
  certify_url=$(url_for inji-certify "$VERIFIABLY_PUBLIC_HOST" "$CERTIFY_NGINX_PORT")
  certify_preauth_url=$(url_for inji-certify-preauth "$VERIFIABLY_PUBLIC_HOST" "$CERTIFY_PREAUTH_PORT")
  inji_verify_svc_url=$(url_for inji-verify "$VERIFIABLY_PUBLIC_HOST" "$INJI_VERIFY_SERVICE_PORT")
  inji_verify_ui_url=$(url_for inji-verify-ui "$VERIFIABLY_PUBLIC_HOST" "$INJI_VERIFY_UI_PORT")
  injiweb_url=$(url_for inji-web "$VERIFIABLY_PUBLIC_HOST" "$INJIWEB_UI_PUBLIC_PORT")
  mimoto_url=$(url_for mimoto "$VERIFIABLY_PUBLIC_HOST" "$MIMOTO_PORT")
  esignet_url=$(url_for esignet "$VERIFIABLY_PUBLIC_HOST" "$ESIGNET_PUBLIC_PORT")

  # Individual DPG stanzas — kept inline as HEREDOCs so the script is
  # self-contained (no per-scenario template files to manage).
  local waltid_stanza
  waltid_stanza=$(cat <<JSON
    {
      "vendor": "Walt Community Stack",
      "type": "walt_community",
      "roles": ["issuer", "holder", "verifier"],
      "dpg": {
        "Vendor": "Walt Community Stack",
        "Version": "v0.18.2",
        "Tag": "API-based",
        "Tagline": "Open-source, API-driven credentialing stack.",
        "FlowPreAuth": true,
        "FlowAuthCode": true,
        "FlowPlain": "OID4VCI with pre-authorized code flow and authorization code flow.",
        "Formats": ["w3c_vcdm_2", "sd_jwt_vc (IETF)", "mso_mdoc"],
        "FormatsPlain": "W3C VCDM 2.0 signed as JWT, SD-JWT VC (IETF), and ISO 18013-5 mdoc.",
        "DirectPDF": false,
        "DirectPDFPlain": "No documented QR-on-PDF export at v0.18.2.",
        "Caveats": "OID4VP v1.0 support in the wallet/demo apps is still rolling out.",
        "Capabilities": [
          {"Kind": "flow",        "Key": "pre_auth",      "Title": "Pre-authorized code flow", "Body": "Issuer stages the offer; wallet redeems at the token endpoint."},
          {"Kind": "flow",        "Key": "auth_code",     "Title": "Authorization code flow",  "Body": "Holder consents at the issuer; wallet exchanges the code."},
          {"Kind": "token",       "Key": "issuer_signed", "Title": "Issuer-signed tokens",     "Body": "Tokens signed by this issuer's own keys."},
          {"Kind": "mode",        "Key": "wallet",        "Title": "Wallet delivery",          "Body": "Offer URI scanned or pasted into any OID4VCI wallet."},
          {"Kind": "bulk_source", "Key": "csv",           "Title": "Bulk from CSV",            "Body": "Operator uploads a CSV; each row issues one credential."},
          {"Kind": "bulk_source", "Key": "api",           "Title": "Bulk from secured API",    "Body": "Adapter GETs a JSON array from an external service."},
          {"Kind": "bulk_source", "Key": "db",            "Title": "Bulk from PostgreSQL",     "Body": "Adapter runs a SELECT against an operator-supplied DSN."}
        ]
      },
      "config": {
        "issuerBaseUrl": "${walt_issuer_url}",
        "verifierBaseUrl": "${walt_verifier_url}",
        "walletBaseUrl": "${walt_wallet_url}",
        "standardVersion": "draft13",
        "demoAccount": {
          "name": "Verifiably Demo",
          "email": "verifiably-demo@example.org",
          "password": "verifiably-demo-password"
        }
      }
    }
JSON
)
  local inji_authcode_stanza
  inji_authcode_stanza=$(cat <<JSON
    {
      "vendor": "Inji Certify · Auth-Code",
      "type": "inji_certify_authcode",
      "roles": ["issuer"],
      "dpg": {
        "Vendor": "Inji Certify",
        "Version": "v0.14.0 · Auth-Code via eSignet",
        "Tag": "MOSIP · Auth-Code",
        "Tagline": "Holder logs into eSignet; Inji Certify validates tokens as a resource server.",
        "FlowAuthCode": true,
        "FlowPresentationDuringIssue": true,
        "FlowPlain": "OID4VCI draft 13 Authorization Code flow via eSignet.",
        "Formats": ["w3c_vcdm_2", "sd_jwt_vc (IETF)"],
        "DirectPDF": false,
        "Caveats": "Holder wallet must be reachable by eSignet's redirect.",
        "Redirect": true,
        "UIURL": "${injiweb_url}",
        "Capabilities": [
          {"Kind": "flow",       "Key": "auth_code",       "Title": "Authorization Code flow",          "Body": "Wallet redirects holder to eSignet for login."},
          {"Kind": "data",       "Key": "identity_lookup", "Title": "Claims from MOSIP Identity Plugin", "Body": "Fills claims via UIN lookup against mock-identity."},
          {"Kind": "wallet",     "Key": "inji_web",        "Title": "Experience via Inji Web Wallet",    "Body": "Clicking the card opens Inji Web where the full eSignet auth-code flow plays out end-to-end."},
          {"Kind": "token",      "Key": "idp_signed",      "Title": "Tokens signed by the IdP",          "Body": "Credential endpoint validates eSignet-signed tokens."},
          {"Kind": "limitation", "Key": "needs_idp",       "Title": "Requires eSignet running",          "Body": "Fails closed if the IdP is unreachable."}
        ]
      },
      "config": {
        "mode": "auth_code",
        "baseUrl": "${certify_url}",
        "internalBaseUrl": "http://certify-nginx:80",
        "publicBaseUrl": "${certify_url}",
        "offerIssuerUrl": "http://certify-nginx:80",
        "authorizationServer": "${esignet_url}"
      }
    }
JSON
)
  local inji_preauth_stanza
  inji_preauth_stanza=$(cat <<JSON
    {
      "vendor": "Inji Certify · Pre-Auth",
      "type": "inji_certify_preauth",
      "roles": ["issuer"],
      "dpg": {
        "Vendor": "Inji Certify",
        "Version": "v0.14.0 · Pre-Authorized Code",
        "Tag": "MOSIP · Pre-Auth",
        "Tagline": "Operator stages claims directly; wallet redeems pre-auth code at certify's own token endpoint.",
        "FlowPreAuth": true,
        "FlowPlain": "Self-contained — no external identity provider.",
        "Formats": ["w3c_vcdm_2", "sd_jwt_vc (IETF)"],
        "DirectPDF": true,
        "DirectPDFPlain": "Server-side dance mints a signed VC and embeds it as a QR on a printable PDF — the subject walks away with paper instead of a wallet credential.",
        "Caveats": "Not compatible with Inji Web Wallet. Demo-only — no user consent.",
        "Capabilities": [
          {"Kind": "flow",        "Key": "pre_auth",         "Title": "Pre-Authorized Code flow",           "Body": "POST /v1/certify/pre-authorized-data; wallet redeems code directly."},
          {"Kind": "data",        "Key": "operator_entered", "Title": "Claims entered by the operator",     "Body": "Operator types claims or loads a CSV row via the Pre-Auth plugin."},
          {"Kind": "wallet",      "Key": "paste",            "Title": "Works with paste-based wallets",     "Body": "Pasteable offer URI for any OID4VCI wallet."},
          {"Kind": "token",       "Key": "self_signed",      "Title": "Tokens signed by this instance",     "Body": "No external IdP; isolated JWKS validates its own tokens."},
          {"Kind": "bulk_source", "Key": "csv",              "Title": "Bulk from CSV",                      "Body": "Matches Inji Certify's native Data Provider Plugin — CSV file uploaded by the operator."},
          {"Kind": "bulk_source", "Key": "db",               "Title": "Bulk from PostgreSQL",               "Body": "Matches Inji Certify's native Data Provider Plugin — operator supplies a DSN + SELECT."},
          {"Kind": "limitation",  "Key": "no_bulk_api",      "Title": "No bulk API source",                 "Body": "docs.inji.io lists PostgreSQL + CSV as the supported Data Provider integrations; API is a 2025 roadmap item. Bulk API chip is hidden for this DPG."},
          {"Kind": "limitation",  "Key": "no_consent",       "Title": "No user consent screen",             "Body": "Demo only — no interactive approval."},
          {"Kind": "limitation",  "Key": "not_inji_web",     "Title": "Not usable by Inji Web Wallet",      "Body": "Mimoto assumes Auth-Code; won't redeem pre-auth offers."}
        ]
      },
      "config": {
        "mode": "pre_auth",
        "baseUrl": "${certify_preauth_url}",
        "internalBaseUrl": "http://inji-certify-preauth:8090",
        "publicBaseUrl": "${certify_preauth_url}",
        "offerIssuerUrl": "http://inji-certify-preauth:8090"
      }
    }
JSON
)
  local inji_verify_stanza
  inji_verify_stanza=$(cat <<JSON
    {
      "vendor": "Inji Verify",
      "type": "inji_verify",
      "roles": ["verifier"],
      "dpg": {
        "Vendor": "Inji Verify",
        "Version": "v0.16.0",
        "Tag": "Redirect",
        "Tagline": "MOSIP verifier — operator runs presentation sessions through Inji Verify's own UI.",
        "FlowPlain": "Click the card to open the real Inji Verify UI in a new tab, or use the in-process direct-verify endpoints (paste/upload a JSON-LD VC).",
        "Formats": ["w3c_vcdm_1", "w3c_vcdm_2", "sd_jwt_vc (IETF)"],
        "Caveats": "INJIVER-1131: v0.16.0 cross-device flow can accept a wrong VC as valid — adapter applies a field-match guard.",
        "Redirect": true,
        "UIURL": "${inji_verify_ui_url}",
        "Capabilities": [
          {"Kind": "flow",       "Key": "direct_paste",  "Title": "Paste JSON-LD VC",         "Body": "POST /v1/verify/vc-verification returns SUCCESS/INVALID synchronously."},
          {"Kind": "flow",       "Key": "direct_upload", "Title": "Upload a QR image",        "Body": "Server decodes the QR with gozxing, then verifies the payload."},
          {"Kind": "flow",       "Key": "oid4vp",        "Title": "OID4VP via Inji Verify UI", "Body": "Full cross-device presentation flow lives in the Inji Verify SPA."},
          {"Kind": "limitation", "Key": "injiver_1131",  "Title": "INJIVER-1131 guard applied", "Body": "Adapter re-checks claims against requested fields."}
        ]
      },
      "config": {
        "baseUrl": "${inji_verify_svc_url}",
        "clientId": "verifiably-demo"
      }
    }
JSON
)
  local injiweb_stanza
  injiweb_stanza=$(cat <<JSON
    {
      "vendor": "Inji Web Wallet",
      "type": "inji_web",
      "roles": ["holder"],
      "dpg": {
        "Vendor": "Inji Web Wallet",
        "Version": "v0.16.0",
        "Tag": "Redirect",
        "Tagline": "MOSIP's browser-hosted wallet — credentials live inside the Inji Web SPA.",
        "FlowPlain": "Holder logs into Inji Web via eSignet. No server-to-server read-back API at v0.16.0.",
        "Formats": ["w3c_vcdm_1", "w3c_vcdm_2"],
        "Caveats": "Tested-compatible with Inji Certify v0.13.1 and Inji Verify v0.17.0 per the v0.16.0 matrix.",
        "Redirect": true,
        "UIURL": "${injiweb_url}",
        "Capabilities": [
          {"Kind": "flow",       "Key": "browser_hosted", "Title": "Browser-hosted wallet",        "Body": "Credentials live inside the Inji Web SPA."},
          {"Kind": "wallet",     "Key": "opens_tab",      "Title": "Opens in a new tab",            "Body": "Selecting this DPG hands off to the Inji Web app."},
          {"Kind": "limitation", "Key": "no_readback",    "Title": "No third-party read-back API",  "Body": "No way for an external service to list credentials at v0.16.0."}
        ]
      },
      "config": {
        "uiUrl": "${injiweb_url}",
        "mimotoUrl": "${mimoto_url}"
      }
    }
JSON
)

  # CREDEBL stanza — rendered for external (CREDEBL_API_URL set) or compose-managed
  # (scenario includes credebl-* services).
  local credebl_stanza=""
  local _credebl_url=""
  local _credebl_email="" _credebl_password="" _credebl_crypto_key=""
  local _credebl_org_id="" _credebl_issuer_id="" _credebl_verifier_id=""
  local _credebl_internal_base_url=""
  if [[ -n "$CREDEBL_API_URL" ]]; then
    # External CREDEBL
    _credebl_url="$CREDEBL_API_URL"
    _credebl_email="$CREDEBL_EMAIL"
    _credebl_password="$CREDEBL_PASSWORD"
    _credebl_crypto_key="$CREDEBL_CRYPTO_PRIVATE_KEY"
    _credebl_org_id="$CREDEBL_ORG_ID"
    _credebl_issuer_id="$CREDEBL_ISSUER_ID"
    _credebl_verifier_id="$CREDEBL_VERIFIER_ID"
    _credebl_internal_base_url="$CREDEBL_INTERNAL_BASE_URL"
  elif [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
    # Compose-managed CREDEBL
    _credebl_url=$(url_for credebl "$VERIFIABLY_PUBLIC_HOST" "$CREDEBL_API_PORT")
    _credebl_email="${CREDEBL_ADMIN_EMAIL}"
    _credebl_password="changeme"
    _credebl_crypto_key="${CREDEBL_CRYPTO_PRIVATE_KEY}"
    _credebl_org_id=""
    _credebl_issuer_id=""
    _credebl_verifier_id=""
    _credebl_internal_base_url="http://credebl-api-gateway:5000"
  fi
  if [[ -n "$_credebl_url" ]]; then
    credebl_stanza=$(cat <<JSON
    {
      "vendor": "CREDEBL",
      "type": "credebl",
      "roles": ["issuer", "verifier"],
      "dpg": {
        "Vendor": "CREDEBL",
        "Version": "v2.x",
        "Tag": "API-based",
        "Tagline": "Enterprise-grade, multi-tenant VC platform — SD-JWT VC issuance and OID4VP verification.",
        "FlowPreAuth": true,
        "FlowPlain": "OID4VCI with pre-authorized code flow; OID4VP DCQL for presentation.",
        "Formats": ["sd_jwt_vc (IETF)"],
        "FormatsPlain": "SD-JWT VC (dc+sd-jwt, IETF draft).",
        "DirectPDF": false,
        "DirectPDFPlain": "No PDF export — credentials are delivered to a wallet via OID4VCI.",
        "Caveats": "Holder wallet required for OID4VP; CREDEBL has no built-in wallet component.",
        "Capabilities": [
          {"Kind": "flow",        "Key": "pre_auth",      "Title": "Pre-authorized code flow", "Body": "Issuer stages the offer; wallet redeems at the token endpoint using the PIN."},
          {"Kind": "flow",        "Key": "oid4vp",        "Title": "OID4VP · DCQL",            "Body": "Verifier sends a DCQL query; holder wallet presents a matching SD-JWT VC."},
          {"Kind": "token",       "Key": "issuer_signed", "Title": "Issuer-signed tokens",     "Body": "Tokens signed by the CREDEBL org's DID key."},
          {"Kind": "mode",        "Key": "wallet",        "Title": "Wallet delivery",          "Body": "Offer URI scanned or pasted into any OID4VCI-compatible wallet."},
          {"Kind": "bulk_source", "Key": "csv",           "Title": "Bulk from CSV",            "Body": "Operator uploads a CSV; each row issues one SD-JWT VC credential offer."},
          {"Kind": "limitation",  "Key": "no_holder",     "Title": "No built-in holder wallet", "Body": "CREDEBL is an issuer + verifier platform; use Inji Web or any OID4VCI wallet as the holder."}
        ]
      },
      "config": {
        "baseUrl": "${_credebl_url}",
        "email": "${_credebl_email}",
        "password": "${_credebl_password}",
        "cryptoPrivateKey": "${_credebl_crypto_key}",
        "orgId": "${_credebl_org_id}",
        "issuerId": "${_credebl_issuer_id}",
        "verifierId": "${_credebl_verifier_id}",
        "defaultPin": "${CREDEBL_DEFAULT_PIN}",
        "internalBaseUrl": "${_credebl_internal_base_url}",
        "publicBaseUrl": "${_credebl_url}"
      }
    }
JSON
)
  fi

  # Assemble the backends array based on scenario.
  local entries=()
  case "$scenario" in
    all)
      entries=( "$waltid_stanza" "$inji_authcode_stanza" "$inji_preauth_stanza" "$inji_verify_stanza" "$injiweb_stanza" )
      # Include CREDEBL when configured (external or compose-managed).
      [[ -n "$credebl_stanza" ]] && entries+=( "$credebl_stanza" )
      ;;
    waltid)
      entries=( "$waltid_stanza" );;
    inji)
      entries=( "$inji_authcode_stanza" "$inji_preauth_stanza" "$inji_verify_stanza" "$injiweb_stanza" );;
    credebl)
      [[ -z "$credebl_stanza" ]] && { red "CREDEBL not configured — either set CREDEBL_API_URL or ensure compose-managed CREDEBL secrets are generated"; return 1; }
      entries=( "$credebl_stanza" )
      ;;
    *)
      red "unknown scenario: $scenario"; return 1;;
  esac

  mkdir -p "$(dirname "$out")"
  {
    printf '{\n  "backends": [\n'
    local i
    for i in "${!entries[@]}"; do
      printf '%s' "${entries[$i]}"
      if [[ $i -lt $(( ${#entries[@]} - 1 )) ]]; then
        printf ',\n'
      else
        printf '\n'
      fi
    done
    printf '  ]\n}\n'
  } > "$out"

  green "wrote $out"
}

# auth_providers_for writes the deploy-managed bootstrap providers to
# config/auth-providers.system.json. The Go loader then layers
# config/auth-providers.user.json (admin-UI managed) on top, so reruns
# of `./deploy.sh run all` no longer wipe the operator's additions.
#
# Every scenario advertises BOTH Keycloak and WSO2IS by default. Set
# VERIFIABLY_NO_DEFAULT_IDPS=1 to write an empty list — useful for
# operators who run their own IdP and would rather start with the empty
# first-run UI than dismiss the demo tiles every install.
auth_providers_for() {
  local scenario="$1"  # kept for signature compatibility; unused here
  local out="$SCRIPT_DIR/config/auth-providers.system.json"

  if [[ "${VERIFIABLY_NO_DEFAULT_IDPS:-0}" == "1" ]]; then
    mkdir -p "$(dirname "$out")"
    printf '[]\n' > "$out"
    green "wrote $out (no default IdPs — first-run UI will prompt)"
    # Drop the legacy filename if it exists so the new loader doesn't
    # second-fallback into stale Keycloak/WSO2 entries.
    rm -f "$SCRIPT_DIR/config/auth-providers.json"
    return
  fi
  # Legacy filename preserved as a side-effect copy so a half-upgraded
  # deployment (new deploy.sh, old binary that still reads
  # auth-providers.json) keeps booting until the operator re-pulls.
  local legacy_out="$SCRIPT_DIR/config/auth-providers.json"
  # Resolve IdP URLs through url_for so localhost-port and per-subdomain
  # both work. Keycloak is a vanilla http URL (the demo container runs
  # plain HTTP); WSO2 needs https + insecureSkipVerify because its self-
  # signed cert isn't in any trust store. When VERIFIABLY_HOSTS_PATTERN
  # supplies the scheme (https://), insecureSkipVerify becomes irrelevant
  # — the cert is presumably real.
  local keycloak_issuer wso2_issuer keycloak_client_id keycloak_client_secret_kv
  if [[ -n "$VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL" ]]; then
    # External Keycloak: use the URL + client details the operator
    # provided. No URL synthesis (the realm path is part of the URL the
    # operator pasted).
    keycloak_issuer="$VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL"
    keycloak_client_id="${VERIFIABLY_KEYCLOAK_EXTERNAL_CLIENT_ID:-vcplatform}"
    if [[ -n "$VERIFIABLY_KEYCLOAK_EXTERNAL_CLIENT_SECRET" ]]; then
      keycloak_client_secret_kv=',"clientSecret":"'"$VERIFIABLY_KEYCLOAK_EXTERNAL_CLIENT_SECRET"'"'
    else
      keycloak_client_secret_kv=""
    fi
  else
    keycloak_issuer="$(url_for keycloak "$VERIFIABLY_PUBLIC_HOST" "$KEYCLOAK_PORT")/realms/${KEYCLOAK_REALM}"
    keycloak_client_id="${KEYCLOAK_CLIENT_ID}"
    keycloak_client_secret_kv=""
  fi
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    wso2_issuer="$(url_for wso2 "$VERIFIABLY_PUBLIC_HOST" "$WSO2_PORT")/oauth2/token"
  else
    # Legacy mode: WSO2 is on https with a self-signed cert.
    wso2_issuer="https://${VERIFIABLY_PUBLIC_HOST}:${WSO2_PORT}/oauth2/token"
  fi

  # clientId "vcplatform" matches the public client seeded by the shared
  # compose's keycloak-realm.json (realm: vcplatform, client: vcplatform,
  # redirectUris: http://localhost:8080/*). Keep these two in sync.
  local keycloak='{"id":"keycloak","type":"oidc","displayName":"Keycloak","kind":"OIDC","issuerUrl":"'"${keycloak_issuer}"'","clientId":"'"${keycloak_client_id}"'"'"${keycloak_client_secret_kv}"',"scopes":["openid","profile","email"]}'

  # WSO2IS client_id + client_secret come from config/wso2is.env, written by
  # scripts/bootstrap-wso2is.sh (run automatically by `deploy.sh up` below).
  # Falls back to placeholder values if the bootstrap hasn't run; the provider
  # button will render but attempts to sign in will fail until it has.
  local wso2_id="verifiably_go_client"
  local wso2_secret=""
  if [[ -f "$SCRIPT_DIR/config/wso2is.env" ]]; then
    # shellcheck disable=SC1090
    source "$SCRIPT_DIR/config/wso2is.env"
    wso2_id="${WSO2_CLIENT_ID:-$wso2_id}"
    wso2_secret="${WSO2_CLIENT_SECRET:-}"
  fi
  local wso2is='{"id":"wso2is","type":"oidc","displayName":"WSO2 Identity Server","kind":"OIDC","issuerUrl":"'"${wso2_issuer}"'","clientId":"'"$wso2_id"'","clientSecret":"'"$wso2_secret"'","scopes":["openid","profile","email"],"insecureSkipVerify":true}'
  local items=( "$keycloak" "$wso2is" )
  mkdir -p "$(dirname "$out")"
  {
    printf '['
    local i
    for i in "${!items[@]}"; do
      [[ $i -gt 0 ]] && printf ','
      printf '\n  %s' "${items[$i]}"
    done
    printf '\n]\n'
  } > "$out"
  cp "$out" "$legacy_out"
  green "wrote $out (+ $legacy_out for back-compat)"
}

# ---------------------------------------------------------------- subcommands

cmd_up() {
  local scenario="${1:-}"
  [[ -n "$scenario" ]] || { red "usage: deploy.sh up <all|waltid|inji|credebl>"; exit 2; }
  scenario_services "$scenario" > /dev/null  # validate

  require docker

  bold "▶ Preparing config for scenario=$scenario"
  backends_for "$scenario"
  auth_providers_for "$scenario"

  # If injiweb-esignet or injiweb-mock-identity are in a restart loop, their
  # container writable layers have accumulated state that keeps the entrypoint
  # from completing (see docker-compose.injiweb-fix.yml for detail). Recreate
  # them so they start with a clean layer.
  if [[ "$(scenario_needs_injiweb "$scenario")" == "yes" ]]; then
    recover_injiweb
    # Mimoto's compose mount expects a writable copy of oidckeystore.p12 at
    # deploy/compose/injiweb/config/certs-runtime/. The "certs-runtime" copy
    # is regenerated from the pristine "certs" original so a fresh clone
    # works before fetch-config.sh has ever run. Idempotent: only copies
    # when the target is missing.
    local cert_src="$SCRIPT_DIR/deploy/compose/injiweb/config/certs/oidckeystore.p12"
    local cert_dst="$SCRIPT_DIR/deploy/compose/injiweb/config/certs-runtime/oidckeystore.p12"
    if [[ -f "$cert_src" && ! -f "$cert_dst" ]]; then
      mkdir -p "$(dirname "$cert_dst")"
      cp "$cert_src" "$cert_dst"
      green "  seeded $cert_dst from $cert_src"
    fi
    # Render mimoto-issuers-config.json with the right URLs for the
    # current mode. Without this Mimoto's redirect_uri /
    # authorization_audience point at the legacy host:port form, and
    # subdomain-mode users see "No issuers found" + the eSignet token
    # exchange fails because the audience claim doesn't match what
    # eSignet advertises in its discovery document.
    bold "▶ Rendering mimoto-issuers-config.json"
    ( cd "$SCRIPT_DIR/deploy/compose/injiweb" && \
      VERIFIABLY_HOSTS_PATTERN="$VERIFIABLY_HOSTS_PATTERN" \
      VERIFIABLY_PUBLIC_DOMAIN="$VERIFIABLY_PUBLIC_DOMAIN" \
      ./render-config.sh ) || red "  mimoto config render failed (proceeding)"
  fi

  # Render per-deployment configs the containers will mount. WSO2's
  # deployment.toml is envsubst'd from a template so the `hostname` +
  # proxy settings reflect $VERIFIABLY_PUBLIC_HOST for whatever host
  # the operator is deploying on (localhost / EC2 / their own domain).
  # Without this, WSO2 boots with a stale hardcoded hostname and its
  # OIDC metadata advertises the wrong `iss`.
  render_wso2_deployment_toml

  # Caddyfile.public is generated from the resolved slug overrides so
  # custom subdomain schemes (e.g. VERIFIABLY_SLUG_KEYCLOAK=auth) land
  # in the routing without forking the file. Skipped when the operator
  # isn't using subdomain mode — the static Caddyfile.public stays
  # untouched and unused.
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    render_public_caddyfile
  fi

  # walt.id issuer-api + verifier-api baseUrls — must match the host
  # the wallet sees, otherwise every OID4VP request bakes localhost into
  # client_id / presentation_definition_uri and the wallet 500s.
  render_waltid_service_confs

  # Walt.id custom-credential catalog. Seeded from a committed baseline
  # on first `up`; subsequent `up`s leave it alone so user-added schemas
  # (appended by internal/adapters/waltid/issuer.go via SaveCustomSchema)
  # survive every git pull/checkout. The runtime path is gitignored.
  seed_credential_issuer_catalog

  # WSO2's accountrecoveryendpoint signup-success page is patched at
  # container start with a meta-refresh redirect; the URL it points at
  # is SIGNUP_REDIRECT_URL. Resolved through url_for so subdomain mode
  # ends up at https://vc.<domain>/auth instead of the legacy
  # host:port form. Without this the user signs up via WSO2 then the
  # browser tries to navigate to a port that isn't published externally
  # in subdomain mode.
  local _verifiably_root_url
  _verifiably_root_url=$(url_for verifiably "$VERIFIABLY_PUBLIC_HOST" "$VERIFIABLY_HOST_PORT")
  export SIGNUP_REDIRECT_URL="${_verifiably_root_url}/auth"

  # MIMOTO_URL is read by the Inji Web React SPA via env.config.js at
  # runtime. The SPA POSTs to ${MIMOTO_URL}/issuers etc. — but this
  # routes through the SPA's own host (injiweb-ui's nginx proxies
  # /v1/mimoto/* to mimoto:8099 internally, keeping requests same-origin
  # to avoid CORS). So MIMOTO_URL is the INJI-WEB subdomain, not the
  # mimoto subdomain. In subdomain mode the SPA can also hit
  # mimoto.<domain> directly via Caddy if CORS is set up — but the
  # inji-web-→-internal-mimoto path is what upstream uses and what the
  # nginx config supports out of the box.
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    local _injiweb_root_url
    _injiweb_root_url=$(url_for inji-web "$VERIFIABLY_PUBLIC_HOST" "$INJIWEB_UI_PUBLIC_PORT")
    export MIMOTO_URL="${_injiweb_root_url}/v1/mimoto"
    # ESIGNET_BASE_URL ends up in Inji Certify's well-known credential-
    # issuer document under authorization_servers, AND in eSignet's own
    # MOSIP_ESIGNET_DOMAIN_URL (which it advertises in its /.well-known/
    # openid-configuration). Both paths feed the SPA's /authorize redirect
    # URL — without the override the SPA was sending users to
    # http://<PUBLIC_HOST>:3005/authorize which isn't externally reachable
    # in subdomain mode (only Caddy on 443).
    export ESIGNET_BASE_URL=$(url_for esignet "$VERIFIABLY_PUBLIC_HOST" "$ESIGNET_PUBLIC_PORT")
  fi

  # CREDEBL pre-flight: generate secrets + write agent runtime env BEFORE
  # docker compose up so the generated config/credebl.env file exists when
  # compose reads it for the CREDEBL service definitions.
  if [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
    bold "▶ Preparing CREDEBL environment"
    ensure_credebl_env
    write_credebl_agent_runtime_env
  fi

  bold "▶ Starting DPG services via docker compose"
  local -a services
  readarray -t services < <(scenario_services "$scenario")
  local profile_args=()
  if [[ "$(scenario_needs_injiweb "$scenario")" == "yes" ]]; then
    profile_args+=( --profile injiweb )
  fi
  if [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
    profile_args+=( --profile credebl )
  fi
  # Per-subdomain mode (VERIFIABLY_HOSTS_PATTERN set) brings up the
  # caddy-public service that fronts every container on 80/443. Skipped
  # for localhost / port-per-service deployments — the existing per-port
  # bindings already serve those without TLS.
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    profile_args+=( --profile subdomain )
  fi
  compose "${profile_args[@]}" up -d "${services[@]}"
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    compose "${profile_args[@]}" up -d caddy-public
  fi
  # If the walt.id service confs changed (subdomain ↔ legacy switch, or
  # subdomain swap), the running issuer-api + verifier-api containers
  # are still serving with the old baseUrl baked into ApplicationConfig.
  # Restart them so the new conf is picked up. Idempotent — same baseUrl
  # → same restarted-with-same-state outcome.
  for svc in issuer-api verifier-api; do
    if compose ps --services 2>/dev/null | grep -qx "$svc"; then
      compose restart "$svc" >/dev/null 2>&1 || true
    fi
  done

  bold "▶ Waiting for services to be reachable"
  wait_for_services "$scenario"

  # Every scenario runs both IdPs, so the OIDC client registrations always
  # need to happen. Both bootstraps are idempotent — a second run reuses
  # the existing client and only patches drift (Keycloak: redirect_uris;
  # WSO2: redirect_uris + self-heals if the OAuth app is missing).
  #
  # Why both run on every up: the only env that needs to change between
  # localhost / EC2 / a custom domain is VERIFIABLY_PUBLIC_HOST. The
  # bootstrap scripts then propagate that value into the IdPs' client
  # configs, so a host change followed by `./deploy.sh up all` is enough
  # to make Keycloak + WSO2 accept the new callback URL.
  # Resolve verifiably-go's browser-facing callback URL through url_for so
  # the bootstrap scripts add the right entry in either mode:
  #   legacy mode  → http://<host>:<port>/auth/callback
  #   pattern mode → https://verifiably.<domain>/auth/callback (and the
  #                  legacy entry is also added so browsers hitting the
  #                  old URL via /etc/hosts still work).
  local _verifiably_url _verifiably_callback
  _verifiably_url=$(url_for verifiably "$VERIFIABLY_PUBLIC_HOST" "$VERIFIABLY_HOST_PORT")
  _verifiably_callback="${_verifiably_url}/auth/callback"

  if [[ -n "$VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL" ]]; then
    bold "▶ Skipping Keycloak bootstrap (external issuer: $VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL)"
    echo "    note: this realm's redirect_uri allow-list must already include"
    echo "          ${_verifiably_callback}"
    echo "          — the local bootstrap can't add it (we don't have admin creds)."
  else
    bold "▶ Bootstrapping Keycloak vcplatform client"
    PUBLIC_HOST="$VERIFIABLY_PUBLIC_HOST" \
      VERIFIABLY_HOST_PORT="$VERIFIABLY_HOST_PORT" \
      VERIFIABLY_CALLBACK_URL="$_verifiably_callback" \
      VERIFIABLY_PUBLIC_URL="$_verifiably_url" \
      KEYCLOAK_BASE="http://localhost:${KEYCLOAK_PORT}" \
      KEYCLOAK_REALM="$KEYCLOAK_REALM" \
      KEYCLOAK_CLIENT_ID="$KEYCLOAK_CLIENT_ID" \
      "$SCRIPT_DIR/scripts/bootstrap-keycloak.sh" \
      || red "  Keycloak bootstrap failed (proceeding — you can re-run it manually)"
  fi

  bold "▶ Bootstrapping WSO2IS OIDC client"
  PUBLIC_HOST="$VERIFIABLY_PUBLIC_HOST" \
    VERIFIABLY_HOST_PORT="$VERIFIABLY_HOST_PORT" \
    VERIFIABLY_CALLBACK_URL="$_verifiably_callback" \
    "$SCRIPT_DIR/scripts/bootstrap-wso2is.sh" || red "  WSO2IS bootstrap failed (proceeding — you can re-run it manually)"
  # Re-generate auth-providers.json now that wso2is.env exists, so the
  # provider list picks up the fresh client_secret.
  auth_providers_for "$scenario"

  # Seed the injiweb stack: register the wallet-demo-client keystore with
  # eSignet so private_key_jwt token exchange works, and stuff a test
  # identity into mock-identity so users can actually sign in.
  if [[ "$(scenario_needs_injiweb "$scenario")" == "yes" ]]; then
    bold "▶ Seeding Inji Web auth stack"
    local esignet_seed="$SCRIPT_DIR/deploy/compose/injiweb/seed-esignet-client.sh"
    local mock_seed="$SCRIPT_DIR/deploy/compose/injiweb/seed-mock-identity.sh"
    if [[ -x "$esignet_seed" ]]; then
      (cd "$(dirname "$esignet_seed")" && "$esignet_seed") \
        || red "  seed-esignet-client failed (retry manually: $esignet_seed)"
    else
      red "  $esignet_seed not found — OIDC login through Inji Web will fail"
    fi
    if [[ -x "$mock_seed" ]]; then
      "$mock_seed" || red "  seed-mock-identity failed (retry manually: $mock_seed)"
    else
      red "  $mock_seed not found — Inji Web login has no identities to authenticate"
    fi
    # The seed script returns OK on duplicate_client_id, but a previous deploy
    # could have registered the client with a different redirect_uri (e.g.
    # http://localhost:3004/redirect if UIURL was localhost before). eSignet
    # then rejects /authorize with invalid_redirect_uri. Repair the row in
    # place and flush the Redis client cache so the fix takes effect without
    # requiring a destructive re-seed.
    repair_injiweb_client_redirect_uri
  fi

  # Bootstrap CREDEBL: import Keycloak realm, apply patches, provision shared agent.
  if [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
    bold "▶ Bootstrapping CREDEBL Keycloak realm"
    bootstrap_credebl_keycloak_realm \
      || red "  CREDEBL Keycloak realm import failed (proceeding — re-run bootstrap_credebl_keycloak_realm manually)"

    bold "▶ Applying CREDEBL container patches"
    apply_credebl_patches \
      || red "  CREDEBL patch application failed (proceeding — some features may not work)"

    bold "▶ Provisioning CREDEBL platform-admin shared agent"
    ensure_credebl_platform_admin_shared_agent \
      || red "  CREDEBL shared agent provisioning failed (proceeding — re-run manually)"

    bold "▶ Setting up CREDEBL platform-admin tenant wallet"
    ensure_credebl_platform_admin_tenant \
      || red "  CREDEBL tenant wallet setup failed (proceeding — re-run manually)"
  fi

  bold "▶ Building verifiably-go image ($VERIFIABLY_IMAGE)"
  # --progress=plain streams every step's output to the terminal so the
  # operator can SEE which step is slow or stuck. Previously this was
  # `-q ... >/dev/null`, which silenced everything and made an OOM-killed
  # Go compile look like a 20-minute hang. On low-RAM VPS instances
  # (1-2GB) the Go compiler often OOMs during the build step — if you
  # see the run halt at `RUN go build` and the container appear to hang,
  # add swap before retrying:
  #   fallocate -l 4G /swapfile && chmod 600 /swapfile \
  #     && mkswap /swapfile && swapon /swapfile
  docker build --progress=plain -t "$VERIFIABLY_IMAGE" "$SCRIPT_DIR"

  bold "▶ Starting verifiably-go container"
  start_container "$scenario"
  echo "    point your browser at $VERIFIABLY_PUBLIC_URL"
}

# repair_injiweb_client_redirect_uri ensures the wallet-demo-client row in
# eSignet's postgres has a redirect_uris array containing
# http://${PUBLIC_HOST}:3004/redirect. If it's missing, we rewrite the row and
# flush the Redis client cache (eSignet caches client_detail rows there with
# no invalidation on external DB writes).
#
# Idempotent — safe to run on every deploy. Only touches the wallet-demo-client
# row.
repair_injiweb_client_redirect_uri() {
  local public_host="${PUBLIC_HOST:-172.24.0.1}"
  local want="http://${public_host}:3004/redirect"
  local current
  current=$(docker exec injiweb-postgres \
    psql -U postgres -d mosip_esignet -tAX \
    -c "SELECT redirect_uris FROM client_detail WHERE id='wallet-demo-client'" 2>/dev/null || true)
  if [[ -z "$current" ]]; then
    red "  wallet-demo-client not found in eSignet DB — seed script may have failed"
    return
  fi
  if [[ "$current" == *"$want"* ]]; then
    return   # already has our redirect URI
  fi
  # Add the PUBLIC_HOST URI alongside whatever is already there. Keeping the
  # existing entries means old browser sessions don't break if a user has an
  # in-flight redirect URL in their history.
  local merged
  merged=$(python3 -c "
import json, sys
cur = json.loads('''$current''')
want = '$want'
if want not in cur:
    cur.append(want)
print(json.dumps(cur))
")
  docker exec injiweb-postgres psql -U postgres -d mosip_esignet -qc \
    "UPDATE client_detail SET redirect_uris='$merged' WHERE id='wallet-demo-client'" >/dev/null
  docker exec injiweb-redis redis-cli DEL 'clientdetails::wallet-demo-client' >/dev/null
  green "  repaired wallet-demo-client redirect_uris (+$want)"
}

cmd_down() {
  local scenario="${1:-all}"
  scenario_services "$scenario" > /dev/null  # validate

  bold "▶ Stopping verifiably-go container"
  stop_container

  bold "▶ Stopping compose services for scenario=$scenario"
  local -a services
  readarray -t services < <(scenario_services "$scenario")
  local profile_args=()
  if [[ "$(scenario_needs_injiweb "$scenario")" == "yes" ]]; then
    profile_args+=( --profile injiweb )
  fi
  if [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
    profile_args+=( --profile credebl )
  fi
  compose "${profile_args[@]}" stop "${services[@]}"
}

cmd_reset() {
  bold "▶ Full reset — wipe all waltid_* named volumes + remove containers"
  echo
  echo "  This removes every persistent volume created by the compose stack:"
  echo "    waltid_certify-db + waltid_certify-pkcs12           (Inji Certify auth-code)"
  echo "    waltid_certify-preauth-db + waltid_certify-preauth-pkcs12 (Inji Certify pre-auth)"
  echo "    waltid_inji-verify-db                                (Inji Verify)"
  echo "    waltid_injiweb-db + friends                          (Inji Web / Mimoto / eSignet / mock-identity)"
  echo "    waltid_postgres + waltid_citizens-data               (walt.id + bulk-issuance citizens)"
  echo "    waltid_locales / waltid_lt-data / waltid_caddy-data  (translator + TLS state)"
  echo
  echo "  Use this when a keystore regenerated but its aliases are still"
  echo "  in the DB — symptom: 'KER-KMA-004 -- No such alias: <uuid>' in"
  echo "  inji-certify or inji-certify-preauth-backend logs."
  echo
  read -r -p "  Type 'RESET' to proceed, anything else cancels: " ack
  if [[ "$ack" != "RESET" ]]; then
    red "  aborted"; return 0
  fi
  stop_container
  compose --profile injiweb down -v 2>&1 | tail -10
  # Belt-and-braces: remove any stragglers not claimed by docker compose
  # (different project name / previous owner). Silent on not-found.
  local vols
  vols="$(docker volume ls --format '{{.Name}}' | grep -E '^waltid_' || true)"
  if [[ -n "$vols" ]]; then
    echo "  removing stragglers: $vols"
    # shellcheck disable=SC2086
    docker volume rm $vols 2>&1 | sed 's/^/  /'
  fi
  green "  reset complete. Next up will start clean."
}

cmd_status() {
  bold "▶ Running compose services"
  compose --profile injiweb --profile credebl ps --format '  {{.Service}}  {{.Status}}' 2>/dev/null | sort -u
  echo
  bold "▶ verifiably-go container"
  if docker ps --filter "name=^${VERIFIABLY_CONTAINER}$" --format '  {{.Names}}  {{.Status}}  {{.Ports}}' | grep -q .; then
    docker ps --filter "name=^${VERIFIABLY_CONTAINER}$" --format '  {{.Names}}  {{.Status}}  {{.Ports}}'
  else
    echo "  not running"
  fi
}

cmd_config() {
  local scenario="${1:-}"
  [[ -n "$scenario" ]] || { red "usage: deploy.sh config <all|waltid|inji|credebl>"; exit 2; }
  backends_for "$scenario"
  echo "---"
  cat "$SCRIPT_DIR/config/backends.json"
}

cmd_run() {
  local scenario="${1:-}"
  [[ -n "$scenario" ]] || { red "usage: deploy.sh run <all|waltid|inji|credebl>"; exit 2; }
  require docker
  backends_for "$scenario"
  auth_providers_for "$scenario"
  bold "▶ Building verifiably-go image ($VERIFIABLY_IMAGE)"
  # --progress=plain streams every step's output to the terminal so the
  # operator can SEE which step is slow or stuck. Previously this was
  # `-q ... >/dev/null`, which silenced everything and made an OOM-killed
  # Go compile look like a 20-minute hang. On low-RAM VPS instances
  # (1-2GB) the Go compiler often OOMs during the build step — if you
  # see the run halt at `RUN go build` and the container appear to hang,
  # add swap before retrying:
  #   fallocate -l 4G /swapfile && chmod 600 /swapfile \
  #     && mkswap /swapfile && swapon /swapfile
  docker build --progress=plain -t "$VERIFIABLY_IMAGE" "$SCRIPT_DIR"
  start_container "$scenario"
  echo "    point your browser at $VERIFIABLY_PUBLIC_URL"
}

# ---------------------------------------------------------------- helpers

# wait_for_services polls the TCP ports each scenario needs to be healthy
# before verifiably-go starts. Bounded — we don't block forever if a service
# is struggling; the app itself surfaces the failure on first use.
wait_for_services() {
  local scenario="$1"
  # Both IdPs (Keycloak 8180, WSO2IS 9443) + the translator (5000) are
  # always in scope because every scenario includes them. DPG-specific
  # ports gate on scenario.
  local -a ports=( 8180 9443 5000 )
  case "$scenario" in
    all|waltid)    ports+=( 7001 7002 7003 );;
  esac
  case "$scenario" in
    all|inji)      ports+=( 8082 8091 8094 );;
  esac
  case "$scenario" in
    all|credebl)
      if [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
        ports+=( "$CREDEBL_API_PORT" )
      fi
      ;;
  esac
  # De-dup; bash-ish.
  local seen="" p
  for p in "${ports[@]}"; do
    [[ ",$seen," == *",$p,"* ]] || { wait_port "$p"; seen="$seen,$p"; }
  done
}

# recover_injiweb force-recreates the three injiweb services that tend to
# get stuck in restart loops, so the next `docker compose up` gives them
# clean container state. Mimoto then picks up the patched bootstrap from the
# override compose; eSignet + mock-identity re-run their entrypoints with
# empty writable layers and the HSM unzip succeeds.
recover_injiweb() {
  local -a stuck=()
  for svc in injiweb-mimoto injiweb-esignet injiweb-mock-identity; do
    local state
    state=$(docker inspect "$svc" --format '{{.State.Status}}' 2>/dev/null || echo missing)
    if [[ "$state" == "restarting" ]]; then
      stuck+=( "$svc" )
    fi
  done
  if [[ ${#stuck[@]} -eq 0 ]]; then
    return 0
  fi
  bold "▶ Recovering injiweb services stuck in restart loop: ${stuck[*]}"
  for svc in "${stuck[@]}"; do
    docker rm -f "$svc" >/dev/null 2>&1 || true
    green "  removed $svc (container layer reset)"
  done
}

wait_port() {
  local port="$1"
  local tries=0
  while ! (exec 3<>/dev/tcp/localhost/"$port") 2>/dev/null; do
    tries=$((tries + 1))
    if [[ $tries -gt 60 ]]; then
      red "  port $port not reachable after 60s — continuing anyway"
      return 0
    fi
    sleep 1
  done
  exec 3<&-
  green "  port $port ready"
}

start_container() {
  local scenario="$1"
  stop_container

  # Regenerate backends.json in docker-internal form. The host-native version
  # (localhost:7002, etc.) is still in config/ but the container mounts an
  # override at /app/config/backends.json so it reaches DPGs via Docker DNS.
  backends_for_docker "$scenario"

  # --add-host=host.docker.internal:host-gateway makes the Docker host
  # reachable from inside this container as `host.docker.internal`. The OIDC
  # provider URLs stay on their browser-facing form (localhost:8180, etc.)
  # so the HX-Redirect we send to the browser is something the browser can
  # actually resolve. Container-side discovery + token exchange travel via
  # docker-internal DNS (wallet-api, issuer-api, ...) where the hostname
  # differs from the browser-facing one.
  # The walt.id catalog mount + docker socket below are what let the
  # SaveCustomSchema hook in internal/adapters/waltid append to
  # credential-issuer-metadata.conf and restart issuer-api when an operator
  # builds a new schema. The catalog mount is rw (it's an edit), the docker
  # socket gates restartContainer's Engine API call. Both are skipped on
  # scenarios that don't bring up walt.id — but it's cheaper to always bind
  # them in than to branch (the host paths exist regardless).
  #
  # Permission gymnastics: verifiably-go runs as the distroless `nonroot`
  # user (UID 65532), but the host bind mount is owned by whoever ran
  # `git clone` (typically UID 1000). The container can read but not
  # write the catalog file, so /issuer/schema/build's HOCON append
  # fails with EACCES. Two practical options:
  #   - chmod the dir + files world-rw (simple, what we do here)
  #   - chown to 65532 (cleaner but needs sudo)
  # Chosen: chmod. This is a dev/demo tool and the host dir already lives
  # under the user's home; world-write doesn't expose anything new. Also
  # mounts /var/run/docker.sock as group-readable so isContainerRunning
  # / restartContainer work without root inside the container.
  local catalog_dir="$SCRIPT_DIR/deploy/k8s/config/issuer"
  if [[ -d "$catalog_dir" ]]; then
    chmod 0777 "$catalog_dir" 2>/dev/null || true
    chmod 0666 "$catalog_dir"/*.conf 2>/dev/null || true
  fi
  # Resolve the docker group's GID at deploy time so --group-add works on
  # any host (Debian/Ubuntu typically use 999 or 984; macOS Docker Desktop
  # has a different mapping). Without this, restartContainer's POST to
  # /var/run/docker.sock returns 403 because UID 65532 isn't in the docker
  # group inside the container. Empty fallback keeps `docker run` happy on
  # hosts that don't have a docker group (rootless setups).
  local docker_gid
  docker_gid=$(stat -c '%g' /var/run/docker.sock 2>/dev/null || echo "")
  local group_add_args=()
  if [[ -n "$docker_gid" ]]; then
    group_add_args=( --group-add "$docker_gid" )
  fi
  # Touch the user-managed providers file before mount: docker would
  # auto-create a directory in its place if the bind target was missing.
  # The Go side tolerates an empty file (loader treats it as []).
  #
  # IMPORTANT: chmod 0666 so the container-side process (running as a
  # non-root UID that doesn't match the host's $USER) can write back to
  # the file when an operator adds a provider via the UI. Without this
  # step, /auth/custom and /admin/auth-providers/*/delete fail with
  # "permission denied: open /app/config/auth-providers.user.json".
  # World-writable is acceptable here — the file lives under the
  # operator's home dir, contains no secrets the operator doesn't
  # already control, and follows the same pattern used for the walt.id
  # catalog file mount further down.
  local user_providers_path="$SCRIPT_DIR/config/auth-providers.user.json"
  if [[ ! -f "$user_providers_path" ]]; then
    printf '[]\n' > "$user_providers_path"
    green "  created empty $user_providers_path (admin UI will populate)"
  fi
  chmod 0666 "$user_providers_path" 2>/dev/null || true

  # Same treatment for the custom-schemas mirror file (Registry's
  # in-memory customSchemas slice durable across rebuilds). Without
  # this, IssuerDisplayName / OwnerKey / Custom flag would be wiped on
  # every container restart even though walt.id's HOCON catalog
  # itself persists.
  local custom_schemas_path="$SCRIPT_DIR/config/custom-schemas.user.json"
  if [[ ! -f "$custom_schemas_path" ]]; then
    printf '[]\n' > "$custom_schemas_path"
    green "  created empty $custom_schemas_path (registry will mirror customSchemas here)"
  fi
  chmod 0666 "$custom_schemas_path" 2>/dev/null || true
  # Pick the system-providers file we feed the container. Prefer the new
  # Docker-rewritten variant; fall back to the legacy filename if a
  # half-upgraded host hasn't run the rewriter yet.
  local system_providers_mount="$SCRIPT_DIR/config/auth-providers.system.docker.json"
  if [[ ! -f "$system_providers_mount" ]]; then
    system_providers_mount="$SCRIPT_DIR/config/auth-providers.docker.json"
  fi
  docker run -d \
    --name "$VERIFIABLY_CONTAINER" \
    --network "${COMPOSE_PROJECT}_default" \
    --add-host=host.docker.internal:host-gateway \
    "${group_add_args[@]}" \
    -p "${VERIFIABLY_HOST_PORT}:8080" \
    -v "$SCRIPT_DIR/config/backends.docker.json:/app/config/backends.json:ro" \
    -v "$system_providers_mount:/app/config/auth-providers.system.json:ro" \
    -v "$user_providers_path:/app/config/auth-providers.user.json" \
    -v "$custom_schemas_path:/app/config/custom-schemas.user.json" \
    -v "$SCRIPT_DIR/deploy/k8s/config/issuer:/app/issuer-api-config" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${VERIFIABLY_CONTAINER}-locales:/app/locales" \
    -e VERIFIABLY_ADAPTER=registry \
    -e VERIFIABLY_ADDR=:8080 \
    -e VERIFIABLY_PUBLIC_URL="$VERIFIABLY_PUBLIC_URL" \
    -e LIBRETRANSLATE_URL="http://libretranslate:5000" \
    -e INJI_CERTIFY_UPSTREAM_URL="http://inji-certify:8090" \
    -e INJI_PROXY_EXTRA_KIDS="${VERIFIABLY_INJI_EXTRA_KIDS:-}" \
    -e WALTID_CATALOG_PATH=/app/issuer-api-config/credential-issuer-metadata.conf \
    -e WALTID_ISSUER_SERVICE=issuer-api \
    -e VERIFIABLY_AUTH_ADMIN="${VERIFIABLY_AUTH_ADMIN:-rw}" \
    -e VERIFIABLY_ADMIN_USER="${VERIFIABLY_ADMIN_USER:-}" \
    -e VERIFIABLY_ADMIN_PASSWORD="${VERIFIABLY_ADMIN_PASSWORD:-}" \
    "$VERIFIABLY_IMAGE" >/dev/null

  sleep 1
  if docker ps --filter "name=^${VERIFIABLY_CONTAINER}$" --filter "status=running" -q | grep -q .; then
    green "  container $VERIFIABLY_CONTAINER running ($scenario)"
  else
    red "  container failed to start — last logs:"
    docker logs "$VERIFIABLY_CONTAINER" 2>&1 | tail -n 25 >&2 || true
    exit 1
  fi
}

stop_container() {
  if docker ps -a --filter "name=^${VERIFIABLY_CONTAINER}$" -q | grep -q .; then
    docker rm -f "$VERIFIABLY_CONTAINER" >/dev/null 2>&1 || true
  fi
}

# =============================================================================
# CREDEBL helpers
# =============================================================================

# ensure_credebl_env auto-generates secrets for any empty CREDEBL_* vars and
# writes deploy/compose/credebl/config/credebl.env with all the variables
# that CREDEBL services need. Called before docker compose up.
ensure_credebl_env() {
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

  local env_dir="$SCRIPT_DIR/deploy/compose/credebl/config"
  mkdir -p "$env_dir"
  local env_file="$env_dir/credebl.env"

  # KEYCLOAK_ADMIN_PASSWORD comes from the shared compose Keycloak
  local _kc_admin_pass="${KEYCLOAK_ADMIN_PASSWORD:-keycloak}"

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
KEYCLOAK_DOMAIN=http://keycloak:8180/
KEYCLOAK_ADMIN_URL=http://keycloak:8180
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
API_ENDPOINT=${VERIFIABLY_PUBLIC_HOST}:${CREDEBL_API_PORT}
VPS_IP=${VERIFIABLY_PUBLIC_HOST}
PLATFORM_WEB_URL=http://${VERIFIABLY_PUBLIC_HOST}:${CREDEBL_API_PORT}
FRONT_END_URL=http://${VERIFIABLY_PUBLIC_HOST}:${CREDEBL_API_PORT}
STUDIO_URL=http://${VERIFIABLY_PUBLIC_HOST}:3010
SOCKET_HOST=http://credebl-api-gateway:5000
ENABLE_CORS_IP_LIST=http://${VERIFIABLY_PUBLIC_HOST}:${CREDEBL_API_PORT},http://localhost:${CREDEBL_API_PORT}
SHORTENED_URL_DOMAIN=
DEEPLINK_DOMAIN=http://${VERIFIABLY_PUBLIC_HOST}:9002/credebl-bucket
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
  cat > "$base/agent.env" <<EOF
LEDGER_URL=http://test.bcovrin.vonx.io
GENESIS_URL=http://test.bcovrin.vonx.io/genesis
TAILS_FILE_SERVER=https://tails.vonx.io
AGENT_HTTP_URL=http://${VERIFIABLY_PUBLIC_HOST}
AGENT_WS_URL=ws://${VERIFIABLY_PUBLIC_HOST}
CONNECT_TIMEOUT=10
MAX_CONNECTIONS=1000
IDLE_TIMEOUT=30000
SESSION_ACQUIRE_TIMEOUT=2147483647
SESSION_LIMIT=2147483647
INMEMORY_LRU_CACHE_LIMIT=2147483647
TRUST_SERVICE_AUTH_TYPE=NoAuth
TRUST_LIST_URL=https://example.com/trust-list.json
EOF
  # Set CREDEBL_COMPOSE_DIR for use in compose volume bind mounts
  export CREDEBL_COMPOSE_DIR="$SCRIPT_DIR/deploy/compose/credebl"
  green "  wrote $base/agent.env (CREDEBL_COMPOSE_DIR=$CREDEBL_COMPOSE_DIR)"
}

# bootstrap_credebl_keycloak_realm imports the credebl-realm into the shared
# Keycloak. Idempotent — skips import when the realm already exists.
bootstrap_credebl_keycloak_realm() {
  local kc_base="http://localhost:${KEYCLOAK_PORT}"
  local realm_file="$SCRIPT_DIR/deploy/compose/credebl/config/keycloak-realm.json"
  local _kc_admin_pass="${KEYCLOAK_ADMIN_PASSWORD:-keycloak}"

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

  # Get admin token
  local token
  token=$(curl -sf --max-time 15 -X POST \
    "$kc_base/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli&username=admin&password=${_kc_admin_pass}&grant_type=password" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' 2>/dev/null) || true
  if [[ -z "$token" ]]; then
    red "  Could not get Keycloak admin token — skipping CREDEBL realm import"
    return 1
  fi

  # Check if realm already exists
  local realm_exists
  realm_exists=$(curl -sf --max-time 10 \
    "$kc_base/admin/realms/credebl-realm" \
    -H "Authorization: Bearer ${token}" \
    | python3 -c 'import json,sys; print("yes")' 2>/dev/null) || realm_exists=""

  if [[ "$realm_exists" == "yes" ]]; then
    green "  credebl-realm already exists in Keycloak — skipping import"
  else
    green "  Importing credebl-realm into Keycloak"
    # Patch redirectUris with the CREDEBL_API_PORT before importing
    local patched_realm
    patched_realm=$(python3 - "$realm_file" "${VERIFIABLY_PUBLIC_HOST}" "${CREDEBL_API_PORT}" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    realm = json.load(f)
host = sys.argv[2]
port = sys.argv[3]
studio_url = f"http://{host}:{port}"
for client in realm.get("clients", []):
    if client.get("clientId") in ("credebl-client", "adminClient"):
        client["redirectUris"] = [f"{studio_url}/*", "http://localhost/*"]
        client["webOrigins"] = [studio_url, "http://localhost"]
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

  # Ensure openid scope with sub claim is present (required for keycloakUserId lookup)
  local scope_id
  scope_id=$(curl -sf --max-time 10 \
    "$kc_base/admin/realms/credebl-realm/client-scopes" \
    -H "Authorization: Bearer ${token}" \
    | python3 -c 'import json,sys; s=[x["id"] for x in json.load(sys.stdin) if x["name"]=="openid"]; print(s[0] if s else "")' 2>/dev/null) || true

  if [[ -z "$scope_id" ]]; then
    curl -sf --max-time 15 -X POST \
      "$kc_base/admin/realms/credebl-realm/client-scopes" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "openid",
        "description": "OpenID Connect built-in scope",
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "true"},
        "protocolMappers": [{
          "name": "sub",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-sub-mapper",
          "consentRequired": false,
          "config": {"access.token.sub.claim": "true", "id.token.sub.claim": "true"}
        }]
      }' >/dev/null || true
    scope_id=$(curl -sf --max-time 10 \
      "$kc_base/admin/realms/credebl-realm/client-scopes" \
      -H "Authorization: Bearer ${token}" \
      | python3 -c 'import json,sys; s=[x["id"] for x in json.load(sys.stdin) if x["name"]=="openid"]; print(s[0] if s else "")' 2>/dev/null) || true
    [[ -n "$scope_id" ]] && green "  openid scope created (id: $scope_id)"
  fi

  if [[ -n "$scope_id" ]]; then
    for client_name in credebl-client adminClient; do
      local client_id
      client_id=$(curl -sf --max-time 10 \
        "$kc_base/admin/realms/credebl-realm/clients?clientId=${client_name}" \
        -H "Authorization: Bearer ${token}" \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")' 2>/dev/null) || true
      if [[ -n "$client_id" ]]; then
        curl -sf --max-time 10 -X PUT \
          "$kc_base/admin/realms/credebl-realm/clients/${client_id}/default-client-scopes/${scope_id}" \
          -H "Authorization: Bearer ${token}" >/dev/null || true
      fi
    done
    green "  openid scope linked to credebl-client and adminClient"
  fi
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
  docker exec --user root credebl-utility node /tmp/patch_utility.js
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
  docker exec --user root credebl-api-gateway node /tmp/patch_api_gw.js
}

_credebl_patch_credo_credential_events() {
  local credo_container
  credo_container="$(docker ps --format '{{.Names}}' | grep -v '^credebl-' | grep -v '^[0-9a-f]\{12\}_credebl' | head -1)"
  if [[ -z "$credo_container" ]]; then
    echo "  No Credo controller container found — skipping."
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
  result="$(docker exec --user root "$credo_container" node /tmp/patch_credo.js)"
  printf '%s\n' "$result"
  if [[ "$result" == "patched" ]]; then
    docker restart "$credo_container" >/dev/null
  fi
}

_credebl_patch_credo_proof_events() {
  local credo_container
  credo_container="$(docker ps --format '{{.Names}}' | grep -v '^credebl-' | grep -v '^[0-9a-f]\{12\}_credebl' | head -1)"
  if [[ -z "$credo_container" ]]; then
    echo "  No Credo controller container found — skipping."
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
  result="$(docker exec --user root "$credo_container" node /tmp/patch_proof.js)"
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
  docker exec --user root credebl-issuance node /tmp/patch_issuance.js
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
  docker exec --user root credebl-issuance node /tmp/patch_issuance_ctx.js
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
  docker exec --user root credebl-issuance node /tmp/patch_issuance_oob.js
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
  docker exec --user root credebl-issuance node /tmp/patch_issuance_qr.js
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
  docker exec --user root credebl-issuance node /tmp/patch_issuance_qrl.js
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
  docker exec --user root credebl-verification node /tmp/patch_verif_qr.js
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
  docker exec --user root credebl-agent-service node /tmp/patch_agent_ct.js
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
  docker exec --user root credebl-agent-service node /tmp/patch_agent_nu.js
}

# apply_credebl_patches applies all 12 container patches in the correct order.
apply_credebl_patches() {
  echo "  Applying CREDEBL container patches..."

  echo -n "  [1/12] Utility service S3→MinIO endpoint: "
  _credebl_patch_utility_s3
  docker restart credebl-utility >/dev/null

  echo -n "  [2/12] API gateway @context validator: "
  _credebl_patch_api_gateway_context_validator
  docker restart credebl-api-gateway >/dev/null

  echo -n "  [3/12] Issuance schema URL dedup: "
  _credebl_patch_issuance_schema_url
  echo -n "  [4/12] Issuance @context URL normalization: "
  _credebl_patch_issuance_context_urls
  echo -n "  [5/12] Issuance OOB credential DB save (upsert): "
  _credebl_patch_issuance_oob_credential_save
  echo -n "  [6/12] Issuance QR code attachment encoding: "
  _credebl_patch_issuance_qr_encoding
  echo -n "  [7/12] Issuance QR uses full deeplink URL: "
  _credebl_patch_issuance_qr_deeplink
  docker restart credebl-issuance >/dev/null

  echo -n "  [8/12] Verification QR code attachment encoding: "
  _credebl_patch_verification_qr_encoding
  docker restart credebl-verification >/dev/null

  echo -n "  [9/12] Agent-service shared wallet create-tenant (root JWT): "
  _credebl_patch_agent_service_create_tenant
  echo -n "  [10/12] Agent-service normalizeUrlWithProtocol (http for Credo): "
  _credebl_patch_agent_service_normalize_url
  docker restart credebl-agent-service >/dev/null

  # Credo patches — only if Credo is running
  echo -n "  [11/12] Credo CredentialEvents guard: "
  _credebl_patch_credo_credential_events
  echo -n "  [12/12] Credo ProofEvents guard: "
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

  # Get root JWT (retry up to 8 times — Credo may still be starting)
  local root_jwt attempt=1
  while [[ $attempt -le 8 ]]; do
    root_jwt="$(curl -sf --max-time 10 -X POST \
      -H "Authorization: $_agent_key" \
      "${endpoint}/agent/token" 2>/dev/null \
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
      "${endpoint}/multi-tenancy/create-tenant" 2>/dev/null || true)"
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
    "${endpoint}/multi-tenancy/get-token/${tenant_id}" 2>/dev/null \
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

  # Restart agent-service so it picks up the new apiKey
  docker restart credebl-agent-service >/dev/null
  sleep 20
  green "  Agent-service restarted."
}

# render_wso2_deployment_toml envsubsts wso2-deployment.toml.template
# with the current VERIFIABLY_PUBLIC_HOST and writes the result to
# wso2-deployment.toml, which the compose file mounts read-only into
# the wso2is container. Keeps the committed template portable while the
# rendered file (gitignored) always matches the operator's .env.
# render_waltid_service_confs writes the issuer-api + verifier-api
# baseUrl conf files at deploy time. The committed templates use the
# Phase-1.2 HOCON env-substitution form `${SERVICE_HOST}:${ISSUER_API_PORT}`
# (resp. VERIFIER_API_PORT) so the same files back both compose and
# the Helm chart's ConfigMap. walt.id resolves those at startup against
# whatever the env (compose or k8s Deployment) supplies for SERVICE_HOST
# and *_API_PORT.
#
# In subdomain mode that committed form is wrong: walt.id bakes the
# resolved baseUrl into every OID4VP request URL (verifier client_id,
# presentation_definition_uri, response_uri) and every credential offer
# URI (issuer offer URI). With SERVICE_HOST=localhost, the wallet-api
# container receives e.g. client_id=http://localhost:7003/openid4vc/verify
# and "localhost:7003" from inside its own network namespace is the
# wallet, not the verifier. Result: every verification + every wallet-
# claim path 500s with "Could not find request parameters or object in
# given parameters" or similar.
#
# So in subdomain mode we overwrite the committed file with the public
# subdomain URL (resolved through url_for + Caddy + DNS). In legacy mode
# we leave the committed `${VAR}` form untouched — walt.id's HOCON
# substitution against compose's env (SERVICE_HOST=localhost,
# *_API_PORT) produces the same `http://localhost:<port>` literal that
# the previous override wrote, and the wallet-api container reaches
# host:port via the docker-compose extra_hosts: "localhost:host-gateway"
# entry. Skipping the write in legacy mode keeps the committed file
# pristine across `up` runs (no working-tree noise).
#
# Restarts both services after rewriting because they only read these
# files at boot.
render_waltid_service_confs() {
  if [[ -z "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    return 0
  fi
  local issuer_conf="$SCRIPT_DIR/deploy/k8s/config/issuer/issuer-service.conf"
  local verifier_conf="$SCRIPT_DIR/deploy/k8s/config/verifier/verifier-service.conf"
  local issuer_url verifier_url
  issuer_url=$(url_for walt-issuer "$VERIFIABLY_PUBLIC_HOST" "$WALTID_ISSUER_PORT")
  verifier_url=$(url_for walt-verifier "$VERIFIABLY_PUBLIC_HOST" "$WALTID_VERIFIER_PORT")
  printf 'baseUrl = "%s"\n' "$issuer_url"   > "$issuer_conf"
  printf 'baseUrl = "%s"\n' "$verifier_url" > "$verifier_conf"
  green "  rendered walt.id service confs (issuer=$issuer_url, verifier=$verifier_url)"
}

# seed_credential_issuer_catalog seeds the runtime credential-issuer-metadata.conf
# from the committed *.baseline.conf when the runtime file doesn't yet exist.
# Idempotent — `cp -n` (no-clobber) means a second run is a no-op even if the
# operator has hand-edited the runtime file or added schemas through the UI.
#
# Why this lives in a runtime path while the seed lives in the repo: walt.id's
# issuer-api appends new credential-config blocks to this file when an operator
# saves a custom schema (internal/adapters/waltid/issuer.go: SaveCustomSchema).
# The seed (*.baseline.conf) is tracked in git so a fresh clone has a working
# catalog; the runtime file is gitignored so user-added schemas survive every
# `git pull`, `git checkout`, and `git stash pop` that would otherwise revert
# the file to its committed shape.
#
# To accept upstream baseline updates after the seed has been customised, the
# operator merges the new entries from *.baseline.conf into the runtime file
# by hand. Diffs between them are intentional state.
seed_credential_issuer_catalog() {
  local baseline="$SCRIPT_DIR/deploy/k8s/config/issuer/credential-issuer-metadata.baseline.conf"
  local runtime="$SCRIPT_DIR/deploy/k8s/config/issuer/credential-issuer-metadata.conf"
  if [[ ! -f "$baseline" ]]; then
    red "  WARN: $baseline missing — issuer catalog seed skipped"
    return 0
  fi
  if [[ -f "$runtime" ]]; then
    return 0
  fi
  cp "$baseline" "$runtime"
  green "  seeded $runtime from baseline"
}

render_wso2_deployment_toml() {
  local tpl="$SCRIPT_DIR/deploy/compose/stack/wso2-deployment.toml.template"
  local out="$SCRIPT_DIR/deploy/compose/stack/wso2-deployment.toml"
  if [[ ! -f "$tpl" ]]; then
    red "  WARN: $tpl missing — WSO2 will boot with whatever hostname is in the compose-mounted toml"
    return 0
  fi
  # In subdomain mode, WSO2's external hostname is its subdomain and the
  # proxyPort is 443 (Caddy's external HTTPS). Without these, WSO2's OIDC
  # discovery advertises authenticationendpoint URLs as
  # https://<VERIFIABLY_PUBLIC_HOST>:9443/... which the browser can't reach.
  local hostname proxy_port
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" && -n "$VERIFIABLY_PUBLIC_DOMAIN" ]]; then
    local wso2_slug
    wso2_slug=$(resolve_slug wso2)
    if [[ -n "$wso2_slug" ]]; then
      hostname="${wso2_slug}.${VERIFIABLY_PUBLIC_DOMAIN}"
      proxy_port=443
    else
      hostname="$VERIFIABLY_PUBLIC_HOST"
      proxy_port=""
    fi
  else
    hostname="$VERIFIABLY_PUBLIC_HOST"
    proxy_port=""
  fi
  # WSO2_CALLBACK_REGEX gates self-registration + account-recovery callback
  # validation. Default whitelist: localhost (laptop dev), the legacy
  # public host (port-per-service mode), and — when in subdomain mode —
  # the verifiably subdomain too. Each literal is regex-escaped so '.'
  # in hostnames doesn't become a wildcard. Anchored loosely (".*" tail)
  # so callbacks with query parameters or trailing paths still match.
  local callback_regex
  callback_regex=$(_wso2_callback_regex)
  # Two-pass render: envsubst fills in hostname + proxy_port + callback_regex
  # placeholders; awk strips the COND_PROXYPORT_* block when proxy_port is
  # empty so the rendered file is valid TOML in either mode.
  WSO2_HOSTNAME="$hostname" WSO2_PROXY_PORT="$proxy_port" \
    WSO2_CALLBACK_REGEX="$callback_regex" \
    envsubst '$WSO2_HOSTNAME $WSO2_PROXY_PORT $WSO2_CALLBACK_REGEX' < "$tpl" |
  awk -v keep="${proxy_port:+1}" '
    /COND_PROXYPORT_OPEN/  { skip = !keep; next }
    /COND_PROXYPORT_CLOSE/ { skip = 0;     next }
    !skip { print }
  ' > "$out"
  green "  rendered wso2-deployment.toml (hostname=$hostname${proxy_port:+ proxyPort=$proxy_port})"
}

# _wso2_callback_regex emits the regex that wso2-deployment.toml's
# self-registration / recovery callback validators use. Always allows
# localhost + the legacy VERIFIABLY_PUBLIC_HOST; adds the verifiably
# subdomain when in subdomain mode. Each literal is regex-escaped so
# dots in hostnames stay literal. Format mirrors WSO2's expectations:
# a single regex string, no anchors needed (WSO2 wraps it in a full
# match itself).
_wso2_callback_regex() {
  local -a hosts=("localhost" "$VERIFIABLY_PUBLIC_HOST")
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" && -n "$VERIFIABLY_PUBLIC_DOMAIN" ]]; then
    # verifiably.<domain> — the OAuth client redirect_uri (where WSO2
    # ultimately sends users after the OIDC dance).
    local v_slug
    v_slug=$(resolve_slug verifiably)
    if [[ -n "$v_slug" ]]; then
      hosts+=("${v_slug}.${VERIFIABLY_PUBLIC_DOMAIN}")
    fi
    # wso2.<domain> — WSO2's INTERNAL callback chain. During self-
    # registration the `callback` param points at WSO2's own
    # authenticationendpoint/login.do (so signup → back-to-login →
    # complete OAuth). Without whitelisting WSO2's external hostname
    # the validator rejects, even though the redirect doesn't leave
    # WSO2. Verified via http_access log:
    #   POST /accountrecoveryendpoint/processregistration.do
    #   referer: ?callback=https://wso2.bootcamp.cdpi.dev/authenticationendpoint/login.do?...
    local w_slug
    w_slug=$(resolve_slug wso2)
    if [[ -n "$w_slug" ]]; then
      hosts+=("${w_slug}.${VERIFIABLY_PUBLIC_DOMAIN}")
    fi
  fi
  local escaped joined=""
  for h in "${hosts[@]}"; do
    [[ -z "$h" ]] && continue
    # Escape regex specials in the host literal. We escape: . \ ^ $ + ? ( ) [ ] { } | * /
    escaped=$(printf '%s' "$h" | sed -e 's/[][\\.*^$+?(){}|/]/\\&/g')
    [[ -n "$joined" ]] && joined+="|"
    joined+="$escaped"
  done
  # Allow http or https + any port + any path/query suffix.
  printf 'https?://(%s)(:[0-9]+)?/.*' "$joined"
}

# render_public_caddyfile generates Caddyfile.public from the resolved
# slug overrides + the static (service → upstream) map below. Operators
# customise their subdomain scheme by setting VERIFIABLY_SLUG_<NAME>
# vars; an empty override skips the service entirely (no Caddy block →
# not exposed at any subdomain).
#
# The map is the single source of truth for "which container + port
# does each service slug point at". Keep it in sync with the compose
# file's container names and the internal listener ports.
render_public_caddyfile() {
  local out="$SCRIPT_DIR/deploy/compose/stack/Caddyfile.public"
  : "${VERIFIABLY_PUBLIC_DOMAIN:=}"
  : "${VERIFIABLY_LE_EMAIL:=}"

  # service-name | container:port | upstream-scheme (http/https)
  # Special: wso2 needs https-with-skip-verify because the container
  # presents a self-signed cert internally.
  local -a entries=(
    "walt-issuer|issuer-api:7002|http"
    "walt-wallet|wallet-api:7001|http"
    "walt-verifier|verifier-api:7003|http"
    "inji-certify|certify-nginx:80|http"
    "inji-certify-preauth|certify-preauth-nginx:80|http"
    "inji-verify|inji-verify-service:8080|http"
    "inji-verify-ui|inji-verify-ui:8000|http"
    "inji-web|injiweb-ui:3004|http"
    "mimoto|injiweb-mimoto:8099|http"
    "esignet|injiweb-oidc-ui:3000|http"
    "keycloak|keycloak:8180|http"  # auto-skipped when VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL is set, via the empty-slug branch below
    "wso2|wso2is:9443|https-skipverify"
    "verifiably|verifiably-go:8080|http"
  )

  {
    cat <<EOF
# Caddyfile.public — generated by deploy.sh's render_public_caddyfile().
# Do NOT edit this file directly; changes will be overwritten on the next
# ./deploy.sh up. Customise via VERIFIABLY_SLUG_<NAME> env vars in .env
# instead — see docs/deploy.md § Per-subdomain deployment.

{
	email ${VERIFIABLY_LE_EMAIL}
}

EOF
    local entry name upstream proto slug subdomain
    for entry in "${entries[@]}"; do
      IFS='|' read -r name upstream proto <<<"$entry"
      # When using an external Keycloak, don't synthesise a Caddy block
      # for the local keycloak slug — there's no local container to
      # proxy to, and the operator's external Keycloak handles requests
      # at its own host (which they don't run through us).
      if [[ "$name" == "keycloak" && -n "$VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL" ]]; then
        printf '# keycloak skipped — external issuer at %s\n\n' "$VERIFIABLY_KEYCLOAK_EXTERNAL_ISSUER_URL"
        continue
      fi
      slug=$(resolve_slug "$name")
      if [[ -z "$slug" ]]; then
        printf '# %s skipped — VERIFIABLY_SLUG_%s set empty\n\n' \
          "$name" "$(printf '%s' "$name" | tr '[:lower:]-' '[:upper:]_')"
        continue
      fi
      subdomain="${slug}.${VERIFIABLY_PUBLIC_DOMAIN}"
      printf '%s {\n' "$subdomain"
      case "$proto" in
        https-skipverify)
          printf '\treverse_proxy https://%s {\n\t\ttransport http {\n\t\t\ttls_insecure_skip_verify\n\t\t}\n\t}\n' "$upstream"
          ;;
        *)
          printf '\treverse_proxy %s\n' "$upstream"
          ;;
      esac
      printf '}\n\n'
    done
  } > "$out"
  green "  rendered Caddyfile.public (domain=$VERIFIABLY_PUBLIC_DOMAIN)"
}

# backends_for_docker writes a sibling config/backends.docker.json with
# docker-internal hostnames so the containerized verifiably-go can reach
# every DPG on the waltid_default network.
#
# Only rewrites fields the CONTAINER reads for backend-to-backend calls —
# "baseUrl", "issuerBaseUrl", "verifierBaseUrl", "walletBaseUrl",
# "mimotoUrl", "authorizationServer", "offerIssuerUrl", "issuerUrl".
# Browser-facing fields ("UIURL", "publicBaseUrl") are left on their
# localhost URLs so link-outs remain host-reachable.
#
# Uses Python instead of sed because sed can't scope rewrites by JSON key.
backends_for_docker() {
  local src="$SCRIPT_DIR/config/backends.json"
  local dst="$SCRIPT_DIR/config/backends.docker.json"
  # Read the authoritative bootstrap file; prefer the new system filename
  # but fall back to the legacy auth-providers.json if a half-upgraded
  # deployment hasn't re-run auth_providers_for yet.
  local auth_src="$SCRIPT_DIR/config/auth-providers.system.json"
  if [[ ! -f "$auth_src" ]]; then
    auth_src="$SCRIPT_DIR/config/auth-providers.json"
  fi
  local auth_dst="$SCRIPT_DIR/config/auth-providers.system.docker.json"

  PUBLIC_HOST_FOR_REWRITE="${VERIFIABLY_PUBLIC_HOST}" \
    KEYCLOAK_PORT_FOR_REWRITE="${KEYCLOAK_PORT}" \
    WSO2_PORT_FOR_REWRITE="${WSO2_PORT}" \
    python3 - "$src" "$dst" "$auth_src" "$auth_dst" <<'PY'
import json, os, sys
src, dst, auth_src, auth_dst = sys.argv[1:5]
public_host = os.environ.get("PUBLIC_HOST_FOR_REWRITE", "localhost")
keycloak_port = os.environ.get("KEYCLOAK_PORT_FOR_REWRITE", "8180")
wso2_port = os.environ.get("WSO2_PORT_FOR_REWRITE", "9443")

# Fields in backends.json that hold a URL the CONTAINER needs to reach.
# UIURL and publicBaseUrl are intentionally excluded — they are shown to
# the browser, not used by the server, and must stay host-reachable.
internal_fields = {
    "baseUrl", "issuerBaseUrl", "verifierBaseUrl", "walletBaseUrl",
    "mimotoUrl", "authorizationServer", "offerIssuerUrl",
    "internalBaseUrl",  # the adapter writes this as the "from" half of the
                        # URL rewrite; it stays on the docker-internal host.
}

# port → docker-internal hostname:container-port. Matched against any host
# prefix (localhost, 172.24.0.1, EC2 hostname) so the rewrite works for
# whatever VERIFIABLY_PUBLIC_HOST the operator picked.
port_to_internal = {
    "7001": "wallet-api:7001",
    "7002": "issuer-api:7002",
    "7003": "verifier-api:7003",
    "8091": "certify-nginx:80",
    "8094": "inji-certify-preauth:8090",
    "8082": "inji-verify-service:8080",
    "3001": "inji-verify-ui:8000",
    "3004": "injiweb-ui:3004",
    "8099": "injiweb-mimoto:8099",
    "3005": "injiweb-oidc-ui:3000",
    "5001": "credebl-api-gateway:5000",
}

import re
URL_RE = re.compile(r"^(https?)://([^:/]+):(\d+)(.*)$")

def rewrite_url(url):
    if not isinstance(url, str):
        return url
    m = URL_RE.match(url)
    if not m:
        return url
    scheme, host, port, rest = m.groups()
    internal = port_to_internal.get(port)
    if not internal:
        return url
    return f"http://{internal}{rest}"

def walk(obj):
    if isinstance(obj, dict):
        for k, v in list(obj.items()):
            if k in internal_fields and isinstance(v, str):
                obj[k] = rewrite_url(v)
            elif isinstance(v, (dict, list)):
                walk(v)
    elif isinstance(obj, list):
        for it in obj:
            walk(it)

with open(src) as f:
    data = json.load(f)
walk(data)
with open(dst, "w") as f:
    json.dump(data, f, indent=2)

# Auth providers: the container-side issuerUrl is the docker-internal
# hostname (used for discovery + token exchange). The original
# browser-facing URL is preserved as publicIssuerUrl so the browser's
# authorize redirect points somewhere it can actually reach.
with open(auth_src) as f:
    auth = json.load(f)
for entry in auth:
    iu = entry.get("issuerUrl", "")
    entry["publicIssuerUrl"] = iu  # what the browser sees
    # Match either localhost or $VERIFIABLY_PUBLIC_HOST on the expected port,
    # swap in the docker-internal DNS name.
    for host in {public_host, "localhost", "172.24.0.1"}:
        iu = iu.replace(f"http://{host}:{keycloak_port}", "http://keycloak:8180")
        iu = iu.replace(f"https://{host}:{wso2_port}", "https://wso2is:9443")
    entry["issuerUrl"] = iu
with open(auth_dst, "w") as f:
    json.dump(auth, f, indent=2)

print(f"  wrote {dst} + {auth_dst} (docker-internal URLs, UIURL preserved)")
PY
}

# ---------------------------------------------------------------- main

usage() {
  cat >&2 <<EOF
usage: deploy.sh <command> [scenario]

commands:
  up <all|waltid|inji|credebl>     start compose services + build & run verifiably-go container
  down [all|waltid|inji|credebl]   stop them (default: all)
  run <all|waltid|inji|credebl>    rebuild + restart only the verifiably-go container
                                   (use when the DPG stack is already up)
  config <all|waltid|inji|credebl> print the backends.json that would be generated
  status                           summarise what's running
  reset                            wipe every waltid_* named volume — fixes keystore/DB
                                   desync ("KER-KMA-004 No such alias: ..."). DESTRUCTIVE;
                                   asks for explicit 'RESET' confirmation.

scenarios:
  all      every DPG + both IdPs + LibreTranslate
           (includes compose-managed CREDEBL when CREDEBL_API_URL is not set
            and CREDEBL_POSTGRES_PASSWORD is set; otherwise includes external
            CREDEBL when CREDEBL_API_URL is set)
  waltid   walt.id stack + Keycloak + LibreTranslate
  inji     Inji Certify (×2) + Inji Verify + Inji Web + WSO2IS + LibreTranslate
  credebl  all CREDEBL services (compose-managed) + Keycloak + WSO2IS + LibreTranslate
           secrets are auto-generated if not set in .env
           to use external CREDEBL instead: set CREDEBL_API_URL, CREDEBL_EMAIL,
           CREDEBL_PASSWORD, CREDEBL_CRYPTO_PRIVATE_KEY, CREDEBL_ORG_ID, CREDEBL_ISSUER_ID
           (but compose-managed CREDEBL is preferred for local dev)

all scenarios include a containerised verifiably-go on port $VERIFIABLY_HOST_PORT,
attached to the compose network (${COMPOSE_PROJECT}_default).
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    up)      shift; cmd_up "$@";;
    down)    shift; cmd_down "$@";;
    reset)   cmd_reset;;
    status)  cmd_status;;
    config)  shift; cmd_config "$@";;
    run)     shift; cmd_run "$@";;
    help|-h|--help|"") usage;;
    *)       red "unknown command: $cmd"; usage; exit 2;;
  esac
}

main "$@"
