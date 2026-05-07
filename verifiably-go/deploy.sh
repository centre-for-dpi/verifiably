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
    *)
      red "unknown scenario: $scenario (want: all | waltid | inji)"; return 1;;
  esac
}

# scenario_needs_injiweb prints "yes" if the scenario includes any injiweb-*
# service — that decides whether we need to pass `--profile injiweb` to
# docker compose.
scenario_needs_injiweb() {
  scenario_services "$1" | grep -q '^injiweb-' && echo yes || echo no
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

  # Assemble the backends array based on scenario.
  local entries=()
  case "$scenario" in
    all)
      entries=( "$waltid_stanza" "$inji_authcode_stanza" "$inji_preauth_stanza" "$inji_verify_stanza" "$injiweb_stanza" );;
    waltid)
      entries=( "$waltid_stanza" );;
    inji)
      entries=( "$inji_authcode_stanza" "$inji_preauth_stanza" "$inji_verify_stanza" "$injiweb_stanza" );;
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
  [[ -n "$scenario" ]] || { red "usage: deploy.sh up <all|waltid|inji>"; exit 2; }
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

  bold "▶ Starting DPG services via docker compose"
  local -a services
  readarray -t services < <(scenario_services "$scenario")
  local profile_args=()
  if [[ "$(scenario_needs_injiweb "$scenario")" == "yes" ]]; then
    profile_args+=( --profile injiweb )
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
  compose --profile injiweb ps --format '  {{.Service}}  {{.Status}}' 2>/dev/null | sort -u
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
  [[ -n "$scenario" ]] || { red "usage: deploy.sh config <all|waltid|inji>"; exit 2; }
  backends_for "$scenario"
  echo "---"
  cat "$SCRIPT_DIR/config/backends.json"
}

cmd_run() {
  local scenario="${1:-}"
  [[ -n "$scenario" ]] || { red "usage: deploy.sh run <all|waltid|inji>"; exit 2; }
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
  up <all|waltid|inji>     start compose services + build & run verifiably-go container
  down [all|waltid|inji]   stop them (default: all)
  run <all|waltid|inji>    rebuild + restart only the verifiably-go container
                           (use when the DPG stack is already up)
  config <all|waltid|inji> print the backends.json that would be generated
  status                   summarise what's running
  reset                    wipe every waltid_* named volume — fixes keystore/DB
                           desync ("KER-KMA-004 No such alias: ..."). DESTRUCTIVE;
                           asks for explicit 'RESET' confirmation.

scenarios:
  all     every DPG + both IdPs + LibreTranslate
  waltid  walt.id stack + Keycloak + LibreTranslate
  inji    Inji Certify (×2) + Inji Verify + Inji Web + WSO2IS + LibreTranslate

all three scenarios include a containerised verifiably-go on port $VERIFIABLY_HOST_PORT,
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
