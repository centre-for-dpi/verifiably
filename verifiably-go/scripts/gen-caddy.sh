#!/usr/bin/env bash
# gen-caddy.sh — config-file renderers: wso2-deployment.toml, walt.id service
# confs, credential-issuer catalog, and the public Caddyfile.
# Sourced by deploy.sh. Can also be sourced standalone after common.sh.
[[ "${_VERIFIABLY_COMMON_LOADED:-}" == "1" ]] || source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/common.sh"

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
    "credebl|credebl-api-gateway:5000|http"
    "credebl-minio|credebl-minio:9000|http"
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
      # Avoid double-prefix when slug == first label of VERIFIABLY_PUBLIC_DOMAIN.
      local _first_label="${VERIFIABLY_PUBLIC_DOMAIN%%.*}"
      if [[ -n "$VERIFIABLY_PUBLIC_DOMAIN" && "$slug" == "$_first_label" ]]; then
        subdomain="${VERIFIABLY_PUBLIC_DOMAIN}"
      else
        subdomain="${slug}.${VERIFIABLY_PUBLIC_DOMAIN}"
      fi
      printf '%s {\n' "$subdomain"
      # OID4VCI requests must bypass the CREDEBL API gateway (which returns
      # 404 for /oid4vci/*) and go directly to the Credo agent controller.
      # caddy-public reaches it via host.docker.internal because the agent
      # container is on afj_default, a separate network from waltid_default.
      if [[ "$name" == "credebl" ]]; then
        # Route OID4VCI and OID4VP agent paths through the nginx sidecar.
        # The sidecar proxies to the Credo agent (host.docker.internal:8001)
        # and, as a safety net, rewrites any bare-IP URLs in response bodies.
        # /openid4vc/* is the OID4VP wallet-facing path (authorization-requests,
        # presentations) — without this rule caddy falls through to the API
        # gateway which returns 404 to the wallet.
        printf '\thandle /oid4vci/* {\n\t\treverse_proxy credebl-oid4vci-rewriter:80\n\t}\n'
        printf '\thandle /oid4vp/* {\n\t\treverse_proxy credebl-oid4vci-rewriter:80\n\t}\n'
        printf '\thandle /openid4vc/* {\n\t\treverse_proxy credebl-oid4vci-rewriter:80\n\t}\n'
      fi
      case "$proto" in
        https-skipverify)
          printf '\treverse_proxy https://%s {\n\t\ttransport http {\n\t\t\ttls_insecure_skip_verify\n\t\t}\n\t}\n' "$upstream"
          ;;
        *)
          # verifiably-go: emit lb_policy=cookie when Redis sessions are enabled
          # so multi-replica setups get sticky L7 routing via the session cookie.
          if [[ "$name" == "verifiably" && -n "${VERIFIABLY_REDIS_URL:-}" ]]; then
            printf '\treverse_proxy %s {\n\t\tlb_policy cookie verifiably_session\n\t}\n' "$upstream"
          else
            printf '\treverse_proxy %s\n' "$upstream"
          fi
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
