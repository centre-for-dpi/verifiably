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
  # Render in BOTH modes (subdomain AND legacy host:port). url_for already
  # resolves the right value per mode: subdomain -> https://walt-issuer.<domain>,
  # legacy -> http://<host>:<port> (reached container-side via the compose
  # extra_hosts localhost:host-gateway). Rendering in legacy too — rather than
  # relying on walt.id's HOCON ${SERVICE_HOST} substitution — makes a fresh
  # localhost deploy work deterministically; the committed files carry the
  # portable ${SERVICE_HOST}:${..._API_PORT} template as a k8s/no-render fallback.
  local issuer_conf="$SCRIPT_DIR/deploy/k8s/config/issuer/issuer-service.conf"
  local verifier_conf="$SCRIPT_DIR/deploy/k8s/config/verifier/verifier-service.conf"
  local issuer_url verifier_url
  issuer_url=$(url_for walt-issuer "$VERIFIABLY_PUBLIC_HOST" "$WALTID_ISSUER_PORT")
  verifier_url=$(url_for walt-verifier "$VERIFIABLY_PUBLIC_HOST" "$WALTID_VERIFIER_PORT")
  printf 'baseUrl = "%s"\n' "$issuer_url"   > "$issuer_conf"
  printf 'baseUrl = "%s"\n' "$verifier_url" > "$verifier_conf"
  green "  rendered walt.id service confs (issuer=$issuer_url, verifier=$verifier_url)"

  # issuer-api2 needs the same treatment for the same reason, but its conf
  # carries far more than baseUrl (env-substituted keys, clientAuthentication
  # config), so this rewrites the single line in place rather than truncating
  # the file the way the two above do.
  #
  # Without this the mdoc credential offer a citizen scans points at the
  # compose-internal host, which no phone can resolve. issuer-api2 publishes
  # no ports; Caddy proxies only its /openid4vci/* and /.well-known/* paths
  # (see the walt-issuer2 entry below) so the unauthenticated /issuer2/*
  # management API stays off the public internet.
  local issuer2_conf="$SCRIPT_DIR/deploy/k8s/config/issuer2/issuer-service.conf"
  if [[ -f "$issuer2_conf" ]]; then
    local issuer2_url
    issuer2_url=$(url_for walt-issuer2 "$VERIFIABLY_PUBLIC_HOST" "$WALTID_ISSUER_PORT")
    # Match the committed template line or a previously rendered literal.
    python3 - "$issuer2_conf" "$issuer2_url" <<'PYEOF'
import re, sys
path, url = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    text = f.read()
new, n = re.subn(r'(?m)^baseUrl\s*=\s*".*"$', 'baseUrl = "%s"' % url, text, count=1)
if n:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(new)
PYEOF
    green "  rendered issuer-api2 baseUrl ($issuer2_url)"

    # ciTokenKey / credentialEncryptionKey cannot be env-substituted at all:
    # bare ${VAR} arrives as a HOCON object where Hoplite wants a JSON string,
    # and """${VAR}""" is not substituted (HOCON leaves triple-quoted text
    # literal). Both crash the boot. So render the real JSON in here, the way
    # walt.id ships it. The committed file carries placeholders; this rewrite
    # is what a running deployment actually reads.
    local _missing=""
    [[ -z "${VERIFIABLY_ISSUER2_CI_TOKEN_KEY:-}" ]] && _missing="VERIFIABLY_ISSUER2_CI_TOKEN_KEY"
    [[ -z "${VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY:-}" ]] && _missing="$_missing VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY"
    if [[ -n "$_missing" ]]; then
      red "  issuer-api2 will NOT boot — missing:$_missing"
      red "  Generate EC P-256 JWKs wrapped as {\"type\":\"jwk\",\"jwk\":{...}} and set them in .env"
    else
      python3 - "$issuer2_conf" "$VERIFIABLY_ISSUER2_CI_TOKEN_KEY" "$VERIFIABLY_ISSUER2_CRED_ENCRYPTION_KEY" <<'PYEOF'
import re, sys
path, ci, enc = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as f:
    text = f.read()
text = re.sub(r'(?m)^ciTokenKey\s*=.*$',
              'ciTokenKey = """%s"""' % ci, text, count=1)
text = re.sub(r'(?m)^credentialEncryptionKey\s*=.*$',
              'credentialEncryptionKey = """%s"""' % enc, text, count=1)
with open(path, "w", encoding="utf-8", newline="") as f:
    f.write(text)
PYEOF
      green "  rendered issuer-api2 ciTokenKey + credentialEncryptionKey"
    fi
  fi
}

# provision_issuer2_certificates generates the mdoc issuance certificate chain
# on first deploy and renders the DSC into issuer2-profiles.conf's x5chain.
#
# WHY THIS EXISTS
# The committed issuer2-profiles.conf carries walt.id's PUBLISHED EXAMPLE
# certificate. Its public key is not the operator's signing key, and ISO
# 18013-5 gives a verifier no source for the signing key other than the
# x5chain leaf. So a clean deploy comes up, issues credentials, returns 200 on
# everything, and produces mdocs that every conformant wallet rejects — a real
# wallet reports only "No trusted certificate was found while validating the
# X.509 chain". Nothing in walt.id logs a complaint. This function is what
# closes that gap without a human remembering to.
#
# KEY/CERTIFICATE BINDING
# cmd/mdl-pki-gen generates the DSC key and certifies THAT key, then emits both
# the certificate and the matching VERIFIABLY_ISSUER2_KEY_X/_Y/_D coordinates.
# They cannot drift apart, because one command produces both from one key. That
# mismatch is the exact failure that has already reached a live deployment.
#
# IDEMPOTENCE
# Both halves are no-clobber, the same posture as seed_credential_issuer_catalog:
#   - mdl-pki-gen returns early if dsc.pem exists, so a redeploy never
#     regenerates. Regenerating would start signing with a key that credentials
#     already in citizens' wallets do not carry in their x5chain.
#   - the x5chain is only rewritten while the committed walt.id example
#     certificate is still in place, so an operator who pasted in their own real
#     chain keeps it.
# An operator supplying real material just drops dsc.pem/iaca.pem into the certs
# directory (and sets the three key vars) before the first deploy; generation
# then skips entirely.
#
# The generated material is proof-of-concept: every subject carries
# O=POC-DO-NOT-TRUST so it cannot be mistaken for a real PKI.
#
# Subject C/ST are configurable because @animo-id/mdoc cross-checks the mdoc's
# issuing_country against countryName and issuing_jurisdiction against
# stateOrProvinceName. A mismatch is a rejection at accept time, and not every
# deployment is Dominican.
provision_issuer2_certificates() {
  local certs_dir="$SCRIPT_DIR/deploy/k8s/config/issuer2/certs"
  local profiles="$SCRIPT_DIR/deploy/k8s/config/issuer2/issuer2-profiles.conf"
  local dsc="$certs_dir/dsc.pem"
  local iaca="$certs_dir/iaca.pem"
  local key_env="$certs_dir/issuer2.env"

  if [[ ! -f "$profiles" ]]; then
    red "  WARN: $profiles missing — issuer2 certificate provisioning skipped"
    return 0
  fi

  local country="${VERIFIABLY_ISSUER2_CERT_COUNTRY:-DO}"
  local province="${VERIFIABLY_ISSUER2_CERT_PROVINCE:-DO-01}"
  local authority="${VERIFIABLY_ISSUER2_CERT_AUTHORITY:-VERIFIABLY POC}"

  # Generate only when there is no DSC yet. mdl-pki-gen re-checks this itself;
  # testing here too keeps the docker run off the path of every redeploy.
  if [[ ! -f "$dsc" ]]; then
    mkdir -p "$certs_dir"
    bold "  Generating mdoc issuance certificates (first deploy)"
    # No Go toolchain is assumed on the deploy host — deploy.sh already
    # requires docker, so build and run the generator in the official image.
    # The module cache is not persisted; this is a once-per-deployment cost.
    if ! docker run --rm \
        -v "$SCRIPT_DIR":/src -w /src \
        -e GOFLAGS=-mod=mod \
        golang:1.25-alpine \
        go run ./cmd/mdl-pki-gen \
          -out "/src/deploy/k8s/config/issuer2/certs" \
          -country "$country" -province "$province" -authority "$authority"; then
      red "  issuer2 certificate generation FAILED — the deployment will issue"
      red "  mdocs carrying walt.id's example certificate, which no wallet accepts."
      return 1
    fi
  fi

  [[ -f "$dsc" ]] || { red "  WARN: $dsc missing after generation — skipping x5chain render"; return 0; }

  # Load the generated coordinates into the environment compose passes through,
  # and persist them to .env so a later `up` (which does not re-run generation)
  # still has them. Never overwrite values an operator set themselves.
  if [[ -f "$key_env" ]]; then
    local _line _var _val
    while IFS= read -r _line; do
      [[ "$_line" == VERIFIABLY_ISSUER2_KEY_* ]] || continue
      _var="${_line%%=*}"
      _val="${_line#*=}"
      if [[ -z "${!_var:-}" ]]; then
        export "$_var=$_val"
        [[ -n "${VERIFIABLY_ENV_FILE:-}" ]] && set_env_var "$VERIFIABLY_ENV_FILE" "$_var" "$_val"
      fi
    done < "$key_env"
    green "  issuer2 signing key loaded from $key_env"
  fi

  # Render the DSC (and its IACA) into defaultIssuerX5chain, but only while the
  # committed walt.id example certificate is still there. Once this file carries
  # a real chain — ours or the operator's — leave it alone.
  python3 - "$profiles" "$dsc" "$iaca" <<'PYEOF'
import re, sys

profiles_path, dsc_path, iaca_path = sys.argv[1], sys.argv[2], sys.argv[3]

with open(profiles_path, encoding="utf-8") as f:
    text = f.read()

# walt.id's published example certificate, identified by the CN baked into it.
# Matching on this rather than on "is there any cert" is what makes the render
# no-clobber: an operator-supplied chain does not contain it.
WALTID_EXAMPLE = "MIIBeTCCAR8CFHrWgrGl5KdefSvRQhR"
if WALTID_EXAMPLE not in text:
    print("  x5chain already carries a non-example certificate — left as is")
    raise SystemExit(0)

def pem_body(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()

certs = [pem_body(dsc_path)]
try:
    certs.append(pem_body(iaca_path))
except OSError:
    pass  # DSC alone is a valid x5chain; the IACA is the trust anchor.

# HOCON triple-quoted strings, one per certificate, leaf first.
block = "defaultIssuerX5chain = [\n" + ",\n".join(
    '  """%s"""' % c for c in certs
) + "\n]\n"

new, n = re.subn(
    r'(?ms)^defaultIssuerX5chain = \[.*?^\]\n',
    lambda m: block,
    text,
    count=1,
)
if not n:
    raise SystemExit("  ERROR: could not locate defaultIssuerX5chain block")

with open(profiles_path, "w", encoding="utf-8", newline="") as f:
    f.write(new)
print("  rendered issuer2 x5chain (%d certificate(s), leaf first)" % len(certs))
PYEOF

  # The IACA is the trust anchor an operator imports into a wallet, so say
  # where it is rather than leaving them to find it.
  if [[ -f "$iaca" ]]; then
    green "  IACA trust anchor for wallet import: $iaca"
  fi
}

# announce_issuer2_trust_anchor tells the operator where the IACA is, at the
# END of a deploy where it is still on screen.
#
# An mdoc is only trustworthy to a wallet that recognises its trust anchor. Our
# IACA is self-signed and in no wallet's default store, so unless the operator
# imports this file, every credential this deployment issues is refused — and
# the wallet's message ("No trusted certificate was found") points at the
# certificate, not at the missing import. Printing the path is what turns that
# into a two-minute fix instead of a debugging session.
announce_issuer2_trust_anchor() {
  local iaca="$SCRIPT_DIR/deploy/k8s/config/issuer2/certs/iaca.pem"
  [[ -f "$iaca" ]] || return 0
  bold "▶ mdoc trust anchor"
  echo "    Import this IACA into your wallet to accept mdocs from this deployment:"
  echo "      $iaca"
  echo "    Generated demo PKI (O=POC-DO-NOT-TRUST). The DSC expires in at most"
  echo "    457 days (ISO/IEC 18013-5 Annex B); re-issue credentials after that."
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
    # walt-issuer2: mso_mdoc (mDL / Photo ID) issuance. Needs a public origin
    # because issuer-api2 stamps its own baseUrl into the credential offer the
    # citizen's wallet resolves — an offer pointing at the compose-internal
    # host is unreachable from a phone. Only the OID4VCI protocol paths are
    # proxied; see the handle rules below, which deliberately do NOT expose
    # /issuer2/* (unauthenticated management API).
    "walt-issuer2|issuer-api2:7002|http"
    "walt-wallet|wallet-api:7001|http"
    "walt-verifier|verifier-api:7003|http"
    "inji-certify|certify-nginx:80|http"
    "inji-certify-preauth|certify-preauth-nginx:80|http"
    "inji-certify-authcode|certify-nginx:80|http"
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
    "grafana|grafana:3000|http"
    "registry-admin|registry-admin:8000|http"
    # Purpose-named registry subdomains (both proxy to verifiably-go; the app
    # redirects identity.registry's root to /registrar/identities). Default
    # slugs give the dotted forms identity.registry.<domain> / admin.registry
    # .<domain> so a deployment reads them as "the identity registry" and "the
    # registry admin console"; override via VERIFIABLY_SLUG_IDENTITY_REGISTRY /
    # VERIFIABLY_SLUG_REGISTRY_ADMIN. Two-label names resolve via the
    # *.registry.<domain> wildcard the agency registries already use.
    "identity-registry|verifiably-go:8080|http"
    # eSignet auth-method config surface (verifiably-owned; the app redirects its
    # root to /admin/esignet). Distinct from esignet.<domain> = the eSignet
    # product. Slug default esignet-config; override via VERIFIABLY_SLUG_ESIGNET_CONFIG.
    "esignet-config|verifiably-go:8080|http"
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

(security_headers) {
	header {
		X-Content-Type-Options  nosniff
		X-Frame-Options         DENY
		X-XSS-Protection        "1; mode=block"
		Referrer-Policy         strict-origin-when-cross-origin
		Permissions-Policy      "camera=(), microphone=(), geolocation=(), payment=()"
		Strict-Transport-Security "max-age=63072000; includeSubDomains"
		-Server
	}
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
      printf '\timport security_headers\n'
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
        # did:web DID document — served statically by the nginx sidecar from
        # .agent-runtime/did/did.json (exported by _credebl_export_did_document).
        printf '\thandle /.well-known/did.json {\n\t\treverse_proxy credebl-oid4vci-rewriter:80\n\t}\n'
      fi
      # walt-issuer: serve the did:web DID document inline via Caddy respond
      # when bootstrap_waltid_did_web has generated .agent-runtime/waltid/did.json.
      # The JSON is embedded directly (backtick string — safe because DID docs
      # never contain backticks). Falls through to issuer-api for all other paths.
      if [[ "$name" == "walt-issuer" ]]; then
        local _waltid_did_file="$SCRIPT_DIR/.agent-runtime/waltid/did.json"
        if [[ -f "$_waltid_did_file" ]]; then
          local _waltid_did_json
          _waltid_did_json=$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        print(json.dumps(json.load(f)))
except Exception:
    pass
" "$_waltid_did_file" 2>/dev/null) || true
          if [[ -n "$_waltid_did_json" ]]; then
            printf '\thandle /.well-known/did.json {\n'
            printf '\t\theader Content-Type "application/json"\n'
            printf '\t\theader Access-Control-Allow-Origin "*"\n'
            printf '\t\trespond `%s` 200\n' "$_waltid_did_json"
            printf '\t}\n'
          fi
        fi
      fi
      # inji-verify: serve the did:web DID document inline at the path the
      # did:web method resolves to — /v1/verify/.well-known/did.json.
      # The Ed25519 public key is the one bundled in mosipid/inji-verify-service:0.16.0
      # (sample-keystore/test.p12, pass=mosip). Falls through to inji-verify-service
      # for all other paths.
      if [[ "$name" == "inji-verify" ]]; then
        local _inji_did="did:web:${subdomain}:v1:verify"
        local _inji_pub_key="z6MkkzruJN9axHYvD6xjym3FrMiPTGaZKuL9LFtt8bQMcEvC"
        local _inji_did_doc
        _inji_did_doc=$(python3 - <<PYEOF 2>/dev/null
import json
did = "${_inji_did}"
key = "${_inji_pub_key}"
print(json.dumps({"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"], "id": did, "verificationMethod": [{"id": did + "#key-0", "type": "Ed25519VerificationKey2020", "controller": did, "publicKeyMultibase": key}], "authentication": [did + "#key-0"]}))
PYEOF
) || true
        if [[ -n "$_inji_did_doc" ]]; then
          printf '\thandle /v1/verify/.well-known/did.json {\n'
          printf '\t\theader Content-Type "application/did+ld+json"\n'
          printf '\t\theader Access-Control-Allow-Origin "*"\n'
          printf '\t\trespond `%s` 200\n' "$_inji_did_doc"
          printf '\t}\n'
        fi
      fi
      # inji-certify-authcode: the dedicated did:web host for the PRIMARY auth-code
      # issuer (kept separate from inji-certify-preauth to avoid any ambiguity).
      # did:web:inji-certify-authcode.<domain> resolves here; serve the patched
      # certify did.json from the verifiably-go primary proxy (InjiProxyPrimaryDidJSON).
      # Other paths fall through to certify-nginx (harmless — it's a DID host).
      if [[ "$name" == "inji-certify-authcode" ]]; then
        printf '\thandle /.well-known/did.json {\n'
        printf '\t\trewrite * /inji-proxy/.well-known/did.json\n'
        printf '\t\treverse_proxy verifiably-go:8080\n'
        printf '\t}\n'
      fi
      # walt-issuer2: expose ONLY the OID4VCI protocol surface a wallet needs.
      #
      # issuer-api2 ships no authentication knob whatsoever. /issuer2/* lets
      # anyone who can reach it mint a signed credential with arbitrary subject
      # data (POST /issuer2/credential-offers) and read issuerKey private
      # material (GET /issuer2/sessions). Network isolation is the mitigation,
      # which is why the compose service publishes no ports — but the wallet
      # still needs a public origin, because issuer-api2 stamps its own baseUrl
      # into the offer the citizen scans.
      #
      # So: allowlist the protocol paths, and return 404 for everything else.
      # verifiably-go keeps reaching /issuer2/* over the compose network, where
      # it was always reachable. Do NOT replace this with a bare reverse_proxy.
      if [[ "$name" == "walt-issuer2" ]]; then
        printf '\thandle /openid4vci/* {\n\t\treverse_proxy %s\n\t}\n' "$upstream"
        printf '\thandle /.well-known/* {\n\t\treverse_proxy %s\n\t}\n' "$upstream"
        printf '\thandle {\n\t\trespond 404\n\t}\n'
        printf '}\n\n'
        continue
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
