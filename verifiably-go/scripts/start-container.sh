#!/usr/bin/env bash
# start-container.sh — start_container(), stop_container(), and
# backends_for_docker() for Docker-mode deployments.
# Sourced by deploy.sh. Can also be sourced standalone after common.sh.
[[ "${_VERIFIABLY_COMMON_LOADED:-}" == "1" ]] || source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/common.sh"
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
  if [[ -z "$docker_gid" ]]; then
    # Docker Desktop for Windows: the socket doesn't exist at a POSIX path
    # from Git Bash, but inside the container it's mounted as srw-rw---- root:root
    # (GID 0). Fall back to GID 0 so UID 65532 can connect via --group-add.
    docker_gid=0
  fi
  local group_add_args=( --group-add "$docker_gid" )
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
  # Init the state volume: the distroless nonroot user (UID 65532) can't
  # write to a newly created Docker named volume (owned root:root). Run a
  # one-shot alpine container to pre-create the sessions subdir and fix
  # ownership. Idempotent — safe to re-run on every start.
  MSYS_NO_PATHCONV=1 docker run --rm \
    -v "${VERIFIABLY_CONTAINER}-state:/vol" \
    alpine:3.18 \
    sh -c "mkdir -p /vol/sessions && chown -R 65532:65532 /vol && chmod 700 /vol" \
    >/dev/null 2>&1 || true

  # ── Subdomain mode: route container-side calls through caddy-public ───────
  # In subdomain mode every backend + IdP URL is a public https://<slug>.<domain>
  # name that (via public DNS) resolves to the host's OWN public IP. Most
  # VPS/cloud hosts don't hairpin traffic from the docker bridge back to their
  # published :443, so verifiably-go's server-side OIDC discovery + adapter
  # calls hang ("context deadline exceeded"). Fix: resolve caddy-public's IP on
  # the compose network and pin every public FQDN to it via --add-host, so those
  # requests go container→caddy-public directly — same SNI + Host header, so
  # Caddy serves the right cert + proxies to the right upstream, and the
  # discovered `issuer` still matches the public URL. The browser is unaffected
  # (it uses real public DNS). No-op in legacy host:port mode.
  local host_alias_args=()
  if [[ -n "${VERIFIABLY_HOSTS_PATTERN:-}" && -n "${VERIFIABLY_PUBLIC_DOMAIN:-}" ]]; then
    local _caddy_ip=""
    _caddy_ip=$(docker inspect "${COMPOSE_PROJECT}-caddy-public-1" \
      --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || true)
    if [[ -z "$_caddy_ip" ]]; then
      local _cid
      _cid=$(docker ps -q --filter "label=com.docker.compose.service=caddy-public" | head -1)
      [[ -n "$_cid" ]] && _caddy_ip=$(docker inspect "$_cid" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || true)
    fi
    if [[ -n "$_caddy_ip" ]]; then
      # compute_host_aliases (common.sh) is the pure, unit-tested core of this
      # fix; it prints one --add-host token per line for every public slug.
      local _tok
      while IFS= read -r _tok; do
        [[ -n "$_tok" ]] && host_alias_args+=( "$_tok" )
      done < <(compute_host_aliases "$VERIFIABLY_PUBLIC_DOMAIN" "$_caddy_ip")
      green "  subdomain mode: pinned *.${VERIFIABLY_PUBLIC_DOMAIN} → caddy-public ($_caddy_ip) for container-side calls"
    else
      yellow "  subdomain mode: could not resolve caddy-public IP — server-side OIDC discovery may time out (hairpin NAT)"
    fi
  fi

  # MSYS_NO_PATHCONV=1 prevents Git Bash from converting Unix paths like
  # /var/run/docker.sock to C:\Program Files\Git\var\run\docker.sock.
  # Docker Desktop on Windows handles MSYS-style paths (/c/Users/...) natively.
  # In-app Inji auth-code wallet: extract the eSignet wallet-demo-client key
  # (PKCS#8 PEM) from the deploy's oidckeystore.p12 and derive the eSignet URL
  # per host, so a holder can claim inside verifiably (no inji-web redirect).
  local _inji_p12="$SCRIPT_DIR/deploy/compose/injiweb/config/certs/oidckeystore.p12"
  local _inji_key_pem=""
  if [ -f "$_inji_p12" ] && command -v openssl >/dev/null 2>&1; then
    _inji_key_pem=$(openssl pkcs12 -in "$_inji_p12" -nodes -nocerts -legacy -passin "pass:${INJIWEB_P12_PASSWORD:-xy4gh6swa2i}" 2>/dev/null | openssl pkcs8 -topk8 -nocrypt 2>/dev/null || true)
  fi
  local _inji_esignet_url="${ESIGNET_BASE_URL:-$(url_for esignet "${VERIFIABLY_PUBLIC_HOST:-${PUBLIC_HOST:-localhost}}" "${ESIGNET_PUBLIC_PORT:-3005}")}"
  MSYS_NO_PATHCONV=1 docker run -d \
    --name "$VERIFIABLY_CONTAINER" \
    --restart unless-stopped \
    --health-cmd="wget -qO- http://localhost:8080/healthz || exit 1" \
    --health-interval=15s \
    --health-timeout=5s \
    --health-retries=3 \
    --network "${COMPOSE_PROJECT}_default" \
    --add-host=host.docker.internal:host-gateway \
    "${host_alias_args[@]}" \
    "${group_add_args[@]}" \
    -p "${VERIFIABLY_HOST_PORT}:8080" \
    -v "$SCRIPT_DIR/config/backends.docker.json:/app/config/backends.json:ro" \
    -v "$system_providers_mount:/app/config/auth-providers.system.json:ro" \
    -v "$user_providers_path:/app/config/auth-providers.user.json" \
    -v "$custom_schemas_path:/app/config/custom-schemas.user.json" \
    -v "$SCRIPT_DIR/deploy/k8s/config/issuer:/app/issuer-api-config" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "${VERIFIABLY_CONTAINER}-locales:/app/locales" \
    -v "${VERIFIABLY_CONTAINER}-state:/app/state" \
    -e VERIFIABLY_ADAPTER=registry \
    -e VERIFIABLY_ADDR=:8080 \
    -e VERIFIABLY_LOG_JSON=1 \
    -e VERIFIABLY_ROLES="${VERIFIABLY_ROLES:-issuer,holder,verifier,trust,schemas}" \
    -e VERIFIABLY_STATE_DIR=/app/state \
    -e VERIFIABLY_PUBLIC_URL="$VERIFIABLY_PUBLIC_URL" \
    -e LIBRETRANSLATE_URL="http://libretranslate:5000" \
    -e INJI_CERTIFY_UPSTREAM_URL="http://inji-certify:8090" \
    -e INJI_CERTIFY_DATABASE_URL="${INJI_CERTIFY_DATABASE_URL:-postgres://postgres:postgres@certify-postgres:5432/inji_certify?sslmode=disable}" \
    -e INJI_AUTHCODE_CLIENT_KEY_PEM="$_inji_key_pem" \
    -e INJI_AUTHCODE_CLIENT_ID="${INJI_AUTHCODE_CLIENT_ID:-wallet-demo-client}" \
    -e INJI_AUTHCODE_CLIENT_KID="${INJI_AUTHCODE_CLIENT_KID:-wallet-demo-client-kid}" \
    -e INJI_AUTHCODE_SCOPE="${INJI_AUTHCODE_SCOPE:-mock_identity_vc_ldp}" \
    -e ESIGNET_BASE_URL="$_inji_esignet_url" \
    -e INJI_PROXY_EXTRA_KIDS="${VERIFIABLY_INJI_EXTRA_KIDS:-}" \
    -e WALTID_CATALOG_PATH=/app/issuer-api-config/credential-issuer-metadata.conf \
    -e WALTID_ISSUER_SERVICE=issuer-api \
    -e VERIFIABLY_AUTH_PROVIDERS_FILE=/app/config/auth-providers.system.json \
    -e VERIFIABLY_AUTH_ADMIN="${VERIFIABLY_AUTH_ADMIN:-rw}" \
    -e VERIFIABLY_ADMIN_USER="${VERIFIABLY_ADMIN_USER:-}" \
    -e VERIFIABLY_ADMIN_PASSWORD="${VERIFIABLY_ADMIN_PASSWORD:-}" \
    ${VERIFIABLY_LANDING_ROLES:+-e VERIFIABLY_LANDING_ROLES="$VERIFIABLY_LANDING_ROLES"} \
    ${VERIFIABLY_SESSION_SECRET:+-e VERIFIABLY_SESSION_SECRET="$VERIFIABLY_SESSION_SECRET"} \
    ${VERIFIABLY_API_KEYS:+-e VERIFIABLY_API_KEYS="$VERIFIABLY_API_KEYS"} \
    ${CREDEBL_EMAIL:+-e CREDEBL_EMAIL="$CREDEBL_EMAIL"} \
    ${CREDEBL_PASSWORD:+-e CREDEBL_PASSWORD="$CREDEBL_PASSWORD"} \
    ${CREDEBL_CRYPTO_PRIVATE_KEY:+-e CREDEBL_CRYPTO_PRIVATE_KEY="$CREDEBL_CRYPTO_PRIVATE_KEY"} \
    ${CREDEBL_ORG_ID:+-e CREDEBL_ORG_ID="$CREDEBL_ORG_ID"} \
    ${CREDEBL_ISSUER_ID:+-e CREDEBL_ISSUER_ID="$CREDEBL_ISSUER_ID"} \
    ${CREDEBL_VERIFIER_ID:+-e CREDEBL_VERIFIER_ID="$CREDEBL_VERIFIER_ID"} \
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

# subdomain-slug → docker-internal hostname:port for subdomain-mode URLs
# (https://slug.domain) that carry no explicit port number and are therefore
# not matched by port_to_internal above. The slug is the first label of the
# hostname (everything before the first dot).
slug_to_internal = {
    "inji-certify-preauth": "inji-certify-preauth:8090",
    "inji-certify":         "certify-nginx:80",
    "inji-verify":          "inji-verify-service:8080",
    "inji-verify-ui":       "inji-verify-ui:8000",
    "inji-web":             "injiweb-ui:3004",
    "mimoto":               "injiweb-mimoto:8099",
    "esignet":              "injiweb-oidc-ui:3000",
    "walt-issuer":          "issuer-api:7002",
    "walt-wallet":          "wallet-api:7001",
    "walt-verifier":        "verifier-api:7003",
    "credebl":              "credebl-api-gateway:5000",
}

import re
URL_RE = re.compile(r"^(https?)://([^:/]+):(\d+)(.*)$")
NOPORT_RE = re.compile(r"^(https?)://([^/:]+)(.*)$")

def rewrite_url(url):
    if not isinstance(url, str):
        return url
    m = URL_RE.match(url)
    if m:
        scheme, host, port, rest = m.groups()
        internal = port_to_internal.get(port)
        if not internal:
            return url
        return f"http://{internal}{rest}"
    # No explicit port — subdomain-mode URL (https://slug.domain/path).
    # Match the first hostname label against slug_to_internal.
    m = NOPORT_RE.match(url)
    if m:
        scheme, host, rest = m.groups()
        slug = host.split(".")[0]
        internal = slug_to_internal.get(slug)
        if internal:
            return f"http://{internal}{rest}"
    return url

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

