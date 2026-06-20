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

# ── Modular sub-scripts ──────────────────────────────────────────────────────
# shellcheck source=scripts/common.sh
source "$SCRIPT_DIR/scripts/common.sh"
# shellcheck source=scripts/gen-backends.sh
source "$SCRIPT_DIR/scripts/gen-backends.sh"
# shellcheck source=scripts/start-container.sh
source "$SCRIPT_DIR/scripts/start-container.sh"
# shellcheck source=scripts/bootstrap-credebl.sh
source "$SCRIPT_DIR/scripts/bootstrap-credebl.sh"
# shellcheck source=scripts/bootstrap-waltid-did.sh
source "$SCRIPT_DIR/scripts/bootstrap-waltid-did.sh"
# shellcheck source=scripts/gen-caddy.sh
source "$SCRIPT_DIR/scripts/gen-caddy.sh"


# ---------------------------------------------------------------- subcommands

cmd_up() {
  local scenario="${1:-}"
  [[ -n "$scenario" ]] || { red "usage: deploy.sh up <all|waltid|inji|credebl>"; exit 2; }
  scenario_services "$scenario" > /dev/null  # validate

  require docker

  # First-time setup: if no .env exists and we are not reading from .env.example,
  # run the setup wizard so the operator sets VERIFIABLY_PUBLIC_HOST before any
  # service starts. Skip if a previous .env already existed (VERIFIABLY_ENV_FILE
  # will point at it) or if the operator explicitly set VERIFIABLY_PUBLIC_HOST.
  local _env_file="$SCRIPT_DIR/.env"
  if [[ ! -f "$_env_file" && "${VERIFIABLY_PUBLIC_HOST:-localhost}" == "localhost" ]]; then
    yellow "  No .env found — running first-time setup wizard."
    echo
    cmd_setup
    echo
    # Re-source the newly written .env so the rest of cmd_up sees the values
    set -o allexport
    # shellcheck disable=SC1090
    source "$_env_file"
    set +o allexport
  fi

  # Detect VERIFIABLY_PUBLIC_HOST change vs. what is baked into running
  # containers (SERVICE_HOST env var on issuer-api / verifier-api / wallet-api,
  # and KC_HOSTNAME_URL on keycloak). When the host changed, recreate those
  # containers so they pick up the new URLs before any client tries to use them.
  local _running_host=""
  _running_host=$(docker inspect waltid-issuer-api-1 \
    --format '{{range .Config.Env}}{{.}}\n{{end}}' 2>/dev/null \
    | grep '^SERVICE_HOST=' | cut -d= -f2- || true)
  if [[ -n "$_running_host" && "$_running_host" != "$VERIFIABLY_PUBLIC_HOST" ]]; then
    yellow "  VERIFIABLY_PUBLIC_HOST changed: ${_running_host} → ${VERIFIABLY_PUBLIC_HOST}"
    yellow "  Recreating issuer-api, verifier-api, wallet-api, and keycloak."
    for _svc in issuer-api verifier-api wallet-api keycloak; do
      compose up -d --force-recreate "$_svc" 2>/dev/null || true
    done
  fi

  # Export compose env vars that differ between IP mode and subdomain mode.
  # These are read by docker-compose via shell environment substitution.
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    # caddy-public owns :80/:443; bind main Caddy's :80 to localhost only
    # so the two services don't collide on the host port.
    export CADDY_HTTP_PORT="127.0.0.1:8079"
    export KC_HOSTNAME_URL
    KC_HOSTNAME_URL=$(url_for keycloak "$VERIFIABLY_PUBLIC_HOST" "${KEYCLOAK_PORT:-8180}")
  else
    export CADDY_HTTP_PORT="80"
    export KC_HOSTNAME_URL="http://${VERIFIABLY_PUBLIC_HOST}:${KEYCLOAK_PORT:-8180}"
  fi

  # Early RAM sanity check: the inji + credebl scenarios + the always-on
  # IdPs (Keycloak + WSO2IS when not skipped) routinely exceed a 4 GiB
  # Docker Desktop allocation and OOM-kill containers mid-bring-up — fail
  # loud here so the operator doesn't waste 10 minutes watching WSO2IS
  # restart-loop. The minimum is a heuristic, not a hard wall; the operator
  # can opt out by setting VERIFIABLY_SKIP_RAM_CHECK=1.
  if [[ "${VERIFIABLY_SKIP_RAM_CHECK:-}" != "1" ]]; then
    local _docker_mem_bytes
    _docker_mem_bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
    local _docker_mem_gib=$(( _docker_mem_bytes / 1024 / 1024 / 1024 ))
    local _needed_gib=4
    case "$scenario" in
      all|credebl) _needed_gib=8 ;;
      inji)        _needed_gib=6 ;;
    esac
    if (( _docker_mem_gib > 0 && _docker_mem_gib < _needed_gib )); then
      yellow "  Docker Engine has ${_docker_mem_gib} GiB allocated; ${scenario} typically needs ${_needed_gib} GiB."
      yellow "  Containers may OOM mid-bring-up. Bump RAM in Docker Desktop (Settings → Resources → Advanced)"
      yellow "  or set VERIFIABLY_SKIP_WSO2IS=1 to drop the heaviest single service (~1.5 GiB)."
      yellow "  Override this check with VERIFIABLY_SKIP_RAM_CHECK=1."
    fi
  fi

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
      VERIFIABLY_PUBLIC_DOMAIN="${VERIFIABLY_PUBLIC_DOMAIN:-}" \
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
    # PREAUTH_PUBLIC_URL drives the pre-auth Inji Certify backend's
    # mosip_certify_domain_url. It MUST be the public subdomain so Certify
    # (a) advertises public credential_issuer/credential_endpoint/
    # authorization_servers natively, and (b) accepts an EXTERNAL wallet's
    # proof JWT — whose `aud` equals the public credential_issuer. Left unset it
    # defaults to the docker-internal host, and every external wallet's proof
    # fails with "invalid_proof: Error encountered during proof jwt parsing"
    # (the aud doesn't match). JWKS stays internal (cluster-local).
    export PREAUTH_PUBLIC_URL=$(url_for inji-certify-preauth "$VERIFIABLY_PUBLIC_HOST" "${INJI_CERTIFY_PREAUTH_PORT:-8094}")
    # PREAUTH_DID_DOMAIN is the host portion of PREAUTH_PUBLIC_URL — it makes the
    # pre-auth instance's issuer DID a PUBLICLY-resolvable did:web at its own
    # subdomain (did:web:inji-certify-preauth.<domain>), instead of the
    # docker-internal did:web:certify-preauth-nginx an external wallet can't
    # resolve. did:web:<host> resolves to https://<host>/.well-known/did.json,
    # which certify-preauth-nginx serves from the verifiably-go pre-auth proxy
    # (the pre-auth backend's own key). This is DELIBERATELY decoupled from
    # ISSUER_DID_DOMAIN (which both Certify instances share): re-pointing the
    # shared var would also move the INTERNAL primary auth-code instance onto
    # this subdomain's did.json — which only carries the pre-auth key — and
    # break the primary's verification. Empty in legacy/port mode → every
    # consumer below falls back to did:web:certify-preauth-nginx (unchanged).
    export PREAUTH_DID_DOMAIN=$(printf '%s' "$PREAUTH_PUBLIC_URL" | sed -E 's#^https?://##; s#[:/].*$##')
  fi

  # CREDEBL pre-flight: generate secrets + write agent runtime env BEFORE
  # docker compose up so the generated config/credebl.env file exists when
  # compose reads it for the CREDEBL service definitions.
  if [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
    bold "▶ Preparing CREDEBL environment"
    ensure_credebl_env
    write_credebl_agent_runtime_env
    # The CREDEBL seed script creates the platform-admin user in Keycloak's
    # credebl-realm. If that realm doesn't exist yet the seed exits 1 and
    # every service that depends on it also fails. Fix: start Keycloak before
    # the full compose up and import the realm so it exists when seed runs.
    bold "▶ Pre-starting Keycloak for CREDEBL realm import"
    compose up -d keycloak
    bold "▶ Importing CREDEBL Keycloak realm (pre-seed)"
    bootstrap_credebl_keycloak_realm \
      || red "  CREDEBL Keycloak realm import failed — seed will likely fail"
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
  # If the project network exists but was created manually (no compose labels),
  # Compose will refuse to use it. Remove it so Compose can recreate it with
  # the correct labels. Safe: only removes when zero containers are attached.
  _net="${COMPOSE_PROJECT}_default"
  if docker network inspect "$_net" >/dev/null 2>&1; then
    _net_label=$(docker network inspect "$_net" \
      --format '{{index .Labels "com.docker.compose.network"}}' 2>/dev/null)
    if [[ -z "$_net_label" ]]; then
      _attached=$(docker network inspect "$_net" \
        --format '{{len .Containers}}' 2>/dev/null || echo "1")
      if [[ "$_attached" == "0" ]]; then
        docker network rm "$_net" 2>/dev/null || true
      else
        echo "ERROR: network $_net has no compose labels and $_attached container(s) attached." >&2
        echo "  Run: docker compose -p ${COMPOSE_PROJECT} down" >&2
        echo "  Then retry: ./deploy.sh up ${scenario}" >&2
        exit 1
      fi
    fi
  fi
  unset _net _net_label _attached

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

  # Idempotent re-init of certify-postgres if its `inji_certify` database is
  # missing. The postgres image only sources `/docker-entrypoint-initdb.d/*`
  # on first startup of a fresh data volume — so if the very first attempt
  # ever crashed mid-init (or someone manually dropped the DB), the next
  # `up inji` would silently leave inji-certify in a CrashLoop with
  # "FATAL: database \"inji_certify\" does not exist". Run init.sh ourselves
  # against an already-running postgres in that case.
  if [[ "$(scenario_services "$scenario" | grep -c '^certify-postgres$' || true)" -gt 0 ]]; then
    if docker inspect certify-postgres --format '{{.State.Status}}' 2>/dev/null | grep -q running; then
      if ! docker exec certify-postgres psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='inji_certify'" 2>/dev/null | grep -q 1; then
        yellow "  certify-postgres missing inji_certify DB — running init.sql"
        DID="did:web:${ISSUER_DID_DOMAIN:-certify-nginx}"
        sed "s|did:web:certify-nginx|${DID}|g" "$SCRIPT_DIR/deploy/compose/stack/inji/certify/init-authcode.sql" \
          | docker exec -i certify-postgres psql -U postgres -v ON_ERROR_STOP=1 >/dev/null \
          && docker restart inji-certify >/dev/null 2>&1 \
          && green "  certify-postgres seeded, inji-certify restarted" \
          || red "  certify init failed — see 'docker exec certify-postgres psql ...'"
      fi
    fi
  fi
  if [[ "$(scenario_services "$scenario" | grep -c '^certify-preauth-postgres$' || true)" -gt 0 ]]; then
    if docker inspect certify-preauth-postgres --format '{{.State.Status}}' 2>/dev/null | grep -q running; then
      if ! docker exec certify-preauth-postgres psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname='inji_certify'" 2>/dev/null | grep -q 1; then
        yellow "  certify-preauth-postgres missing inji_certify DB — running init-preauth.sql"
        DID="did:web:${PREAUTH_DID_DOMAIN:-${ISSUER_DID_DOMAIN:-certify-preauth-nginx}}"
        sed "s|did:web:certify-preauth-nginx|${DID}|g" "$SCRIPT_DIR/deploy/compose/stack/inji/certify/init-preauth.sql" \
          | docker exec -i certify-preauth-postgres psql -U postgres -v ON_ERROR_STOP=1 >/dev/null \
          && docker restart inji-certify-preauth-backend >/dev/null 2>&1 \
          && green "  certify-preauth-postgres seeded, inji-certify-preauth-backend restarted" \
          || red "  certify-preauth init failed — see 'docker exec certify-preauth-postgres psql ...'"
      fi
    fi
  fi

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
      KEYCLOAK_REALM="vcplatform" \
      KEYCLOAK_CLIENT_ID="vcplatform" \
      "$SCRIPT_DIR/scripts/bootstrap-keycloak.sh" \
      || red "  Keycloak bootstrap failed (proceeding — you can re-run it manually)"
  fi

  # WSO2IS is opt-out — common.sh leaves IDP_WSO2IS empty when the operator
  # sets VERIFIABLY_SKIP_WSO2IS=1 (typically to fit the inji stack inside a
  # 4 GiB Docker Desktop allocation, since WSO2IS alone needs ~1.5 GiB).
  if [[ ${#IDP_WSO2IS[@]} -eq 0 ]]; then
    yellow "▶ Skipping WSO2IS bootstrap (VERIFIABLY_SKIP_WSO2IS=$VERIFIABLY_SKIP_WSO2IS)"
  else
    bold "▶ Bootstrapping WSO2IS OIDC client"
    PUBLIC_HOST="$VERIFIABLY_PUBLIC_HOST" \
      VERIFIABLY_HOST_PORT="$VERIFIABLY_HOST_PORT" \
      VERIFIABLY_CALLBACK_URL="$_verifiably_callback" \
      "$SCRIPT_DIR/scripts/bootstrap-wso2is.sh" || red "  WSO2IS bootstrap failed (proceeding — you can re-run it manually)"
  fi
  # Re-generate auth-providers.json now that wso2is.env exists (or doesn't,
  # if we skipped), so the provider list reflects the current IdP set.
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

  # Bootstrap CREDEBL: apply patches and provision shared agent.
  # Keycloak realm import already ran before compose up (see pre-seed block above).
  if [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
    bold "▶ Applying CREDEBL container patches"
    apply_credebl_patches \
      || red "  CREDEBL patch application failed (proceeding — some features may not work)"

    bold "▶ Provisioning CREDEBL platform-admin shared agent"
    ensure_credebl_platform_admin_shared_agent \
      || red "  CREDEBL shared agent provisioning failed (proceeding — re-run manually)"

    # Credo container only exists after provisioning — apply patches now
    echo -n "  Patching Credo CredentialEvents: "
    _credebl_patch_credo_credential_events
    echo -n "  Patching Credo ProofEvents: "
    _credebl_patch_credo_proof_events

    bold "▶ Configuring CREDEBL OID4VCI nginx rewriter"
    _credebl_configure_oid4vci_rewriter \
      || red "  OID4VCI rewriter config failed — credential offer downloads will 502"

    bold "▶ Setting up CREDEBL platform-admin tenant wallet"
    ensure_credebl_platform_admin_tenant \
      || red "  CREDEBL tenant wallet setup failed (proceeding — re-run manually)"

    bold "▶ Provisioning CREDEBL OID4VCI issuer + credential template"
    ensure_credebl_oid4vc_issuer \
      || red "  CREDEBL OID4VCI issuer setup failed (proceeding — re-run manually)"

    # Re-export did:web DID document now that orgDid may have just been created.
    # The first _credebl_configure_oid4vci_rewriter call (above) ran before the
    # DID existed; this second call picks up the newly created did:web.
    bold "▶ Exporting CREDEBL did:web DID document"
    _credebl_configure_oid4vci_rewriter \
      || true

    # Re-attach the openid/profile/email login scopes to credebl-client. The
    # pre-seed realm import set them, but CREDEBL's seed re-imports the realm
    # and resets credebl-client to openid-only — which makes the Keycloak login
    # tile fail with invalid_scope (verifiably-go requests openid+profile+email).
    # Runs last so it isn't clobbered. Idempotent.
    bold "▶ Re-attaching Keycloak login scopes (post-seed)"
    ensure_credebl_keycloak_login_scopes \
      || red "  Keycloak login-scope re-attach failed (login may hit invalid_scope — re-run manually)"

    # Re-generate backends.json now that CREDEBL_ISSUER_ID is known.
    # The first call (top of cmd_up) runs before provisioning, so issuerId=""
    # there. This second call writes the final correct value.
    backends_for "$scenario"
  fi

  # Set up did:web for the walt.id issuer when running in domain mode.
  # Skipped for CREDEBL-only scenarios and for localhost / IP deployments.
  if [[ -n "${VERIFIABLY_PUBLIC_DOMAIN:-}" ]] && \
     [[ "$scenario" == "waltid" || "$scenario" == "all" ]]; then
    bold "▶ Setting up Walt.id did:web"
    bootstrap_waltid_did_web \
      || red "  Walt.id did:web setup failed (proceeding — issuer will use did:key)"
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
  docker build --progress=plain \
    --build-arg GIT_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || date +%s)" \
    -t "$VERIFIABLY_IMAGE" "$SCRIPT_DIR"

  bold "▶ Starting verifiably-go container"
  start_container "$scenario"
  echo "    point your browser at $VERIFIABLY_PUBLIC_URL"
  verify_oidc_discovery
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
  local want
  want="$(url_for inji-web "${VERIFIABLY_PUBLIC_HOST:-$public_host}" "${INJIWEB_UI_PUBLIC_PORT:-3004}")/redirect"
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

cmd_setup() {
  local env_file="$SCRIPT_DIR/.env"
  bold "▶ verifiably-go setup wizard"
  echo
  echo "  This writes ${env_file} with the settings for your deployment."
  echo "  Press Enter to keep the value shown in [brackets]."
  echo

  # ── Host / IP ─────────────────────────────────────────────────────────────
  # VERIFIABLY_PUBLIC_HOST must always be an IP address — Docker containers
  # route back to the host via this IP. A domain name here breaks internal
  # agent networking. Put the domain in the HTTPS question below.
  local _default_host="${VERIFIABLY_PUBLIC_HOST:-localhost}"
  # Suggest the current LAN IP when the stored value is still a placeholder.
  if [[ "$_default_host" == "localhost" ]] || [[ ! "$_default_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    _default_host=$(ip route get 1 2>/dev/null | awk '{print $NF; exit}' || hostname -I 2>/dev/null | awk '{print $1}' || echo "${VERIFIABLY_PUBLIC_HOST:-localhost}")
  fi
  printf "  Server IP address (must be an IPv4, e.g. 10.0.0.1) [%s]: " "$_default_host"
  local _host
  read -r _host
  _host="${_host:-$_default_host}"
  if [[ ! "$_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ "$_host" != "localhost" ]]; then
    yellow "  WARNING: '${_host}' does not look like an IP address."
    yellow "  Docker agent networking requires an IP — enter the IP on the next run if things fail."
  fi

  # ── Domain mode ───────────────────────────────────────────────────────────
  local _default_domain_yn="N"
  [[ -n "${VERIFIABLY_PUBLIC_DOMAIN:-}" ]] && _default_domain_yn="Y"

  printf "  Enable HTTPS via Let's Encrypt? (needs DNS *.domain pointing here + ports 80/443 open) [%s]: " "$_default_domain_yn"
  local _domain_yn
  read -r _domain_yn
  _domain_yn="${_domain_yn:-$_default_domain_yn}"

  local _domain="" _le_email="" _hosts_pattern=""
  if [[ "${_domain_yn,,}" == y* ]]; then
    # Infer the base domain from the host when possible:
    #   verifiably.ysalabs.work → ysalabs.work  (strip first label of a subdomain)
    #   ysalabs.work            → ysalabs.work  (already a base domain)
    local _inferred_domain=""
    if [[ "$_host" == *.*.* ]]; then
      _inferred_domain="${_host#*.}"
    elif [[ "$_host" == *.* ]]; then
      _inferred_domain="$_host"
    fi
    local _default_domain="${VERIFIABLY_PUBLIC_DOMAIN:-$_inferred_domain}"
    printf "  Base domain for subdomains (e.g. ysalabs.work) [%s]: " "$_default_domain"
    local _domain_input
    read -r _domain_input
    _domain="${_domain_input:-$_default_domain}"

    if [[ -z "$_domain" ]]; then
      yellow "  WARNING: no domain entered — domain mode disabled."
    else
      local _default_le_email="${VERIFIABLY_LE_EMAIL:-}"
      printf "  Let's Encrypt email (for TLS certificates) [%s]: " "$_default_le_email"
      local _le_input
      read -r _le_input
      _le_email="${_le_input:-$_default_le_email}"

      _hosts_pattern="https://%s.${_domain}"

      echo
      yellow "  Subdomains that will be created:"
      for _svc in verifiably keycloak credebl walt-issuer walt-wallet walt-verifier; do
        printf "    https://%s.%s\n" "$_svc" "$_domain"
      done
      echo "  (plus inji-*, esignet, mimoto, wso2 when those scenarios are active)"
    fi
  fi

  # ── Keycloak ──────────────────────────────────────────────────────────────
  local _default_kc_pass="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
  printf "  Keycloak admin password [%s]: " "$_default_kc_pass"
  local _kc_pass
  read -r _kc_pass
  _kc_pass="${_kc_pass:-$_default_kc_pass}"

  # ── CREDEBL ───────────────────────────────────────────────────────────────
  local _default_credebl_email="${CREDEBL_ADMIN_EMAIL:-admin@cdpi.dev}"
  printf "  CREDEBL platform admin email [%s]: " "$_default_credebl_email"
  local _credebl_email
  read -r _credebl_email
  _credebl_email="${_credebl_email:-$_default_credebl_email}"

  # ── Write .env ────────────────────────────────────────────────────────────
  echo
  bold "  Writing ${env_file}"
  {
    printf '# Generated by ./deploy.sh setup on %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '# Edit manually or re-run '\''./deploy.sh setup'\'' to change settings.\n\n'

    printf 'VERIFIABLY_PUBLIC_HOST=%s\n' "$_host"
    printf 'PUBLIC_HOST=%s\n\n' "$_host"

    if [[ -n "$_domain" ]]; then
      printf 'VERIFIABLY_PUBLIC_DOMAIN=%s\n' "$_domain"
      printf 'VERIFIABLY_HOSTS_PATTERN=%s\n' "$_hosts_pattern"
      printf 'VERIFIABLY_LE_EMAIL=%s\n\n' "$_le_email"
    fi

    printf 'KEYCLOAK_ADMIN_USER=admin\n'
    printf 'KEYCLOAK_ADMIN_PASSWORD=%s\n\n' "$_kc_pass"

    printf 'CREDEBL_ADMIN_EMAIL=%s\n' "$_credebl_email"
  } > "$env_file"

  # ── Sync deploy/compose/stack/.env ────────────────────────────────────────
  # render-config.sh sources stack/.env directly for Inji/mimoto URL rendering,
  # and docker compose falls back to it when run without --env-file.
  # Keep the shared vars in sync so both paths produce the same result.
  local _stack_env="$SCRIPT_DIR/deploy/compose/stack/.env"
  if [[ -f "$_stack_env" ]]; then
    bold "  Syncing $_stack_env"
    set_env_var "$_stack_env" "PUBLIC_HOST"               "$_host"
    set_env_var "$_stack_env" "VERIFIABLY_PUBLIC_HOST"    "$_host"
    if [[ -n "$_domain" ]]; then
      set_env_var "$_stack_env" "VERIFIABLY_PUBLIC_DOMAIN"  "$_domain"
      set_env_var "$_stack_env" "VERIFIABLY_HOSTS_PATTERN"  "$_hosts_pattern"
      set_env_var "$_stack_env" "VERIFIABLY_LE_EMAIL"       "$_le_email"
    else
      # Remove domain vars if domain mode was disabled
      sed -i '/^VERIFIABLY_PUBLIC_DOMAIN=/d;/^VERIFIABLY_HOSTS_PATTERN=/d;/^VERIFIABLY_LE_EMAIL=/d' "$_stack_env" 2>/dev/null || true
    fi
  fi

  if [[ -n "$_domain" ]]; then
    green "  Done — domain mode enabled."
    echo "  Make sure DNS *.${_domain} points to ${_host} and run './deploy.sh up <scenario>'."
  else
    green "  Done — run './deploy.sh up <scenario>' to start the stack."
  fi
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
  echo "    waltid_credebl_postgres_data / _redis_data / _nats_data / _minio_data (CREDEBL)"
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
  compose --profile injiweb --profile credebl down -v 2>&1 | tail -10
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
  docker build --progress=plain \
    --build-arg GIT_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || date +%s)" \
    -t "$VERIFIABLY_IMAGE" "$SCRIPT_DIR"
  start_container "$scenario"
  echo "    point your browser at $VERIFIABLY_PUBLIC_URL"
  verify_oidc_discovery
}

# ---------------------------------------------------------------- helpers

# verify_oidc_discovery — post-up smoke gate for the login flow. For every OIDC
# provider in the generated config it drives verifiably-go's OWN /auth/start
# from the host and checks two things that otherwise stay invisible (the deploy
# exits 0 and only a browser click reveals them):
#
#   1. /auth/start produces an authorize redirect — proving the container's
#      server-side OIDC discovery reached the IdP. Catches the subdomain
#      hairpin-NAT regression (discover ...: context deadline exceeded).
#   2. Following that authorize URL one hop does NOT bounce back to the callback
#      with error=invalid_scope / invalid_client / unauthorized_client. Catches
#      the Keycloak credebl-client scope regression (and similar IdP misconfig).
#
# Best-effort by default (red on failure, like the other bootstraps); set
# VERIFIABLY_STRICT_VERIFY=1 to make a failure abort the deploy (use in CI).
verify_oidc_discovery() {
  local base="${VERIFIABLY_PUBLIC_URL%/}"
  local cfg="$SCRIPT_DIR/config/auth-providers.system.json"
  [[ -f "$cfg" ]] || { yellow "  discovery gate: no provider config — skip"; return 0; }
  local ids
  ids=$(python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
ps=d if isinstance(d,list) else d.get("providers",[])
print("\n".join(p["id"] for p in ps if p.get("type")=="oidc"))' "$cfg" 2>/dev/null) || true
  [[ -n "$ids" ]] || { yellow "  discovery gate: no OIDC providers — skip"; return 0; }

  bold "▶ Verifying OIDC login (discovery + authorize)"
  # Wait for the app to answer before probing (it was just (re)started).
  local _t=0
  while ! curl -sk --max-time 5 -o /dev/null "$base/" 2>/dev/null; do
    _t=$((_t + 2)); [[ $_t -ge 30 ]] && break; sleep 2
  done

  local jar rc=0 id
  jar="$(mktemp)"
  for id in $ids; do
    : > "$jar"
    curl -sk -c "$jar" -b "$jar" --max-time 15 -o /dev/null "$base/" || true
    curl -sk -c "$jar" -b "$jar" --max-time 15 -o /dev/null -X POST "$base/role" --data 'role=issuer' || true
    local hdrs authz
    hdrs=$(curl -sk -c "$jar" -b "$jar" --max-time 30 -D - -o /dev/null \
      -H 'HX-Request: true' -X POST "$base/auth/start" --data "provider=$id" 2>/dev/null) || true
    authz=$(printf '%s' "$hdrs" | grep -iE '^(location|hx-redirect):' | head -1 | sed -E 's/^[^:]+:[[:space:]]*//' | tr -d '\r') || true
    if [[ -z "$authz" || "$authz" != *"://"* ]]; then
      red "  discovery gate: '$id' — /auth/start did not redirect to the IdP (server-side discovery failed: hairpin NAT? cert? upstream down?)"
      rc=1; continue
    fi
    local az_loc
    az_loc=$(curl -sk --max-time 20 -D - -o /dev/null "$authz" 2>/dev/null | grep -iE '^location:' | head -1 | tr -d '\r') || true
    if printf '%s' "$az_loc" | grep -qiE 'error=(invalid_scope|invalid_request|invalid_client|unauthorized_client|access_denied)'; then
      red "  discovery gate: '$id' — authorize rejected the request (${az_loc#*error=}); scope/client misconfig at the IdP"
      rc=1; continue
    fi
    green "  discovery gate: '$id' OK (discovery + authorize accepted)"
  done
  rm -f "$jar"
  if [[ "$rc" -ne 0 ]]; then
    if [[ "${VERIFIABLY_STRICT_VERIFY:-}" == "1" ]]; then
      red "  discovery gate FAILED (VERIFIABLY_STRICT_VERIFY=1) — aborting deploy."
      return 1
    fi
    yellow "  discovery gate found problems above — login may fail. (set VERIFIABLY_STRICT_VERIFY=1 to make this fatal)"
  fi
  return 0
}

# wait_for_services polls the TCP ports each scenario needs to be healthy
# before verifiably-go starts. Bounded — we don't block forever if a service
# is struggling; the app itself surfaces the failure on first use.
wait_for_services() {
  local scenario="$1"
  # Both IdPs (Keycloak 8180, WSO2IS 9443) + the translator (5000) are
  # always in scope because every scenario includes them. DPG-specific
  # ports gate on scenario. WSO2IS is dropped when IDP_WSO2IS is empty
  # (VERIFIABLY_SKIP_WSO2IS=1) so we don't waste 60s waiting for a
  # service that's intentionally not running.
  local -a ports=( 8180 5000 )
  if [[ ${#IDP_WSO2IS[@]} -gt 0 ]]; then
    ports+=( 9443 )
  fi
  case "$scenario" in
    all|waltid)    ports+=( 7001 7002 7003 );;
  esac
  case "$scenario" in
    all|inji)      ports+=( 8082 8088 8091 8094 );;
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

# ---------------------------------------------------------------- hub subcommands
# The Hub is a separate compose project (deploy/compose/hub/) — it does NOT
# share the DPG compose stack. These functions are the single entry point for
# Hub lifecycle operations.

HUB_COMPOSE_FILE="$SCRIPT_DIR/deploy/compose/hub/docker-compose.yml"
HUB_ENV_FILE="$SCRIPT_DIR/deploy/compose/hub/.env"

hub_compose() {
  # Run from inside the hub compose directory. Export hub .env variables in the
  # subshell BEFORE calling docker compose so they override any conflicting vars
  # that common.sh exported from the DPG .env.example (e.g. VERIFIABLY_PUBLIC_DOMAIN
  # exported as empty by the DPG setup takes precedence over the hub .env file value
  # because shell env vars win over .env file lookups in Docker Compose v2).
  local compose_dir
  compose_dir="$(dirname "$HUB_COMPOSE_FILE")"
  (
    cd "$compose_dir"
    if [[ -f .env ]]; then
      set -o allexport
      # shellcheck disable=SC1091
      source .env
      set +o allexport
    fi
    docker compose -f "$(basename "$HUB_COMPOSE_FILE")" "$@"
  )
}

# ensure_hub_signing_key generates an ECDSA P-256 PEM key at
# config/trust-signing-key.pem when one doesn't exist yet. Idempotent.
ensure_hub_signing_key() {
  local key_path="$SCRIPT_DIR/config/trust-signing-key.pem"
  if [[ -f "$key_path" ]]; then
    green "  signing key: config/trust-signing-key.pem (existing)"
    return 0
  fi
  require openssl
  bold "  Generating ES256 signing key → config/trust-signing-key.pem"
  openssl ecparam -name prime256v1 -genkey -noout -out /tmp/_hub_ec_raw.pem 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in /tmp/_hub_ec_raw.pem -out "$key_path" 2>/dev/null
  rm -f /tmp/_hub_ec_raw.pem
  green "  signing key: config/trust-signing-key.pem (generated)"
}

# ensure_hub_env copies .env.example → .env when missing, auto-generates
# POSTGRES_PASSWORD + VERIFIABLY_SESSION_SECRET, and prompts for the
# values an operator must set (public URL, admin password, grafana password).
ensure_hub_env() {
  if [[ -f "$HUB_ENV_FILE" ]]; then
    green "  hub env: deploy/compose/hub/.env (existing)"
    return 0
  fi
  bold "  Creating deploy/compose/hub/.env from template"
  cp "$SCRIPT_DIR/deploy/compose/hub/.env.example" "$HUB_ENV_FILE"

  # The signing key is loaded by the server directly from
  # config/trust-signing-key.pem (mounted at /app/config/ in the container).
  # No injection into .env needed — Docker Compose .env can't carry multiline PEM.

  # Auto-generate secrets.
  local pg_pass session_secret
  pg_pass=$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | base64 | tr -d '/+=\n')
  session_secret=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -d '/+=\n')
  set_env_var "$HUB_ENV_FILE" "POSTGRES_PASSWORD"          "$pg_pass"
  set_env_var "$HUB_ENV_FILE" "VERIFIABLY_SESSION_SECRET"  "$session_secret"

  # Prompt for operator-specific values.
  local public_url admin_pass grafana_pass
  printf "  Hub public URL [http://localhost:8080]: "
  read -r public_url
  public_url="${public_url:-http://localhost:8080}"
  set_env_var "$HUB_ENV_FILE" "VERIFIABLY_PUBLIC_URL" "$public_url"

  printf "  Admin password [admin]: "
  read -r -s admin_pass; echo
  admin_pass="${admin_pass:-admin}"
  set_env_var "$HUB_ENV_FILE" "VERIFIABLY_ADMIN_PASSWORD" "$admin_pass"

  printf "  Grafana password [admin]: "
  read -r -s grafana_pass; echo
  grafana_pass="${grafana_pass:-admin}"
  set_env_var "$HUB_ENV_FILE" "GRAFANA_PASSWORD" "$grafana_pass"

  # Optional: production TLS via Caddy (tls compose profile).
  local hub_domain le_email
  printf "  Public domain for TLS (e.g. verify.cdpi.dev — leave blank for localhost): "
  read -r hub_domain
  if [[ -n "$hub_domain" ]]; then
    set_env_var "$HUB_ENV_FILE" "VERIFIABLY_PUBLIC_DOMAIN" "$hub_domain"
    # VERIFIABLY_PUBLIC_URL should use https when a domain is set.
    set_env_var "$HUB_ENV_FILE" "VERIFIABLY_PUBLIC_URL" "https://${hub_domain}"
    printf "  Let's Encrypt email: "
    read -r le_email
    set_env_var "$HUB_ENV_FILE" "VERIFIABLY_LE_EMAIL" "${le_email}"
    # In TLS mode Grafana is served at grafana.<domain> via Caddy.
    set_env_var "$HUB_ENV_FILE" "GRAFANA_EXTERNAL_URL" "https://grafana.${hub_domain}"
  fi

  green "  hub env: deploy/compose/hub/.env (created)"
}

# ensure_hub_targets runs the federation Prometheus target generator. Safe to
# re-run at every 'up' — the output file is overwritten atomically by jq.
ensure_hub_targets() {
  local gen="$SCRIPT_DIR/deploy/compose/monitoring/generate-federation-prometheus.sh"
  local targets="$SCRIPT_DIR/deploy/compose/hub/federation-targets.json"
  local fed="$SCRIPT_DIR/config/federation.json"
  if [[ ! -x "$gen" ]]; then
    yellow "  skipping target gen (script not found: $gen)"
    return 0
  fi
  if [[ ! -f "$fed" ]]; then
    yellow "  skipping target gen (federation.json not found — using empty targets)"
    printf '[]' > "$targets"
    return 0
  fi
  bash "$gen" "$fed" "$targets" || yellow "  target generation warning — check output above"
}

cmd_up_hub() {
  require docker

  bold "▶ Hub: verifying prerequisites"
  ensure_hub_signing_key
  ensure_hub_env

  bold "▶ Hub: generating Prometheus federation targets"
  ensure_hub_targets

  # Read VERIFIABLY_IMAGE from hub .env (or fall back to the default tag).
  local hub_image="verifiably/verifiably-go:latest"
  if [[ -f "$HUB_ENV_FILE" ]]; then
    local _img
    _img=$(grep -E '^VERIFIABLY_IMAGE=' "$HUB_ENV_FILE" | cut -d= -f2- | tr -d '"' || true)
    [[ -n "$_img" ]] && hub_image="$_img"
  fi

  bold "▶ Hub: building image ($hub_image)"
  docker build --progress=plain \
    --build-arg GIT_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || date +%s)" \
    -t "$hub_image" "$SCRIPT_DIR"

  # Read VERIFIABLY_PUBLIC_DOMAIN from hub .env to decide whether to activate
  # the tls compose profile (which brings up Caddy with Let's Encrypt).
  #
  # Reserved/test TLDs (RFC 2606 .test/.example/.invalid/.localhost + mDNS
  # .local) cannot get a public certificate, so activating Caddy against
  # them produces useless Let's Encrypt traffic. Skip the tls profile and
  # warn rather than letting Caddy hammer the LE ACME endpoint.
  local hub_domain=""
  hub_domain=$(grep -E '^VERIFIABLY_PUBLIC_DOMAIN=' "$HUB_ENV_FILE" 2>/dev/null \
    | cut -d= -f2- | tr -d '"' || true)
  local tls_eligible="no"
  if [[ -n "$hub_domain" ]]; then
    case "$hub_domain" in
      *.test|*.example|*.invalid|*.localhost|*.local|localhost)
        yellow "  VERIFIABLY_PUBLIC_DOMAIN='${hub_domain}' uses a reserved TLD — skipping TLS profile."
        yellow "  Set a publicly-resolvable domain to enable Caddy + Let's Encrypt."
        ;;
      *)
        tls_eligible="yes"
        ;;
    esac
  fi

  local profile_args=()
  if [[ "$tls_eligible" == "yes" ]]; then
    profile_args+=( --profile tls )
    bold "▶ Hub: starting stack with TLS (Caddy + Let's Encrypt) for ${hub_domain}"
  else
    bold "▶ Hub: starting stack (postgres + verifiably-go + prometheus + grafana)"
  fi
  hub_compose "${profile_args[@]}" up -d

  # Read ports for the summary (fall back to defaults from .env.example).
  local hub_port prom_port grafana_port grafana_ext
  hub_port=$(grep -E '^HUB_PORT=' "$HUB_ENV_FILE" 2>/dev/null | cut -d= -f2 || echo 8080)
  # PROMETHEUS_PORT may include a bind address (e.g. 127.0.0.1:9090); extract just the port.
  prom_port=$(grep -E '^PROMETHEUS_PORT=' "$HUB_ENV_FILE" 2>/dev/null | cut -d= -f2 | cut -d: -f2 || echo 9090)
  grafana_port=$(grep -E '^GRAFANA_PORT=' "$HUB_ENV_FILE" 2>/dev/null | cut -d= -f2 || echo 3100)
  grafana_ext=$(grep -E '^GRAFANA_EXTERNAL_URL=' "$HUB_ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)
  hub_port="${hub_port:-8080}"
  prom_port="${prom_port:-9090}"
  grafana_port="${grafana_port:-3100}"

  echo
  green "  Hub is up."
  if [[ "$tls_eligible" == "yes" ]]; then
    echo "    Hub:        https://${hub_domain}"
    echo "    Admin:      https://admin.${hub_domain}/admin/login"
    echo "    Grafana:    https://grafana.${hub_domain}  (admin / <GRAFANA_PASSWORD>)"
    echo "    Prometheus: http://localhost:${prom_port}  (loopback only)"
    yellow "  Caddy is acquiring Let's Encrypt certificates — first request may be slow."
  else
    echo "    Hub:        http://localhost:${hub_port}"
    echo "    Admin:      http://localhost:${hub_port}/admin/login"
    echo "    Prometheus: http://localhost:${prom_port}"
    echo "    Grafana:    ${grafana_ext:-http://localhost:${grafana_port}}  (admin / <GRAFANA_PASSWORD>)"
  fi
}

cmd_down_hub() {
  bold "▶ Hub: stopping stack"
  hub_compose down
  green "  Hub stopped."
}

cmd_run_hub() {
  require docker
  ensure_hub_env

  local hub_image="verifiably/verifiably-go:latest"
  if [[ -f "$HUB_ENV_FILE" ]]; then
    local _img
    _img=$(grep -E '^VERIFIABLY_IMAGE=' "$HUB_ENV_FILE" | cut -d= -f2- | tr -d '"' || true)
    [[ -n "$_img" ]] && hub_image="$_img"
  fi

  bold "▶ Hub: rebuilding image ($hub_image)"
  docker build --progress=plain \
    --build-arg GIT_COMMIT="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || date +%s)" \
    -t "$hub_image" "$SCRIPT_DIR"

  bold "▶ Hub: restarting verifiably-go container"
  hub_compose up -d --no-deps --force-recreate verifiably-go
  green "  verifiably-go (hub) restarted."
}

# ---------------------------------------------------------------- main

usage() {
  cat >&2 <<EOF
usage: deploy.sh <command> [scenario]

commands:
  setup                            interactive wizard — writes .env with your host/IP,
                                   Keycloak admin password, and CREDEBL email. Auto-runs
                                   on first 'up' if .env does not exist.
  up <all|waltid|inji|credebl>     start compose services + build & run verifiably-go container
  up hub                           start the Hub stack (Trust Registry + /verify + Prometheus + Grafana)
                                   generates signing key + .env on first run; idempotent
  down [all|waltid|inji|credebl]   stop DPG services (default: all)
  down hub                         stop the Hub stack
  run <all|waltid|inji|credebl>    rebuild + restart only the verifiably-go container
                                   (use when the DPG stack is already up)
  run hub                          rebuild verifiably-go image and restart the Hub container
  config <all|waltid|inji|credebl> print the backends.json that would be generated
  status                           summarise what's running
  reset                            wipe every waltid_* named volume — fixes keystore/DB
                                   desync ("KER-KMA-004 No such alias: ..."). DESTRUCTIVE;
                                   asks for explicit 'RESET' confirmation.

scenarios:
  hub      central Hub — Trust Registry (JWT ES256) + /verify portal + Schema Registry +
           Prometheus + Grafana. Separate compose project (deploy/compose/hub/).
           Signing key + .env generated automatically on first run.
  all      every DPG + both IdPs + LibreTranslate
           (includes compose-managed CREDEBL unless CREDEBL_API_URL is set;
            secrets are auto-generated on first run)
  waltid   walt.id stack + Keycloak + LibreTranslate
  inji     Inji Certify (×2) + Inji Verify + Inji Web + WSO2IS + LibreTranslate
  credebl  all CREDEBL services (compose-managed) + Keycloak + WSO2IS + LibreTranslate
           secrets are auto-generated if not set in .env
           to use external CREDEBL instead: set CREDEBL_API_URL, CREDEBL_EMAIL,
           CREDEBL_PASSWORD, CREDEBL_CRYPTO_PRIVATE_KEY, CREDEBL_ORG_ID, CREDEBL_ISSUER_ID
           (but compose-managed CREDEBL is preferred for local dev)

DPG scenarios include a containerised verifiably-go on port $VERIFIABLY_HOST_PORT,
attached to the compose network (${COMPOSE_PROJECT}_default).
EOF
}

main() {
  local cmd="${1:-}"
  local scenario="${2:-}"
  case "$cmd" in
    up)
      shift
      if [[ "${1:-}" == "hub" ]]; then cmd_up_hub; else cmd_up "$@"; fi;;
    down)
      shift
      if [[ "${1:-}" == "hub" ]]; then cmd_down_hub; else cmd_down "$@"; fi;;
    run)
      shift
      if [[ "${1:-}" == "hub" ]]; then cmd_run_hub; else cmd_run "$@"; fi;;
    reset)   cmd_reset;;
    setup)   cmd_setup;;
    status)  cmd_status;;
    config)  shift; cmd_config "$@";;
    help|-h|--help|"") usage;;
    *)       red "unknown command: $cmd"; usage; exit 2;;
  esac
}

main "$@"
