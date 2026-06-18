#!/usr/bin/env bash
# gen-backends.sh — backends_for() and auth_providers_for() template renderers.
# Sourced by deploy.sh. Can also be sourced standalone after common.sh.
[[ "${_VERIFIABLY_COMMON_LOADED:-}" == "1" ]] || source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/common.sh"
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
  # did_url written into new custom credential_config rows (db.go SaveCustomSchema).
  # In subdomain mode (url_for returns https://<host>) use the instance's own
  # public host so the issued VC's issuer/proof verificationMethod is a
  # publicly-resolvable did:web — matching the backend's CERTIFY_ISSUER_DID and
  # the seeded rows (deploy.sh PREAUTH_DID_DOMAIN / init-preauth.sh). In legacy
  # port mode keep the docker-internal did:web:certify-preauth-nginx.
  local certify_preauth_did
  if [[ "$certify_preauth_url" =~ ^https:// ]]; then
    certify_preauth_did="did:web:$(printf '%s' "$certify_preauth_url" | sed -E 's#^https?://##; s#[:/].*$##')"
  else
    certify_preauth_did="did:web:certify-preauth-nginx"
  fi
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
        "offerIssuerUrl": "http://inji-certify-preauth:8090",
        "db": {
          "dsn": "postgres://postgres:postgres@certify-preauth-postgres:5432/inji_certify?sslmode=disable",
          "didUrl": "${certify_preauth_did}",
          "scope": "mock_identity_vc_ldp"
        }
      }
    }
JSON
)
  local _inji_verify_did
  _inji_verify_did=$(python3 -c "
from urllib.parse import urlparse
h = urlparse('${inji_verify_svc_url}').hostname or 'inji-verify.${VERIFIABLY_PUBLIC_HOST}'
print('did:web:' + h + ':v1:verify')
" 2>/dev/null) || _inji_verify_did="did:web:injiverify.dev.mosip.net:v1:verify"
  local inji_verify_stanza
  inji_verify_stanza=$(cat <<JSON
    {
      "vendor": "Inji Verify",
      "type": "inji_verify",
      "roles": ["verifier"],
      "dpg": {
        "Vendor": "Inji Verify",
        "Version": "v0.16.0",
        "Tag": "API-based",
        "Tagline": "MOSIP verifier — OID4VP presentation requests generated inline in Verifiably, plus direct paste/upload verification.",
        "FlowPlain": "Verifiably generates the openid4vp:// request from your custom schema and shows a QR; the holder scans with any OID4VC wallet. Direct verification (paste/upload) also supported.",
        "Formats": ["w3c_vcdm_1", "w3c_vcdm_2", "sd_jwt_vc (IETF)"],
        "Caveats": "INJIVER-1131: v0.16.0 cross-device flow can accept a wrong VC as valid — adapter applies a field-match guard.",
        "Capabilities": [
          {"Kind": "flow",       "Key": "oid4vp",        "Title": "OID4VP inline",             "Body": "Verifiably builds the Presentation Definition from your schema and calls Inji Verify's /v1/verify/vp-request. QR shown here."},
          {"Kind": "flow",       "Key": "direct_paste",  "Title": "Paste JSON-LD VC",          "Body": "POST /v1/verify/vc-verification returns SUCCESS/INVALID synchronously."},
          {"Kind": "flow",       "Key": "direct_upload", "Title": "Upload a QR image",         "Body": "Server decodes the QR with gozxing, then verifies the payload."},
          {"Kind": "limitation", "Key": "injiver_1131",  "Title": "INJIVER-1131 guard applied", "Body": "Adapter re-checks claims against requested fields."}
        ]
      },
      "config": {
        "baseUrl": "${inji_verify_svc_url}",
        "internalBaseUrl": "http://inji-verify-service:8080",
        "clientId": "${_inji_verify_did}"
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
    # External CREDEBL — credentials come from env vars (passed to container
    # via -e flags in start_container); do NOT embed them in the JSON file.
    _credebl_url="$CREDEBL_API_URL"
    _credebl_email=""
    _credebl_password=""
    _credebl_crypto_key=""
    _credebl_org_id="$CREDEBL_ORG_ID"
    _credebl_issuer_id="$CREDEBL_ISSUER_ID"
    _credebl_verifier_id="$CREDEBL_VERIFIER_ID"
    _credebl_internal_base_url="$CREDEBL_INTERNAL_BASE_URL"
  elif [[ "$(scenario_needs_credebl "$scenario")" == "yes" ]]; then
    # Compose-managed CREDEBL — use well-known defaults.
    # Credentials are exported as env vars so start_container can pass
    # them via -e flags; the JSON stanza stays credential-free.
    _credebl_url=$(url_for credebl "$VERIFIABLY_PUBLIC_HOST" "$CREDEBL_API_PORT")
    _credebl_email=""
    _credebl_password=""
    _credebl_crypto_key=""
    # Export so the docker run -e flags below can pick them up.
    CREDEBL_EMAIL="${CREDEBL_EMAIL:-${CREDEBL_ADMIN_EMAIL}}"
    CREDEBL_PASSWORD="${CREDEBL_PASSWORD:-changeme}"
    CREDEBL_CRYPTO_PRIVATE_KEY="${CREDEBL_CRYPTO_PRIVATE_KEY:-cdpi-poc-crypto-key-change-me}"
    # Auto-detect org UUID from compose-managed postgres (set after provisioning)
    _credebl_org_id="${CREDEBL_ORG_ID:-}"
    if [[ -z "$_credebl_org_id" ]] && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^credebl-postgres$'; then
      _credebl_org_id="$(docker exec -i credebl-postgres sh -c \
        'PGPASSWORD="$POSTGRES_PASSWORD" psql -U credebl -d credebl -Atqc "SELECT id FROM organisation WHERE name='"'"'Platform-admin'"'"' LIMIT 1;"' \
        2>/dev/null | tr -d '\r')"
    fi
    # Auto-detect issuer UUID from DB (populated by ensure_credebl_oid4vc_issuer)
    _credebl_issuer_id="${CREDEBL_ISSUER_ID:-}"
    if [[ -z "$_credebl_issuer_id" ]] && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^credebl-postgres$'; then
      _credebl_issuer_id="$(docker exec -i credebl-postgres sh -c \
        'PGPASSWORD="$POSTGRES_PASSWORD" psql -U credebl -d credebl -Atqc "SELECT id FROM oidc_issuer WHERE \"orgId\"=(SELECT id FROM organisation WHERE name='"'"'Platform-admin'"'"' LIMIT 1) LIMIT 1;"' \
        2>/dev/null | tr -d '\r')"
    fi
    _credebl_verifier_id=""
    # The Credo agent controller embeds AGENT_HTTP_URL (bare server IP) in
    # credential offer URIs.  Set internalBaseUrl to that same value so the
    # rewritePublic() call in the adapter rewrites it to the public domain URL.
    _credebl_internal_base_url="http://${VERIFIABLY_PUBLIC_HOST}"
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
  local scenario="$1"
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
    # CREDEBL scenarios use a dedicated realm (credebl-realm / credebl-client).
    # If KEYCLOAK_REALM is still the non-CREDEBL default ("vcplatform"), switch
    # automatically when the scenario includes CREDEBL. An operator who explicitly
    # sets KEYCLOAK_REALM to something other than "vcplatform" keeps their value.
    local _kc_realm="${KEYCLOAK_REALM}"
    local _kc_client="${KEYCLOAK_CLIENT_ID}"
    if [[ "$(scenario_needs_credebl "$scenario")" == "yes" && "$_kc_realm" == "vcplatform" ]]; then
      _kc_realm="credebl-realm"
      [[ "$_kc_client" == "vcplatform" ]] && _kc_client="credebl-client"
    fi
    keycloak_issuer="$(url_for keycloak "$VERIFIABLY_PUBLIC_HOST" "$KEYCLOAK_PORT")/realms/${_kc_realm}"
    keycloak_client_id="${_kc_client}"
    # credebl-client is confidential — include the secret so the token exchange succeeds.
    keycloak_client_secret_kv=""
    if [[ "$_kc_realm" == "credebl-realm" ]]; then
      local _credebl_env="$SCRIPT_DIR/deploy/compose/credebl/config/credebl.env"
      local _credebl_kc_secret="${CREDEBL_KEYCLOAK_CLIENT_SECRET:-}"
      if [[ -z "$_credebl_kc_secret" && -f "$_credebl_env" ]]; then
        _credebl_kc_secret=$(grep '^CREDEBL_KEYCLOAK_CLIENT_SECRET=' "$_credebl_env" | cut -d= -f2- | tr -d '\r')
      fi
      [[ -n "$_credebl_kc_secret" ]] && keycloak_client_secret_kv=',"clientSecret":"'"$_credebl_kc_secret"'"'
    fi
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
