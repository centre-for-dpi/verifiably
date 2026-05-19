#!/usr/bin/env bash
# bootstrap-waltid-did.sh — creates a did:web DID for the walt.id issuer-api
# when operating in domain/subdomain mode (VERIFIABLY_PUBLIC_DOMAIN set).
# Sourced by deploy.sh. Can also be sourced standalone after common.sh.
[[ "${_VERIFIABLY_COMMON_LOADED:-}" == "1" ]] || source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/common.sh"

# _waltid_issuer_ready returns 0 when the issuer-api is accepting requests.
# Uses /.well-known/openid-credential-issuer (standard OID4VCI endpoint,
# always present) rather than /did/list which varies across versions.
_waltid_issuer_ready() {
  local base="$1"
  curl -sf --max-time 5 \
    "${base}/.well-known/openid-credential-issuer" >/dev/null 2>&1 || \
  curl -sf --max-time 5 \
    "${base}/openid-credential-issuer" >/dev/null 2>&1
}

# _waltid_list_dids returns a newline-separated list of DIDs from the
# issuer-api. Tries both /did and /did/list since the path changed between
# walt.id minor versions.
_waltid_list_dids() {
  local base="$1"
  local raw
  # Try /did first (0.18.x), then /did/list (older releases)
  raw=$(curl -sf --max-time 10 "${base}/did" 2>/dev/null) || \
  raw=$(curl -sf --max-time 10 "${base}/did/list" 2>/dev/null) || true
  [[ -z "$raw" ]] && return 0
  echo "$raw" | python3 -c "
import json, sys
try:
    items = json.load(sys.stdin)
    if not isinstance(items, list):
        items = items.get('results', items.get('dids', items.get('list', [])))
    for item in items:
        did = item if isinstance(item, str) else item.get('did', item.get('id', ''))
        if did:
            print(did)
except Exception:
    pass
" 2>/dev/null || true
}

# bootstrap_waltid_did_web creates a did:web DID for the running walt.id
# issuer-api and verifies that /.well-known/did.json is served at the
# issuer's subdomain. Idempotent — skips creation if a did:web already exists.
#
# Operator note: for an existing deployment already issuing under did:key,
# switching to did:web changes the issuer DID for NEW credentials only.
# Old credentials remain verifiable (they carry the did:key).
# Update the Hub Trust Registry entry after the switch.
bootstrap_waltid_did_web() {
  if [[ -z "${VERIFIABLY_PUBLIC_DOMAIN:-}" ]]; then
    return 0
  fi

  local issuer_port="${WALTID_ISSUER_PORT:-7002}"
  local issuer_base="http://localhost:${issuer_port}"

  # Derive the DID domain from the public issuer subdomain URL.
  local issuer_url issuer_domain
  issuer_url=$(url_for walt-issuer "$VERIFIABLY_PUBLIC_HOST" "$issuer_port")
  issuer_domain="${issuer_url#https://}"
  issuer_domain="${issuer_domain#http://}"
  issuer_domain="${issuer_domain%%/*}"

  local did="did:web:${issuer_domain}"

  # Wait for the issuer API to accept requests (up to 72 s).
  local tries=0
  until _waltid_issuer_ready "$issuer_base"; do
    tries=$((tries + 1))
    if [[ $tries -gt 24 ]]; then
      red "  Walt.id issuer-api not reachable at ${issuer_base} after 72s — skipping did:web setup"
      return 1
    fi
    sleep 3
  done

  # Check whether a did:web DID already exists.
  local existing_did
  existing_did=$(_waltid_list_dids "$issuer_base" \
    | grep '^did:web:' | head -1) || true

  if [[ -n "$existing_did" ]]; then
    green "  Walt.id did:web already configured: $existing_did"
    return 0
  fi

  green "  Creating walt.id did:web: $did"
  local create_out http_code
  create_out=$(curl -sf --max-time 30 -w '\n%{http_code}' -X POST \
    "$issuer_base/did/create" \
    -H "Content-Type: application/json" \
    -d "{\"method\":\"web\",\"options\":{\"domain\":\"${issuer_domain}\"}}" \
    2>/dev/null) || true

  http_code=$(echo "$create_out" | tail -1)
  create_out=$(echo "$create_out" | head -n -1)

  if [[ -z "$create_out" ]] || [[ "$http_code" == "404" ]] || [[ "$http_code" == "405" ]]; then
    red "  POST /did/create returned ${http_code:-empty} — walt.id ${issuer_port} may not expose DID management at this version"
    yellow "  Check: curl -X POST ${issuer_base}/did/create -H 'Content-Type: application/json' -d '{\"method\":\"web\",\"options\":{\"domain\":\"${issuer_domain}\"}}'"
    return 1
  fi

  local created_did
  created_did=$(echo "$create_out" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('did') or d.get('id') or '')
except Exception:
    pass
" 2>/dev/null) || true
  [[ -n "$created_did" ]] && green "  Created: $created_did"

  # Verify /.well-known/did.json is now served by the issuer-api.
  # Walt.id 0.18.x exposes this endpoint automatically once a did:web exists.
  local poll=0
  until curl -sf --max-time 5 "$issuer_base/.well-known/did.json" >/dev/null 2>&1; do
    poll=$((poll + 1))
    [[ $poll -gt 6 ]] && break
    sleep 2
  done

  if curl -sf --max-time 5 "$issuer_base/.well-known/did.json" >/dev/null 2>&1; then
    green "  ✓ ${issuer_domain}/.well-known/did.json is live"
  else
    yellow "  /.well-known/did.json not yet served — restarting issuer-api to pick up new DID"
    compose restart issuer-api >/dev/null 2>&1 || true
    sleep 5
    if curl -sf --max-time 5 "$issuer_base/.well-known/did.json" >/dev/null 2>&1; then
      green "  ✓ ${issuer_domain}/.well-known/did.json is live after restart"
    else
      yellow "  /.well-known/did.json still not served — check: curl ${issuer_base}/.well-known/did.json"
    fi
  fi
}
