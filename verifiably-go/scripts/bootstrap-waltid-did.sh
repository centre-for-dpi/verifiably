#!/usr/bin/env bash
# bootstrap-waltid-did.sh — creates a did:web DID for the walt.id issuer-api
# when operating in domain/subdomain mode (VERIFIABLY_PUBLIC_DOMAIN set).
# Sourced by deploy.sh. Can also be sourced standalone after common.sh.
[[ "${_VERIFIABLY_COMMON_LOADED:-}" == "1" ]] || source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/common.sh"

# bootstrap_waltid_did_web creates a did:web DID for the running walt.id
# issuer-api and verifies that /.well-known/did.json is served at the
# issuer's subdomain. Idempotent — skips creation if a did:web already exists.
#
# Why: walt.id defaults to did:key, which is fine for development but
# unsuitable for production Hub accreditation. did:web ties issuer identity to
# a government domain so any OID4VC-compatible verifier can identify the issuer
# without consulting a proprietary Trust Registry.
#
# How it works:
#   1. Calls POST /did/create on the issuer-api with method=web.
#   2. After creation, the issuer-api automatically serves the DID document at
#      GET /.well-known/did.json (standard OID4VCI issuer behaviour in walt.id).
#   3. If the endpoint is not live after creation, the issuer-api is restarted
#      once to pick up the new DID configuration.
#
# Operator note: for an EXISTING deployment that already has credentials issued
# under a did:key, switching to did:web changes the issuer DID. Old credentials
# remain verifiable (they carry the did:key), but NEW credentials will carry
# the did:web. Update the Hub Trust Registry entry after the switch.
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

  # Wait for the issuer API to be reachable (it may still be starting).
  local tries=0
  until curl -sf --max-time 5 "$issuer_base/did/list" >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [[ $tries -gt 24 ]]; then
      red "  Walt.id issuer-api not reachable at ${issuer_base} after 72s — skipping did:web setup"
      return 1
    fi
    sleep 3
  done

  # Check whether a did:web DID already exists.
  local existing_did
  existing_did=$(curl -sf --max-time 10 "$issuer_base/did/list" 2>/dev/null \
    | python3 -c "
import json, sys
try:
    items = json.load(sys.stdin)
    if not isinstance(items, list):
        items = items.get('results', items.get('dids', []))
    match = next(
        (d if isinstance(d, str) else d.get('did', ''))
        for d in items
        if (d if isinstance(d, str) else d.get('did', '')).startswith('did:web:')
    )
    print(match)
except StopIteration:
    pass
except Exception:
    pass
" 2>/dev/null) || true

  if [[ -n "$existing_did" ]]; then
    green "  Walt.id did:web already configured: $existing_did"
    return 0
  fi

  green "  Creating walt.id did:web: $did"
  local create_out
  create_out=$(curl -sf --max-time 30 -X POST \
    "$issuer_base/did/create" \
    -H "Content-Type: application/json" \
    -d "{\"method\":\"web\",\"options\":{\"domain\":\"${issuer_domain}\"}}" \
    2>/dev/null) || true

  if [[ -z "$create_out" ]]; then
    red "  POST /did/create returned empty — issuer-api may not support did:web at this version"
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
  # Walt.id exposes this endpoint automatically after a did:web is created.
  local poll=0
  until curl -sf --max-time 5 "$issuer_base/.well-known/did.json" >/dev/null 2>&1; do
    poll=$((poll + 1))
    [[ $poll -gt 6 ]] && break
    sleep 2
  done

  if curl -sf --max-time 5 "$issuer_base/.well-known/did.json" >/dev/null 2>&1; then
    green "  ✓ ${issuer_domain}/.well-known/did.json is live"
  else
    yellow "  /.well-known/did.json not yet served — restarting issuer-api"
    compose restart issuer-api >/dev/null 2>&1 || true
    sleep 5
    if curl -sf --max-time 5 "$issuer_base/.well-known/did.json" >/dev/null 2>&1; then
      green "  ✓ ${issuer_domain}/.well-known/did.json is live after restart"
    else
      yellow "  /.well-known/did.json not served after restart — check issuer-api logs"
    fi
  fi
}
