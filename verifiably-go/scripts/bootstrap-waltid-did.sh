#!/usr/bin/env bash
# bootstrap-waltid-did.sh — provisions a did:web DID for the walt.id issuer-api
# when operating in domain/subdomain mode (VERIFIABLY_PUBLIC_DOMAIN set).
#
# Walt.id 0.18.2 architecture: DID management is stateless — /onboard/issuer
# generates a keypair + DID inline and returns them in the response body.
# We persist the result to .agent-runtime/waltid/issuer.json so subsequent
# deploys reuse the same identity without re-provisioning.
#
# Sourced by deploy.sh. Can also be sourced standalone after common.sh.
[[ "${_VERIFIABLY_COMMON_LOADED:-}" == "1" ]] || source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/common.sh"

# _waltid_issuer_ready returns 0 when the issuer-api is accepting requests.
# Uses /livez — the standard health-check endpoint in walt.id 0.18.2.
# Earlier versions may lack /livez; fall back to / (which returns 302 → swagger,
# a non-error response that curl -sf treats as success).
_waltid_issuer_ready() {
  local base="$1"
  curl -sf --max-time 5 "${base}/livez" >/dev/null 2>&1 || \
  curl -sf --max-time 5 "${base}/"       >/dev/null 2>&1
}

# _waltid_build_did_document constructs a minimal did:web DID document from
# the issuerKey JWK returned by /onboard/issuer. Strips the private key 'd'
# parameter so only the public key is served.
_waltid_build_did_document() {
  local did="$1"
  local jwk_json="$2"
  python3 -c "
import json, sys
did  = sys.argv[1]
jwk  = json.loads(sys.argv[2])
jwk.pop('d', None)   # never expose the private key
vm_id = did + '#key-1'
doc = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/jws-2020/v1'
  ],
  'id': did,
  'verificationMethod': [{
    'id': vm_id,
    'type': 'JsonWebKey2020',
    'controller': did,
    'publicKeyJwk': jwk
  }],
  'assertionMethod': [vm_id],
  'authentication':  [vm_id]
}
print(json.dumps(doc))
" "$did" "$jwk_json" 2>/dev/null
}

# _waltid_inject_backends_json patches config/backends.json with the pinned
# issuerKey + issuerDid so verifiably-go signs credentials with the persistent
# did:web identity instead of generating a fresh did:jwk on every restart.
# Idempotent — safe to call on every deploy.
_waltid_inject_backends_json() {
  local issuer_file="$1"
  local backends="$SCRIPT_DIR/config/backends.json"
  [[ -f "$issuer_file" ]] || return 0
  [[ -f "$backends"    ]] || return 0
  python3 - "$issuer_file" "$backends" <<'PY'
import json, sys
issuer_file, backends_path = sys.argv[1], sys.argv[2]
with open(issuer_file) as f:
    issuer = json.load(f)
issuer_key = issuer.get('issuerKey')
issuer_did = issuer.get('issuerDid', '')
if not issuer_key or not issuer_did.startswith('did:web:'):
    sys.exit(0)
with open(backends_path) as f:
    data = json.load(f)
changed = False
for b in data.get('backends', []):
    if b.get('type') == 'walt_community':
        cfg = b.setdefault('config', {})
        if cfg.get('issuerDid') != issuer_did:
            cfg['issuerKey'] = issuer_key
            cfg['issuerDid'] = issuer_did
            changed = True
if changed:
    with open(backends_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'  injected issuerKey + issuerDid ({issuer_did}) into backends.json')
else:
    print(f'  backends.json already has issuerDid={issuer_did}')
PY
}

# _waltid_reload_caddy_public reloads the public Caddy container after the
# Caddyfile is regenerated with the /.well-known/did.json handler.
_waltid_reload_caddy_public() {
  local caddy_container
  caddy_container=$(docker ps --format '{{.Names}}' | grep 'caddy-public' | head -1 2>/dev/null) || true
  [[ -z "$caddy_container" ]] && return 0
  if docker exec "$caddy_container" caddy reload \
      --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
    green "  Reloaded caddy-public with updated Caddyfile"
  else
    docker restart "$caddy_container" >/dev/null 2>&1 || true
    green "  Restarted caddy-public to pick up new Caddyfile"
  fi
}

# bootstrap_waltid_did_web provisions a did:web DID for the running walt.id
# issuer-api and wires it into verifiably-go's backends.json + the public
# Caddy config so /.well-known/did.json is served at the issuer subdomain.
# Idempotent — skips provisioning if .agent-runtime/waltid/issuer.json
# already contains a did:web entry.
bootstrap_waltid_did_web() {
  if [[ -z "${VERIFIABLY_PUBLIC_DOMAIN:-}" ]]; then
    return 0
  fi

  local issuer_port="${WALTID_ISSUER_PORT:-7002}"
  local issuer_base="http://localhost:${issuer_port}"
  local runtime_dir="$SCRIPT_DIR/.agent-runtime/waltid"
  local issuer_file="$runtime_dir/issuer.json"
  local did_file="$runtime_dir/did.json"

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

  mkdir -p "$runtime_dir"

  # Idempotency: if we already provisioned a did:web key, reuse it.
  local existing_did=""
  if [[ -f "$issuer_file" ]]; then
    existing_did=$(python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
    print(d.get('issuerDid', ''))
except Exception:
    pass
" "$issuer_file" 2>/dev/null) || true
  fi

  if [[ "$existing_did" == "did:web:"* ]]; then
    green "  Walt.id did:web already provisioned: $existing_did"
    _waltid_inject_backends_json "$issuer_file"
    if [[ -n "$VERIFIABLY_HOSTS_PATTERN" && -f "$did_file" ]]; then
      render_public_caddyfile
      _waltid_reload_caddy_public
    fi
    return 0
  fi

  # Call /onboard/issuer with did:web configuration.
  # Walt.id 0.18.2 accepts {"key":{...}, "did":{"method":"web","config":{"domain":"..."}}}
  green "  Provisioning walt.id did:web: $did"
  local onboard_out
  onboard_out=$(curl -sf --max-time 30 -X POST \
    "$issuer_base/onboard/issuer" \
    -H "Content-Type: application/json" \
    -d "{\"key\":{\"backend\":\"jwk\",\"keyType\":\"secp256r1\"},\"did\":{\"method\":\"web\",\"config\":{\"domain\":\"${issuer_domain}\"}}}" \
    2>/dev/null) || true

  if [[ -z "$onboard_out" ]]; then
    red "  POST /onboard/issuer returned empty — did:web provisioning failed"
    return 1
  fi

  # Verify we got a did:web DID back.
  local result_did
  result_did=$(echo "$onboard_out" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('issuerDid', ''))
except Exception:
    pass
" 2>/dev/null) || true

  if [[ "$result_did" != "did:web:"* ]]; then
    red "  /onboard/issuer did not return a did:web DID (got: ${result_did:-empty response})"
    yellow "  Check: curl -X POST ${issuer_base}/onboard/issuer -H 'Content-Type: application/json' -d '{\"key\":{\"keyType\":\"secp256r1\"},\"did\":{\"method\":\"web\",\"config\":{\"domain\":\"${issuer_domain}\"}}}'  "
    return 1
  fi

  # Persist issuerKey + issuerDid for reuse on subsequent deploys.
  echo "$onboard_out" > "$issuer_file"
  green "  Created: $result_did"

  # Build and save the DID document (public JWK only — no private key).
  local jwk_json
  jwk_json=$(echo "$onboard_out" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    ik = d.get('issuerKey', {})
    # 0.18.2 shape: {\"type\":\"jwk\",\"jwk\":{...}}
    if isinstance(ik, dict):
        jwk = ik.get('jwk') or ik
        print(json.dumps(jwk))
except Exception:
    pass
" 2>/dev/null) || true

  if [[ -n "$jwk_json" ]]; then
    local did_doc
    did_doc=$(_waltid_build_did_document "$result_did" "$jwk_json") || true
    if [[ -n "$did_doc" ]]; then
      echo "$did_doc" > "$did_file"
      green "  Saved DID document → $did_file"
    fi
  fi

  # Inject the pinned key+DID into backends.json so verifiably-go uses did:web.
  _waltid_inject_backends_json "$issuer_file"

  # Re-render Caddyfile.public (now includes /.well-known/did.json handler)
  # and reload caddy-public so the endpoint is live immediately.
  if [[ -n "$VERIFIABLY_HOSTS_PATTERN" ]]; then
    render_public_caddyfile
    _waltid_reload_caddy_public
  fi

  # Verify the DID document is now reachable at the public URL.
  local public_did_url="https://${issuer_domain}/.well-known/did.json"
  sleep 2
  if curl -sf --max-time 10 "$public_did_url" >/dev/null 2>&1; then
    green "  ✓ ${public_did_url} is live"
  else
    yellow "  /.well-known/did.json not yet reachable at ${public_did_url}"
    yellow "  (Caddy may still be acquiring TLS — retry in a few seconds)"
  fi
}
