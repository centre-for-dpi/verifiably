#!/usr/bin/env bash
# seed-esignet-client.sh — register the wallet-demo-client OIDC client
# with the local esignet instance.
#
# Why this script exists:
#   Mimoto signs private_key_jwt assertions with docker/injiweb/config/
#   certs/oidckeystore.p12 (alias wallet-demo-client). Esignet's token
#   endpoint verifies that JWT against a JWK stored in its client_detail
#   SQL table. Before Mimoto can actually exchange a code for a token,
#   esignet needs to know the public key half of our p12.
#
#   This script:
#     1. extracts the RSA public key from the p12 using keytool + openssl
#     2. converts it to a JWK (n, e, kty=RSA) matching what esignet
#        stores per https://github.com/mosip/esignet postman collection
#     3. POSTs it to esignet /v1/esignet/client-mgmt/oidc-client
#
# Run this AFTER `docker compose --profile injiweb up -d` and AFTER
# esignet has finished booting (check with `docker logs injiweb-esignet`).
# It's idempotent — re-running just re-upserts the client.
#
# Usage:
#   cd docker/injiweb
#   ./seed-esignet-client.sh

set -euo pipefail
cd "$(dirname "$0")"

# Pick up PUBLIC_HOST / port overrides from the shared .env file if it
# exists. Lets a single file (docker/stack/.env) drive both docker
# compose + this seed script so the client's registered redirect_uri
# matches what the browser actually follows after esignet authorizes.
ENV_FILE="../stack/.env"
if [[ -f "$ENV_FILE" ]]; then
    set -o allexport
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +o allexport
fi

: "${PUBLIC_HOST:=172.24.0.1}"
: "${INJIWEB_UI_PUBLIC_PORT:=3004}"
: "${INJIWEB_P12_PASSWORD:=xy4gh6swa2i}"

P12=config/certs/oidckeystore.p12
P12_PASS="$INJIWEB_P12_PASSWORD"
ALIAS="wallet-demo-client"
CLIENT_ID="wallet-demo-client"
CLIENT_NAME="Inji Web Demo Client"
ESIGNET_URL="${ESIGNET_URL:-http://localhost:8088}"
REDIRECT_URI="${MIMOTO_REDIRECT_URI:-http://${PUBLIC_HOST}:${INJIWEB_UI_PUBLIC_PORT}/redirect}"

if [[ ! -f "$P12" ]]; then
    echo "error: $P12 not found — copy your oidckeystore.p12 into place first" >&2
    exit 1
fi
if ! command -v openssl >/dev/null; then
    echo "error: openssl required" >&2
    exit 1
fi
if ! command -v python3 >/dev/null; then
    echo "error: python3 required (used to base64url-encode modulus + exponent)" >&2
    exit 1
fi
if ! command -v curl >/dev/null; then
    echo "error: curl required" >&2
    exit 1
fi

# --- Step 1: extract the public key from the p12 ---
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# The real wallet-demo-client p12 is encrypted with RC2-40-CBC — a
# legacy cipher OpenSSL 3.x disables by default. Pass -legacy so the
# pkcs12 decoder accepts it. No silent downgrade: if the p12 was
# generated with modern ciphers this flag is a harmless no-op.
openssl pkcs12 -legacy -in "$P12" -passin "pass:$P12_PASS" -nokeys -clcerts -out "$TMPDIR/cert.pem"
openssl x509 -in "$TMPDIR/cert.pem" -pubkey -noout > "$TMPDIR/pubkey.pem"

# --- Step 2: convert the RSA public key to a JWK ---
# Esignet's client_detail.public_key column stores a JSON Web Key
# (JWK) with base64url-encoded n and e. We write the converter to a
# temp file to avoid the heredoc/shell-expansion dance.
cat > "$TMPDIR/pem2jwk.py" <<'PY'
import sys, base64, json, re, subprocess

pubkey_pem = sys.argv[1]
out = subprocess.run(
    ["openssl", "rsa", "-pubin", "-in", pubkey_pem, "-text", "-noout"],
    check=True, capture_output=True, text=True,
).stdout

# Parse "Modulus:\n    00:ab:cd:..." and "Exponent: 65537 (0x10001)"
m = re.search(r"Modulus:\s*\n((?:\s+[0-9a-f:]+\n?)+)", out)
if not m:
    print("failed to parse modulus", file=sys.stderr)
    sys.exit(2)
hex_stream = re.sub(r"[^0-9a-f]", "", m.group(1))
mod_bytes = bytes.fromhex(hex_stream)
# Strip a leading 0x00 padding byte that openssl adds for positive ints.
if mod_bytes and mod_bytes[0] == 0:
    mod_bytes = mod_bytes[1:]

e = re.search(r"Exponent:\s*(\d+)", out)
if not e:
    print("failed to parse exponent", file=sys.stderr)
    sys.exit(2)
exp_int = int(e.group(1))
exp_bytes = exp_int.to_bytes((exp_int.bit_length() + 7) // 8, "big")

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()

jwk = {
    "kty": "RSA",
    "e": b64u(exp_bytes),
    "n": b64u(mod_bytes),
    "use": "sig",
    "alg": "RS256",
    "kid": "wallet-demo-client-kid",
}
print(json.dumps(jwk))
PY
JWK=$(python3 "$TMPDIR/pem2jwk.py" "$TMPDIR/pubkey.pem")
echo "JWK: $JWK"

# --- Step 3: fetch a CSRF token + POST the client ---
# esignet returns {token, parameterName, headerName} at the top level,
# not wrapped under a `response` key. Parse accordingly.
#
# eSignet (Spring Boot) keeps accepting TCP connections for ~30s while still
# initialising its application context. Poll until the CSRF endpoint returns
# a parseable JSON token rather than a connection reset or HTML error page.
CSRF_TOKEN=""
for _attempt in $(seq 1 30); do
    CSRF_BODY=$(curl -fsS --max-time 5 -c "$TMPDIR/cookies" "$ESIGNET_URL/v1/esignet/csrf/token" 2>/dev/null || true)
    CSRF_TOKEN=$(echo "$CSRF_BODY" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("token") or d.get("response",{}).get("token",""))' 2>/dev/null || echo "")
    [[ -n "$CSRF_TOKEN" ]] && break
    echo "  waiting for eSignet CSRF endpoint (attempt $_attempt/30)…" >&2
    sleep 5
done

if [[ -z "$CSRF_TOKEN" ]]; then
    echo "warning: failed to get CSRF token from $ESIGNET_URL — is esignet running?" >&2
    echo "         Try: docker compose --profile injiweb logs injiweb-esignet | tail -20" >&2
    exit 1
fi

REQ_BODY=$(python3 <<PY
import json, datetime
body = {
    # esignet validates requestTime against the current clock with a
    # narrow tolerance — use UTC "now" or it rejects with invalid_request.
    "requestTime": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.datetime.utcnow().microsecond // 1000:03d}Z",
    "request": {
        "clientId": "$CLIENT_ID",
        "clientName": "$CLIENT_NAME",
        "relyingPartyId": "$CLIENT_ID",
        "publicKey": $JWK,
        "logoUri": "https://avatars.githubusercontent.com/u/69429477",
        "redirectUris": ["$REDIRECT_URI"],
        "userClaims": ["name", "email", "gender", "phone_number", "picture", "birthdate", "address"],
        "authContextRefs": ["mosip:idp:acr:generated-code", "mosip:idp:acr:linked-wallet"],
        "grantTypes": ["authorization_code"],
        "clientAuthMethods": ["private_key_jwt"],
    },
}
print(json.dumps(body))
PY
)

echo "POST $ESIGNET_URL/v1/esignet/client-mgmt/oidc-client"
RESPONSE=$(curl -fsS -X POST \
    -H "Content-Type: application/json" \
    -H "X-XSRF-TOKEN: $CSRF_TOKEN" \
    -b "$TMPDIR/cookies" \
    -d "$REQ_BODY" \
    "$ESIGNET_URL/v1/esignet/client-mgmt/oidc-client" || true)

echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

if echo "$RESPONSE" | grep -q '"errorCode"'; then
    # Duplicate client is a soft failure — already seeded.
    if echo "$RESPONSE" | grep -q 'duplicate_client_id'; then
        echo "OK: $CLIENT_ID already registered with esignet"
        exit 0
    fi
    echo "error: esignet rejected the registration (see response above)" >&2
    exit 1
fi

echo "OK: $CLIENT_ID registered with esignet at $ESIGNET_URL"
