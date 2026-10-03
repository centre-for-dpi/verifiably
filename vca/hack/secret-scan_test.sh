#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests for secret-scan.sh. Run: hack/secret-scan_test.sh
# Each case is a small git repository with one tracked file.

set -u

here=$(cd "$(dirname "$0")" && pwd)
scan="$here/secret-scan.sh"
fail=0

# run_case <name> <file name> <content> <want exit> [<want pattern>]
run_case() {
  name=$1
  tmp=$(mktemp -d)
  (
    cd "$tmp" || exit 2
    git init -q .
    mkdir -p "$(dirname "$2")"
    printf '%s\n' "$3" > "$2"
    git add "$2"
    "$scan" > out.txt 2>&1
    echo $? > exit.txt
  )
  got=$(cat "$tmp/exit.txt")
  if [ "$got" != "$4" ]; then
    echo "FAIL $name: exit $got, want $4:"
    sed 's/^/     /' "$tmp/out.txt"
    fail=1
  elif [ -n "${5:-}" ] && ! grep -q -- "$5" "$tmp/out.txt"; then
    echo "FAIL $name: expected /$5/ in output:"
    sed 's/^/     /' "$tmp/out.txt"
    fail=1
  else
    echo "ok   $name"
  fi
  rm -rf "$tmp"
}

# key=value files: a literal secret fails, a variable or an empty value
# passes (ADR-055 decision 5).
run_case "properties password literal" app.properties "x.password=s3cretvalue" 1 "password: app.properties:1"
run_case "properties secret literal" app.properties "mosip.event.secret=Qw7literal" 1 "password: app.properties:1"
run_case "properties secret key literal" app.properties "token.request.secretKey=s3cretvalue" 1 "password:"
run_case "properties client secret literal" app.properties "mosip.iam.adapter.clientsecret=s3cretvalue" 1 "password:"
run_case "properties api key literal" app.properties "wallet.binding.partner.api.key=s3cretvalue" 1 "password:"
run_case "properties encryption key literal" app.properties "mosip.partner.encryption.key=s3cretvalue" 1 "password:"
run_case "properties variable" app.properties "x.password=\${X}" 0
run_case "properties variable with default name" app.properties "x.password=\${INJI_DB_PASSWORD}" 0
run_case "properties empty" app.properties "x.password=" 0
run_case "properties placeholder" app.properties "x.password=<set by the operator>" 0
run_case "properties a key that is a URL" app.properties "mosip.certify.authn.jwk-set-uri=http://inji-certify:8090/.well-known/jwks.json" 0
run_case "conf literal" wallet.conf "tokenKey = \"s3cretvalue\"" 1 "password: wallet.conf:1"
run_case "conf variable" wallet.conf "tokenKey = \${WALLET_TOKEN_KEY}" 0
# key: value files keep their rule.
run_case "yaml password literal" stack.yaml "  password: certify" 1 "password: stack.yaml:1"
run_case "yaml password variable" stack.yaml "  password: \${INJI_DB_PASSWORD:?set by vca setup}" 0
# A comment is not a value.
run_case "properties comment" app.properties "# the password=s3cretvalue of the release" 0

# The peer identity of ADR-075: an identity file, a key file, and the
# authority key never belong in the tree, whatever they hold.
run_case "tracked peer identity file" deploy/issuer-waltid/peer/issuance.env "VCA_PEER_IDENTITY=x" 1 "peer-identity: deploy/issuer-waltid/peer/issuance.env"
run_case "tracked landing identity file" deploy/landing/peer/landing.env "VCA_PEER_CALLERS=" 1 "peer-identity:"
run_case "tracked peer key file" deploy/issuer-waltid/peer/keys/issuance.jwk "{}" 1 "peer-identity: deploy/issuer-waltid/peer/keys/issuance.jwk"
run_case "tracked peer authority" deploy/peer/authority.pem "placeholder" 1 "peer-identity: deploy/peer/authority.pem"
# A private JWK: a "d" member in a JSON file, or a key=value whose value
# is a base64url JWK with a "d" member. A public JWK passes.
private_jwk='{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"}'
public_jwk='{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}'
b64url() { printf '%s' "$1" | base64 | tr -d '\n=' | tr '+/' '-_'; }
run_case "private JWK in a JSON file" config/signer.json "$private_jwk" 1 "private-jwk: config/signer.json:1"
run_case "public JWK in a JSON file" config/signer.json "$public_jwk" 0
run_case "peer key in an env file" app.env "VCA_PEER_KEY=$(b64url "$private_jwk")" 1 "private-jwk: app.env:1"
run_case "another private key in an env file" app.env "VCA_OTHER_SIGNING_KEY=$(b64url "$private_jwk")" 1 "private-jwk: app.env:1"
run_case "public key set in an env file" app.env "VCA_PEER_AUTHORITY_KEY=$(b64url "$public_jwk")" 0
run_case "key file path in an env file" app.env "VCA_PEER_KEY_FILE=/run/vca/peer/key.jwk" 0

if [ "$fail" -ne 0 ]; then
  echo "secret-scan_test: FAILED"
  exit 1
fi
echo "secret-scan_test: all cases passed"
