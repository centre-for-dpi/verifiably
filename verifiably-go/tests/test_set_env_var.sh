#!/usr/bin/env bash
# tests/test_set_env_var.sh — tests for set_env_var in scripts/common.sh. Run
# from repo root:
#   bash verifiably-go/tests/test_set_env_var.sh
#
# What this guards. deploy.sh (and hub_compose) load .env files with real bash
# parsing (`set -o allexport; source FILE`), not simple KEY=VALUE reading. A
# value containing shell-special characters — most importantly a JSON blob
# like issuer-api2's ciTokenKey ({"type":"jwk","jwk":{...}}) — written
# unquoted is silently corrupted the next time that file is sourced: bash
# strips the JSON's own double quotes as if they were shell syntax, and
# nothing errors anywhere in the chain (this exact failure mode is documented
# against VERIFIABLY_ISSUER2_CI_TOKEN_KEY in deploy/compose/stack/.env.example).
# set_env_var must quote any value that needs it, and must round-trip
# correctly through an actual `source` — not just "look right" when catted.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- test harness -----------------------------------------------------------
_PASS=0; _FAIL=0
ok()   { echo "  PASS: $1"; (( _PASS++ )) || true; }
fail() { echo "  FAIL: $1"; (( _FAIL++ )) || true; }
assert_eq() {
  local label="$1" got="$2" want="$3"
  [[ "$got" == "$want" ]] && ok "$label" || fail "$label — got: $(printf '%q' "$got") want: $(printf '%q' "$want")"
}

# --- load the function under test --------------------------------------------
# shellcheck disable=SC1091
source "$SCRIPT_DIR/scripts/common.sh"

# --- scratch fixture ----------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ENV_FILE="$TMP/.env"

round_trip() {
  # Write VAR=val via set_env_var, then source the file exactly the way
  # deploy.sh does, and echo back what the shell actually ends up with.
  local var="$1" val="$2"
  echo "PLACEHOLDER=x" > "$ENV_FILE"
  set_env_var "$ENV_FILE" "$var" "$val"
  ( set -o allexport; source "$ENV_FILE"; set +o allexport; printf '%s' "${!var}" )
}

echo "== a JSON JWK-wrapper value survives set_env_var + allexport source =="
jwk='{"type":"jwk","jwk":{"kty":"EC","crv":"P-256","x":"abc","y":"def","d":"ghi"}}'
got="$(round_trip TESTVAR "$jwk")"
assert_eq "double-quoted JSON round-trips intact" "$got" "$jwk"

echo "== a plain alphanumeric value is unaffected (existing callers) =="
got="$(round_trip TESTVAR 'https://issuer.example.com:8443')"
assert_eq "plain URL round-trips intact" "$got" "https://issuer.example.com:8443"

echo "== a value with an embedded single quote survives =="
got="$(round_trip TESTVAR "it's a value")"
assert_eq "embedded single quote round-trips intact" "$got" "it's a value"

echo "== a value with spaces survives =="
got="$(round_trip TESTVAR "two words")"
assert_eq "spaced value round-trips intact" "$got" "two words"

echo "== the upsert path (variable already present) quotes too =="
echo "TESTVAR=old" > "$ENV_FILE"
set_env_var "$ENV_FILE" "TESTVAR" "$jwk"
got="$( ( set -o allexport; source "$ENV_FILE"; set +o allexport; printf '%s' "$TESTVAR" ) )"
assert_eq "upsert path also round-trips JSON intact" "$got" "$jwk"

echo "== an empty value still upserts cleanly =="
echo "TESTVAR=old" > "$ENV_FILE"
set_env_var "$ENV_FILE" "TESTVAR" ""
got="$(grep '^TESTVAR=' "$ENV_FILE")"
assert_eq "empty value writes as TESTVAR=" "$got" "TESTVAR="

echo
echo "  $_PASS passed, $_FAIL failed"
[[ $_FAIL -eq 0 ]]
