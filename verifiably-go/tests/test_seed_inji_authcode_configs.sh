#!/usr/bin/env bash
# tests/test_seed_inji_authcode_configs.sh — tests for seed_inji_authcode_configs
# in scripts/gen-caddy.sh. Run from repo root:
#   bash verifiably-go/tests/test_seed_inji_authcode_configs.sh
#
# What this guards. Inji Certify Auth-Code's two runtime configs hold state
# that is expensive-to-impossible to recover:
#   - certify-postgres-dataprovider.properties carries every operator-saved
#     Auth-Code schema's scope-query-mapping brace-entry, appended in place by
#     applyAuthcodeSchema (internal/handlers/inji_schema.go).
#   - credential-scopes.properties carries the matching eSignet scope +
#     scope-resource-mapping entries for the same schemas.
# Seeding must therefore be strictly no-clobber, same requirement and same
# shape as seed_issuer2_configs (tests/test_seed_issuer2_configs.sh) — this
# file mirrors that one, adapted to two files living in two directories
# instead of one.
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
assert_file_exists() {
  local label="$1" path="$2"
  [[ -f "$path" ]] && ok "$label" || fail "$label — missing: $path"
}

# --- load the function under test ------------------------------------------
bold()  { echo "$@"; }
green() { echo "$@"; }
red()   { echo "$@"; }
# shellcheck disable=SC1090
seed_fn="$(sed -n '/^seed_inji_authcode_configs() {$/,/^}$/p' "$SCRIPT_DIR/scripts/gen-caddy.sh")"
[[ -n "$seed_fn" ]] || { echo "FATAL: seed_inji_authcode_configs not found in scripts/gen-caddy.sh"; exit 1; }
eval "$seed_fn"

# --- scratch fixture --------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SCRIPT_DIR="$TMP"
CERTIFY_DIR="$TMP/deploy/compose/stack/inji/certify"
ESIGNET_DIR="$TMP/deploy/compose/stack/inji/esignet"
mkdir -p "$CERTIFY_DIR" "$ESIGNET_DIR"

echo "BASELINE-CERTIFY-SCOPES" > "$CERTIFY_DIR/certify-postgres-dataprovider.baseline.properties"
echo "BASELINE-ESIGNET-SCOPES" > "$ESIGNET_DIR/credential-scopes.baseline.properties"

echo "== first run seeds both runtime files from their baselines =="
seed_inji_authcode_configs >/dev/null
assert_file_exists "certify-postgres-dataprovider.properties created" "$CERTIFY_DIR/certify-postgres-dataprovider.properties"
assert_file_exists "credential-scopes.properties created"             "$ESIGNET_DIR/credential-scopes.properties"
assert_eq "certify props seeded from baseline" "$(cat "$CERTIFY_DIR/certify-postgres-dataprovider.properties")" "BASELINE-CERTIFY-SCOPES"
assert_eq "esignet props seeded from baseline" "$(cat "$ESIGNET_DIR/credential-scopes.properties")" "BASELINE-ESIGNET-SCOPES"

echo "== operator state (appended scopes) survives a second seed =="
# Stand in for the real thing: applyAuthcodeSchema-appended scope entries.
echo "BASELINE-CERTIFY-SCOPES + OPERATOR-SCOPE-A" > "$CERTIFY_DIR/certify-postgres-dataprovider.properties"
echo "BASELINE-ESIGNET-SCOPES + OPERATOR-SCOPE-A" > "$ESIGNET_DIR/credential-scopes.properties"
seed_inji_authcode_configs >/dev/null
assert_eq "second seed does not clobber certify scopes" \
  "$(cat "$CERTIFY_DIR/certify-postgres-dataprovider.properties")" "BASELINE-CERTIFY-SCOPES + OPERATOR-SCOPE-A"
assert_eq "second seed does not clobber esignet scopes" \
  "$(cat "$ESIGNET_DIR/credential-scopes.properties")" "BASELINE-ESIGNET-SCOPES + OPERATOR-SCOPE-A"

echo "== baselines are never written to =="
assert_eq "certify baseline untouched" \
  "$(cat "$CERTIFY_DIR/certify-postgres-dataprovider.baseline.properties")" "BASELINE-CERTIFY-SCOPES"
assert_eq "esignet baseline untouched" \
  "$(cat "$ESIGNET_DIR/credential-scopes.baseline.properties")" "BASELINE-ESIGNET-SCOPES"

echo "== a third run is still a no-op (idempotent) =="
seed_inji_authcode_configs >/dev/null
assert_eq "third seed leaves certify scopes alone" \
  "$(cat "$CERTIFY_DIR/certify-postgres-dataprovider.properties")" "BASELINE-CERTIFY-SCOPES + OPERATOR-SCOPE-A"

echo "== migration case: pre-existing runtime file from an older checkout =="
# An operator upgrading from before the split already has real content sitting
# at the runtime name (the old tracked filename). Seeding must adopt it as-is.
rm -rf "$CERTIFY_DIR" "$ESIGNET_DIR" && mkdir -p "$CERTIFY_DIR" "$ESIGNET_DIR"
echo "BASELINE-CERTIFY-SCOPES" > "$CERTIFY_DIR/certify-postgres-dataprovider.baseline.properties"
echo "BASELINE-ESIGNET-SCOPES" > "$ESIGNET_DIR/credential-scopes.baseline.properties"
echo "PRE-EXISTING-CERTIFY-SCOPES" > "$CERTIFY_DIR/certify-postgres-dataprovider.properties"
seed_inji_authcode_configs >/dev/null
assert_eq "pre-existing runtime certify scopes adopted, not overwritten" \
  "$(cat "$CERTIFY_DIR/certify-postgres-dataprovider.properties")" "PRE-EXISTING-CERTIFY-SCOPES"
assert_eq "the missing sibling is still seeded" \
  "$(cat "$ESIGNET_DIR/credential-scopes.properties")" "BASELINE-ESIGNET-SCOPES"

echo "== missing baseline warns and skips rather than failing the deploy =="
rm -rf "$CERTIFY_DIR" "$ESIGNET_DIR" && mkdir -p "$CERTIFY_DIR" "$ESIGNET_DIR"
echo "BASELINE-ESIGNET-SCOPES" > "$ESIGNET_DIR/credential-scopes.baseline.properties"
out="$(seed_inji_authcode_configs 2>&1)"
assert_eq "returns success despite missing baseline" "$?" "0"
echo "$out" | grep -q "WARN" && ok "warns about the missing baseline" || fail "no WARN emitted"
assert_eq "the present baseline still seeds" \
  "$(cat "$ESIGNET_DIR/credential-scopes.properties")" "BASELINE-ESIGNET-SCOPES"

echo
echo "  $_PASS passed, $_FAIL failed"
[[ $_FAIL -eq 0 ]]
