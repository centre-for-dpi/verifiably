#!/usr/bin/env bash
# tests/test_seed_issuer2_configs.sh — tests for seed_issuer2_configs in
# scripts/gen-caddy.sh. Run from repo root:
#   bash verifiably-go/tests/test_seed_issuer2_configs.sh
#
# What this guards. issuer-api2's two runtime configs hold state that is
# expensive-to-impossible to recover:
#   - issuer2-profiles.conf carries the deployment's real DSC/IACA x5chain. The
#     DSC in it is the certificate already inside every mdoc this deployment has
#     ever issued, so overwriting it is not recoverable by regenerating.
#   - credential-issuer-metadata.conf carries the operator's mdoc schema display
#     name, typed by hand in the schema builder.
# Seeding must therefore be strictly no-clobber. A seed that overwrote either
# file would break a live deployment silently: mdocs keep issuing, wallets just
# start refusing them, and nothing on our side logs an error.
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
# gen-caddy.sh is a function library plus colour helpers; sourcing it with a
# scratch SCRIPT_DIR is enough to exercise the seeding in isolation.
bold()  { echo "$@"; }
green() { echo "$@"; }
red()   { echo "$@"; }
# shellcheck disable=SC1090
seed_fn="$(sed -n '/^seed_issuer2_configs() {$/,/^}$/p' "$SCRIPT_DIR/scripts/gen-caddy.sh")"
[[ -n "$seed_fn" ]] || { echo "FATAL: seed_issuer2_configs not found in scripts/gen-caddy.sh"; exit 1; }
eval "$seed_fn"

# --- scratch fixture --------------------------------------------------------
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SCRIPT_DIR="$TMP"
mkdir -p "$TMP/deploy/k8s/config/issuer2"
D="$TMP/deploy/k8s/config/issuer2"

echo "BASELINE-PROFILES" > "$D/issuer2-profiles.baseline.conf"
echo "BASELINE-METADATA" > "$D/credential-issuer-metadata.baseline.conf"

echo "== first run seeds both runtime files from their baselines =="
seed_issuer2_configs >/dev/null
assert_file_exists "issuer2-profiles.conf created"           "$D/issuer2-profiles.conf"
assert_file_exists "credential-issuer-metadata.conf created" "$D/credential-issuer-metadata.conf"
assert_eq "profiles seeded from baseline" "$(cat "$D/issuer2-profiles.conf")" "BASELINE-PROFILES"
assert_eq "metadata seeded from baseline" "$(cat "$D/credential-issuer-metadata.conf")" "BASELINE-METADATA"

echo "== operator state at the runtime paths survives a second seed =="
# Stand in for the real thing: a rendered x5chain and a saved display name.
echo "OPERATOR-REAL-X5CHAIN" > "$D/issuer2-profiles.conf"
echo "OPERATOR-SCHEMA-NAME"  > "$D/credential-issuer-metadata.conf"
seed_issuer2_configs >/dev/null
assert_eq "second seed does not clobber profiles" \
  "$(cat "$D/issuer2-profiles.conf")" "OPERATOR-REAL-X5CHAIN"
assert_eq "second seed does not clobber metadata" \
  "$(cat "$D/credential-issuer-metadata.conf")" "OPERATOR-SCHEMA-NAME"

echo "== baselines are never written to =="
assert_eq "profiles baseline untouched" \
  "$(cat "$D/issuer2-profiles.baseline.conf")" "BASELINE-PROFILES"
assert_eq "metadata baseline untouched" \
  "$(cat "$D/credential-issuer-metadata.baseline.conf")" "BASELINE-METADATA"

echo "== a third run is still a no-op (idempotent) =="
seed_issuer2_configs >/dev/null
assert_eq "third seed leaves profiles alone" \
  "$(cat "$D/issuer2-profiles.conf")" "OPERATOR-REAL-X5CHAIN"

echo "== migration case: pre-existing runtime file from an older checkout =="
# An operator upgrading from before the split already has real content sitting
# at the runtime name (the old tracked filename). Seeding must adopt it as-is.
rm -rf "$D" && mkdir -p "$D"
echo "BASELINE-PROFILES" > "$D/issuer2-profiles.baseline.conf"
echo "BASELINE-METADATA" > "$D/credential-issuer-metadata.baseline.conf"
echo "PRE-EXISTING-CERTS" > "$D/issuer2-profiles.conf"
seed_issuer2_configs >/dev/null
assert_eq "pre-existing runtime profiles adopted, not overwritten" \
  "$(cat "$D/issuer2-profiles.conf")" "PRE-EXISTING-CERTS"
assert_eq "the missing sibling is still seeded" \
  "$(cat "$D/credential-issuer-metadata.conf")" "BASELINE-METADATA"

echo "== missing baseline warns and skips rather than failing the deploy =="
rm -rf "$D" && mkdir -p "$D"
echo "BASELINE-METADATA" > "$D/credential-issuer-metadata.baseline.conf"
out="$(seed_issuer2_configs 2>&1)"
assert_eq "returns success despite missing baseline" "$?" "0"
echo "$out" | grep -q "WARN" && ok "warns about the missing baseline" || fail "no WARN emitted"
assert_eq "the present baseline still seeds" \
  "$(cat "$D/credential-issuer-metadata.conf")" "BASELINE-METADATA"

echo
echo "  $_PASS passed, $_FAIL failed"
[[ $_FAIL -eq 0 ]]
