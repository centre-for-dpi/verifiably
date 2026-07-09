#!/usr/bin/env bash
# tests/test_roles.sh — tests for role-based deploy helper functions in common.sh.
# Run from repo root: bash verifiably-go/tests/test_roles.sh
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
assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  echo "$haystack" | grep -q "$needle" && ok "$label" || fail "$label — '$needle' not found in output"
}
assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  echo "$haystack" | grep -q "$needle" && fail "$label — '$needle' should NOT be in output" || ok "$label"
}

# --- setup: stub .env so common.sh doesn't fail on missing file -------------
export VERIFIABLY_ENV_FILE=/dev/null
export VERIFIABLY_PUBLIC_HOST=localhost
export VERIFIABLY_SKIP_WSO2IS=1   # skip WSO2IS in tests to keep output simple

source "$SCRIPT_DIR/scripts/common.sh"

# ============================================================================
echo "--- resolve_role ---"
unset CLI_ROLE VERIFIABLY_ROLES
assert_eq "default when nothing set"        "$(resolve_role)" "issuer,verifier,holder"
export VERIFIABLY_ROLES=issuer
assert_eq ".env value used"                 "$(resolve_role)" "issuer"
export CLI_ROLE=verifier
assert_eq "CLI_ROLE overrides VERIFIABLY_ROLES" "$(resolve_role)" "verifier"
unset CLI_ROLE VERIFIABLY_ROLES

# ============================================================================
echo "--- validate_roles ---"
validate_roles "issuer"           && ok "issuer valid"        || fail "issuer valid"
validate_roles "verifier"         && ok "verifier valid"      || fail "verifier valid"
validate_roles "holder"           && ok "holder valid"        || fail "holder valid"
validate_roles "issuer,verifier"  && ok "multi-role valid"    || fail "multi-role valid"
validate_roles "issuer,verifier,holder" && ok "all-roles valid" || fail "all-roles valid"
( validate_roles "admin" 2>/dev/null ) && fail "unknown role should fail" || ok "unknown role rejected"
( validate_roles "" 2>/dev/null ) && fail "empty role should fail" || ok "empty role rejected"

# ============================================================================
echo "--- role_services waltid ---"
OUT=$(role_services waltid issuer)
assert_contains "waltid issuer has issuer-api"   "$OUT" "issuer-api"
assert_not_contains "waltid issuer no verifier-api" "$OUT" "verifier-api"
assert_not_contains "waltid issuer no wallet-api"   "$OUT" "wallet-api"

OUT=$(role_services waltid verifier)
assert_contains "waltid verifier has verifier-api"  "$OUT" "verifier-api"
assert_not_contains "waltid verifier no issuer-api" "$OUT" "issuer-api"

OUT=$(role_services waltid holder)
assert_contains "waltid holder has wallet-api"      "$OUT" "wallet-api"
assert_not_contains "waltid holder no issuer-api"   "$OUT" "issuer-api"

OUT=$(role_services waltid "issuer,verifier,holder")
assert_contains "waltid all has issuer-api"   "$OUT" "issuer-api"
assert_contains "waltid all has verifier-api" "$OUT" "verifier-api"
assert_contains "waltid all has wallet-api"   "$OUT" "wallet-api"
# dedup: postgres must appear exactly once
COUNT=$(echo "$OUT" | grep -c "^postgres$")
assert_eq "waltid all: postgres deduplicated" "$COUNT" "1"

# ============================================================================
echo "--- role_services inji ---"
OUT=$(role_services inji issuer)
assert_contains "inji issuer has inji-certify"    "$OUT" "inji-certify"
assert_not_contains "inji issuer no inji-verify"  "$OUT" "inji-verify-service"

OUT=$(role_services inji verifier)
assert_contains "inji verifier has inji-verify-service" "$OUT" "inji-verify-service"
assert_not_contains "inji verifier no inji-certify"     "$OUT" "inji-certify"

OUT=$(role_services inji holder)
assert_contains "inji holder has injiweb-ui"      "$OUT" "injiweb-ui"

# ============================================================================
echo "--- role_services credebl ---"
OUT=$(role_services credebl issuer)
assert_contains "credebl issuer has oid4vc-issuance"    "$OUT" "credebl-oid4vc-issuance"
assert_not_contains "credebl issuer no oid4vc-verif"    "$OUT" "credebl-oid4vc-verification"

OUT=$(role_services credebl verifier)
assert_contains "credebl verifier has oid4vc-verification" "$OUT" "credebl-oid4vc-verification"
assert_not_contains "credebl verifier no oid4vc-issuance"  "$OUT" "credebl-oid4vc-issuance"

OUT=$(role_services credebl holder)
assert_contains "credebl holder has cloud-wallet"   "$OUT" "credebl-cloud-wallet"

# ============================================================================
echo "--- infra_services ---"
OUT=$(infra_services "issuer")
assert_contains "issuer infra has keycloak"        "$OUT" "keycloak"
assert_contains "issuer infra has libretranslate"  "$OUT" "libretranslate"
assert_not_contains "issuer infra no wso2is"       "$OUT" "wso2is"

OUT=$(infra_services "issuer,verifier,holder")
assert_not_contains "all-roles: wso2is skipped (VERIFIABLY_SKIP_WSO2IS=1)" "$OUT" "wso2is"
export VERIFIABLY_SKIP_WSO2IS=0
IDP_WSO2IS=(wso2is)   # re-init since common.sh ran with SKIP=1
OUT=$(infra_services "issuer,verifier,holder")
assert_contains "all-roles + SKIP=0: wso2is included" "$OUT" "wso2is"
export VERIFIABLY_SKIP_WSO2IS=1
IDP_WSO2IS=()

# ============================================================================
echo ""
echo "Results: ${_PASS} passed, ${_FAIL} failed"
(( _FAIL == 0 )) && exit 0 || exit 1
