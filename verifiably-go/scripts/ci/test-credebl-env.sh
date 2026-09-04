#!/usr/bin/env bash
# Contract test for the CREDEBL environment pipeline:
#
#   1. ensure_credebl_env (scripts/bootstrap-credebl.sh) must produce every
#      secret gen-backends.sh's hard guard demands — including CREDEBL_PASSWORD,
#      which historically had no generator anywhere — and must keep an
#      operator-set value.
#   2. The generated credebl.env must seed PLATFORM_ADMIN_INITIAL_PASSWORD from
#      CREDEBL_PASSWORD (they drift apart otherwise: Keycloak seeds one value,
#      the adapter signs in with another) and must round-trip both
#      CREDEBL_PASSWORD and CREDEBL_CRYPTO_PRIVATE_KEY so re-runs do not rotate
#      them (a rotated crypto key silently invalidates every stored secret).
#   3. deploy.sh must call ensure_credebl_env BEFORE backends_for in every
#      command that renders config (up, run, config) — backends_for exits hard
#      when the CREDEBL secrets are missing.
#
# Pure logic: no Docker, no network; everything renders into a temp dir.
#
#   Run:  bash scripts/ci/test-credebl-env.sh
#   CI:   exits non-zero on any failed assertion.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hermetic: never read the operator's .env; /dev/null is not a regular file so
# common.sh skips sourcing and falls back to its built-in defaults.
export VERIFIABLY_ENV_FILE=/dev/null
export VERIFIABLY_PUBLIC_HOST=127.0.0.1
export VERIFIABLY_HOSTS_PATTERN=
export CREDEBL_API_URL=
# shellcheck source=/dev/null
source "$DIR/scripts/common.sh" >/dev/null 2>&1
# shellcheck source=/dev/null
source "$DIR/scripts/bootstrap-credebl.sh" >/dev/null 2>&1

fail=0
pass() { printf 'PASS  %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; fail=1; }

# Render into the temp dir, not the repo's deploy/ tree.
SCRIPT_DIR="$TMP"
ENVF="$TMP/deploy/compose/credebl/config/credebl.env"

# ── 1. defaults: every guard-checked secret exists after one call ─────────────
CREDEBL_PASSWORD= CREDEBL_CRYPTO_PRIVATE_KEY=
ensure_credebl_env >/dev/null 2>&1 || bad "ensure_credebl_env failed"
[[ -f "$ENVF" ]] && pass "credebl.env written" || { bad "credebl.env not written"; exit 1; }

[[ -n "$CREDEBL_PASSWORD" ]] \
  && pass "CREDEBL_PASSWORD is generated (got a value)" \
  || bad  "CREDEBL_PASSWORD still empty after ensure_credebl_env"
[[ "$CREDEBL_PASSWORD" == "admin" ]] \
  && pass "CREDEBL_PASSWORD defaults to the documented PoC value" \
  || bad  "CREDEBL_PASSWORD default is '$CREDEBL_PASSWORD', want 'admin'"
[[ -n "$CREDEBL_CRYPTO_PRIVATE_KEY" ]] \
  && pass "CREDEBL_CRYPTO_PRIVATE_KEY is generated" \
  || bad  "CREDEBL_CRYPTO_PRIVATE_KEY empty"

# ── 2. credebl.env contract ───────────────────────────────────────────────────
grep -qx "PLATFORM_ADMIN_INITIAL_PASSWORD=${CREDEBL_PASSWORD}" "$ENVF" \
  && pass "PLATFORM_ADMIN_INITIAL_PASSWORD seeded from CREDEBL_PASSWORD" \
  || bad  "PLATFORM_ADMIN_INITIAL_PASSWORD not seeded from CREDEBL_PASSWORD: $(grep '^PLATFORM_ADMIN_INITIAL_PASSWORD=' "$ENVF" || echo missing)"
grep -qx "CREDEBL_PASSWORD=${CREDEBL_PASSWORD}" "$ENVF" \
  && pass "CREDEBL_PASSWORD round-tripped in the internal-names block" \
  || bad  "CREDEBL_PASSWORD missing from credebl.env internal-names block"
grep -qx "CREDEBL_CRYPTO_PRIVATE_KEY=${CREDEBL_CRYPTO_PRIVATE_KEY}" "$ENVF" \
  && pass "CREDEBL_CRYPTO_PRIVATE_KEY round-tripped in the internal-names block" \
  || bad  "CREDEBL_CRYPTO_PRIVATE_KEY missing from credebl.env internal-names block"

# ── 3. re-run stability: nothing rotates ──────────────────────────────────────
_pw1="$CREDEBL_PASSWORD"; _key1="$CREDEBL_CRYPTO_PRIVATE_KEY"
CREDEBL_PASSWORD= CREDEBL_CRYPTO_PRIVATE_KEY=
ensure_credebl_env >/dev/null 2>&1 || bad "second ensure_credebl_env failed"
[[ "$CREDEBL_PASSWORD" == "$_pw1" ]] \
  && pass "CREDEBL_PASSWORD stable across re-runs" \
  || bad  "CREDEBL_PASSWORD rotated on re-run"
[[ "$CREDEBL_CRYPTO_PRIVATE_KEY" == "$_key1" ]] \
  && pass "CREDEBL_CRYPTO_PRIVATE_KEY stable across re-runs" \
  || bad  "CREDEBL_CRYPTO_PRIVATE_KEY rotated on re-run (breaks every stored secret)"

# ── 4. operator override is honoured ──────────────────────────────────────────
rm -rf "$TMP/deploy"
CREDEBL_PASSWORD="operator-chosen" CREDEBL_CRYPTO_PRIVATE_KEY=
ensure_credebl_env >/dev/null 2>&1 || bad "override ensure_credebl_env failed"
[[ "$CREDEBL_PASSWORD" == "operator-chosen" ]] \
  && pass "operator-set CREDEBL_PASSWORD kept" \
  || bad  "operator-set CREDEBL_PASSWORD clobbered: '$CREDEBL_PASSWORD'"
grep -qx "PLATFORM_ADMIN_INITIAL_PASSWORD=operator-chosen" "$ENVF" \
  && pass "operator-set password reaches PLATFORM_ADMIN_INITIAL_PASSWORD" \
  || bad  "operator-set password not seeded into credebl.env"

# ── 5. no hardcoded 'changeme' credential remains ─────────────────────────────
n_changeme=$(grep -c "changeme" "$DIR/scripts/bootstrap-credebl.sh" || true)
[[ "$n_changeme" -eq 0 ]] \
  && pass "no hardcoded 'changeme' credential in bootstrap-credebl.sh" \
  || bad  "bootstrap-credebl.sh still hardcodes 'changeme' ($n_changeme occurrence(s))"

# ── 6. ordering: ensure_credebl_env precedes backends_for in up/run/config ────
# backends_for hard-exits when the CREDEBL secrets are unset, so each command
# that renders config must prepare the CREDEBL env first (guarded by
# scenario_needs_credebl; the guard itself must sit before the render call).
fn_body() { awk "/^${1}\(\) \{/,/^\}/" "$DIR/deploy.sh"; }
for cmd in cmd_up cmd_run cmd_config; do
  body="$(fn_body "$cmd")"
  # Match only call sites (line starts with the command after indentation),
  # never mentions inside comments.
  e_line=$(grep -nE '^[[:space:]]*ensure_credebl_env([[:space:]]|$)' <<<"$body" | head -1 | cut -d: -f1)
  b_line=$(grep -nE '^[[:space:]]*backends_for[[:space:]]' <<<"$body" | head -1 | cut -d: -f1)
  if [[ -z "$b_line" ]]; then
    bad "$cmd: backends_for call not found (test needs updating)"
  elif [[ -z "$e_line" ]]; then
    bad "$cmd: never calls ensure_credebl_env before backends_for"
  elif (( e_line < b_line )); then
    pass "$cmd: ensure_credebl_env precedes backends_for"
  else
    bad "$cmd: ensure_credebl_env at line $e_line AFTER backends_for at $b_line"
  fi
done

if [[ $fail -eq 0 ]]; then
  echo "OK — all credebl-env assertions passed"
else
  echo "FAILURES above"
  exit 1
fi
