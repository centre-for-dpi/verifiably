#!/bin/sh
# Unit test for scripts/ci/coverage-gate.sh — the per-function 100% statement
# coverage gate for internal/handlers. Exercises ONLY the parser/decision
# logic against fixture `go tool cover -func` output (via --from), so it needs
# no Go toolchain, no network and no docker.
#
#   Run:  sh scripts/ci/test-coverage-gate.sh
#   CI:   exits non-zero on any failed assertion.
set -u

DIR="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$DIR/scripts/ci/coverage-gate.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail=0
pass() { printf 'PASS  %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; fail=1; }

MOD=github.com/verifiably/verifiably-go/internal/handlers
FIX="$TMP/cover.txt"
printf '%s:55:\tBulkSource\t0.0%%\n'        "$MOD/bulk.go"           >  "$FIX"
printf '%s:95:\tbulkAreaData\t100.0%%\n'    "$MOD/bulk.go"           >> "$FIX"
printf '%s:738:\tqueryDBRows\t62.5%%\n'     "$MOD/bulk.go"           >> "$FIX"
printf '%s:40:\tdockerExecCapture\t0.0%%\n' "$MOD/esignet_config.go" >> "$FIX"
printf '%s:12:\tShow\t100.0%%\n'            "$MOD/docs.go"           >> "$FIX"
printf 'total:\t(statements)\t27.7%%\n'                              >> "$FIX"

run() { # run <exclusions-file> ; stdout+stderr -> $TMP/out, rc -> $rc
  sh "$GATE" --from "$FIX" --exclusions "$1" >"$TMP/out" 2>&1; rc=$?
}

# ── 1. no exclusions: every non-100% function fails, exit 1 ──────────────────
: > "$TMP/empty.txt"
run "$TMP/empty.txt"
[ "$rc" -eq 1 ] && pass "fail case: exit 1" || bad "fail case: expected exit 1, got $rc"
grep -q '^bulk.go:55 BulkSource 0.0%$' "$TMP/out"                    && pass "fail case: lists bulk.go:55 BulkSource 0.0%" || bad "fail case: BulkSource line missing"
grep -q '^bulk.go:738 queryDBRows 62.5%$' "$TMP/out"                 && pass "fail case: lists partial function" || bad "fail case: queryDBRows line missing"
grep -q '^esignet_config.go:40 dockerExecCapture 0.0%$' "$TMP/out"   && pass "fail case: lists dockerExecCapture" || bad "fail case: dockerExecCapture line missing"
grep -q 'bulkAreaData' "$TMP/out" && bad "fail case: 100% function wrongly listed" || pass "fail case: 100% functions not listed"
grep -q 'Show' "$TMP/out" && bad "fail case: docs.go Show wrongly listed" || pass "fail case: same-name-safe (docs.go Show not listed)"
grep -q '^total: 27.7%$' "$TMP/out"                                   && pass "fail case: total printed" || bad "fail case: total missing"
grep -q '^FAIL' "$TMP/out"                                            && pass "fail case: FAIL verdict" || bad "fail case: FAIL verdict missing"
grep -q '3 function(s) below 100%' "$TMP/out"                         && pass "fail case: failure count is 3" || bad "fail case: wrong failure count"

# ── 2. every non-100% function excluded: PASS, exit 0 ────────────────────────
cat > "$TMP/ok.txt" <<'X'
# comment line

bulk.go BulkSource            # fixture: not yet covered
bulk.go queryDBRows           # statements after pgx.Connect need a live Postgres
esignet_config.go dockerExecCapture  # dials the docker socket
X
run "$TMP/ok.txt"
[ "$rc" -eq 0 ] && pass "pass case: exit 0" || bad "pass case: expected exit 0, got $rc"
grep -q '^PASS' "$TMP/out"        && pass "pass case: PASS verdict" || bad "pass case: PASS verdict missing"
grep -q '^total: 27.7%$' "$TMP/out" && pass "pass case: total printed" || bad "pass case: total missing"
grep -q 'BulkSource' "$TMP/out"   && bad "pass case: excluded function still listed" || pass "pass case: excluded functions not listed"

# ── 3. exclusion that matches file but not function name is NOT a match ──────
cat > "$TMP/wrongfile.txt" <<'X'
docs.go BulkSource   # same func name, wrong file: must not excuse bulk.go BulkSource
bulk.go queryDBRows
esignet_config.go dockerExecCapture
X
run "$TMP/wrongfile.txt"
[ "$rc" -eq 1 ] && pass "file-scoped: exit 1" || bad "file-scoped: expected exit 1, got $rc"
grep -q '^bulk.go:55 BulkSource 0.0%$' "$TMP/out" && pass "file-scoped: bulk.go BulkSource still failing" || bad "file-scoped: bulk.go BulkSource wrongly excused"
grep -q '^unknown exclusion: docs.go BulkSource' "$TMP/out" && pass "file-scoped: reported as unknown exclusion" || bad "file-scoped: unknown exclusion not reported"

# ── 4. exclusion naming a non-existent function fails even when all covered ──
cat > "$TMP/stale.txt" <<'X'
bulk.go BulkSource
bulk.go queryDBRows
esignet_config.go dockerExecCapture
bulk.go noSuchFunction   # removed from the code base
X
run "$TMP/stale.txt"
[ "$rc" -eq 1 ] && pass "unknown exclusion: exit 1" || bad "unknown exclusion: expected exit 1, got $rc"
grep -q '^unknown exclusion: bulk.go noSuchFunction' "$TMP/out" && pass "unknown exclusion: named in output" || bad "unknown exclusion: not named"
grep -q '1 unknown exclusion(s)' "$TMP/out" && pass "unknown exclusion: counted" || bad "unknown exclusion: count missing"
grep -q '^FAIL' "$TMP/out" && pass "unknown exclusion: FAIL verdict" || bad "unknown exclusion: FAIL verdict missing"

# ── 5. missing exclusions file is treated as empty ───────────────────────────
sh "$GATE" --from "$FIX" --exclusions "$TMP/does-not-exist.txt" >"$TMP/out" 2>&1; rc=$?
[ "$rc" -eq 1 ] && grep -q '3 function(s) below 100%' "$TMP/out" && pass "missing exclusions file: treated as empty" || bad "missing exclusions file: unexpected behaviour (rc=$rc)"

# ── 6. bad usage ─────────────────────────────────────────────────────────────
sh "$GATE" --bogus >"$TMP/out" 2>&1; rc=$?
[ "$rc" -eq 2 ] && pass "unknown flag: exit 2" || bad "unknown flag: expected exit 2, got $rc"

echo "------------------------------------------------------------"
if [ "$fail" -eq 0 ]; then echo "OK — all coverage-gate assertions passed"; else echo "FAILURES above"; fi
exit $fail
