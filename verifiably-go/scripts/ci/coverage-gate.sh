#!/bin/sh
# coverage-gate.sh — per-function statement-coverage gate for internal/handlers.
#
# A function PASSES iff `go tool cover -func` reports 100.0% for it, or its
# "<file.go> <func>" pair is listed in scripts/ci/coverage-exclusions.txt.
# The gate PASSES iff every function passes and `go vet ./...` is clean.
# The package total is printed but not gated.
#
# Written in POSIX sh (no bash) so it runs unchanged inside golang:*-alpine.
#
#   Usage (from verifiably-go/):
#     sh scripts/ci/coverage-gate.sh [--pkg ./internal/handlers/]
#                                   [--exclusions scripts/ci/coverage-exclusions.txt]
#                                   [--from <cover -func output>]   # skip go test/vet; parse a file
#   Exit: 0 PASS · 1 FAIL (any function below 100%, or an exclusion naming a
#         function that does not exist, or go vet failure) · 2 usage.
set -eu

PKG=./internal/handlers/
EXCL=scripts/ci/coverage-exclusions.txt
FROM=
while [ $# -gt 0 ]; do
  case "$1" in
    --pkg)        PKG=$2; shift 2 ;;
    --exclusions) EXCL=$2; shift 2 ;;
    --from)       FROM=$2; shift 2 ;;
    -h|--help)    sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "coverage-gate: unknown argument: $1" >&2; exit 2 ;;
  esac
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FUNCS="$TMP/func.txt"

if [ -n "$FROM" ]; then
  cp "$FROM" "$FUNCS"
else
  echo "coverage-gate: go vet ./..."
  go vet ./...
  echo "coverage-gate: go test -count=1 -coverprofile $PKG"
  go test -count=1 -coverprofile="$TMP/cover.out" "$PKG" >/dev/null
  go tool cover -func="$TMP/cover.out" > "$FUNCS"
fi

[ -f "$EXCL" ] || EXCL=/dev/null

# awk does all the work: pass 1 reads the exclusions (file func), pass 2 the
# cover -func lines. Output is deterministic (input order) and the verdict is
# the last line. Exit status carried through awk's exit code.
awk -v excl="$EXCL" '
BEGIN {
  while ((getline line < excl) > 0) {
    sub(/#.*/, "", line)               # strip trailing comment
    n = split(line, f, /[ \t]+/)
    k = 0
    for (i = 1; i <= n; i++) if (f[i] != "") { k++; tok[k] = f[i] }
    if (k == 0) continue               # blank / comment-only line
    if (k != 2) { print "malformed exclusion line: " line; bad_excl++; continue }
    key = tok[1] " " tok[2]
    if (!(key in ex)) { nex++; exorder[nex] = key }
    ex[key] = 1
  }
  close(excl)
}
/^total:/ { total = $NF; next }
NF >= 3 {
  loc = $1; fn = $2; pct = $3
  sub(/:$/, "", loc)                   # "…/bulk.go:55:" -> "…/bulk.go:55"
  file = loc; sub(/:[0-9]+$/, "", file); sub(/.*\//, "", file)   # -> bulk.go
  line = loc; sub(/.*:/, "", line)
  key = file " " fn
  seen[key] = 1
  if (pct == "100.0%") next
  if (key in ex) next
  print file ":" line " " fn " " pct
  nfail++
}
END {
  for (i = 1; i <= nex; i++) { k = exorder[i]; if (!(k in seen)) { print "unknown exclusion: " k; nunk++ } }
  print "total: " total
  if (nfail + nunk + bad_excl == 0) { print "PASS — every function 100.0% or excluded"; exit 0 }
  print "FAIL — " nfail + 0 " function(s) below 100%, " nunk + 0 " unknown exclusion(s), " bad_excl + 0 " malformed exclusion line(s)"
  exit 1
}' "$FUNCS"
