#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests for ste-lint.sh. Run: hack/ste-lint_test.sh

set -u

here=$(cd "$(dirname "$0")" && pwd)
lint="$here/ste-lint.sh"
data="$here/testdata/ste"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0

expect() {
  # expect <name> <pattern> <output>
  if printf '%s\n' "$3" | grep -q -- "$2"; then
    echo "ok   $1"
  else
    echo "FAIL $1: expected /$2/ in output:"
    printf '%s\n' "$3" | sed 's/^/     /'
    fail=1
  fi
}

reject() {
  # reject <name> <pattern> <output>
  if printf '%s\n' "$3" | grep -q -- "$2"; then
    echo "FAIL $1: did not expect /$2/ in output:"
    printf '%s\n' "$3" | sed 's/^/     /'
    fail=1
  else
    echo "ok   $1"
  fi
}

# 1. A clean file gives exit 0 and no output.
out=$("$lint" "$data/clean.md" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && [ -z "$out" ]; then
  echo "ok   clean file exits 0"
else
  echo "FAIL clean file: rc=$rc output=$out"; fail=1
fi

# 2. A bad markdown file gives exit 1 and the expected findings.
out=$("$lint" "$data/bad.md" 2>&1); rc=$?
[ "$rc" -eq 1 ] && echo "ok   bad file exits 1" || { echo "FAIL bad file rc=$rc"; fail=1; }
expect "passive was" "bad.md:3: passive: was started" "$out"
expect "banned in order to" "bad.md:4: banned-word: in order to -> to" "$out"
expect "long sentence" "bad.md:5: long-sentence: 2[0-9] words" "$out"
expect "passive is being" "bad.md:7: passive: is being updated" "$out"
expect "banned in table" "bad.md:13: banned-word: utilize -> use" "$out"

# 3. Proto comments are checked, proto code is not.
out=$("$lint" "$data/bad.proto" 2>&1); rc=$?
[ "$rc" -eq 1 ] && echo "ok   bad proto exits 1" || { echo "FAIL bad proto rc=$rc"; fail=1; }
expect "proto passive" "bad.proto:6: passive: was signed" "$out"
expect "proto banned" "bad.proto:6: banned-word: prior to -> before" "$out"
reject "proto code ignored" "bad.proto:8:" "$out"
reject "proto url ignored" "bad.proto:9:" "$out"

# 4. Dashes are reported and fixed. The fixture is built here so that the
#    repository holds no dash characters.
f="$tmp/dash.md"
printf 'Ports 80%s443 are open.\nRun the tool %s it is fast.\n' \
  "$(printf '\342\200\223')" "$(printf '\342\200\224')" > "$f"
out=$("$lint" "$f" 2>&1); rc=$?
[ "$rc" -eq 1 ] && echo "ok   dash file exits 1" || { echo "FAIL dash rc=$rc"; fail=1; }
expect "en dash found" "dash.md:1: dash:" "$out"
expect "em dash found" "dash.md:2: dash:" "$out"
out=$("$lint" --fix-dashes "$f" 2>&1); rc=$?
[ "$rc" -eq 0 ] && echo "ok   fixed file exits 0" || { echo "FAIL fix rc=$rc out=$out"; fail=1; }
fixed=$(cat "$f")
expect "number range becomes to" "Ports 80 to 443 are open." "$fixed"
expect "em dash becomes comma" "Run the tool, it is fast." "$fixed"

# 5. The word list has at least 60 entries.
n=$(grep -c -- '->' "$here/ste-words.txt")
[ "$n" -ge 60 ] && echo "ok   word list has $n entries" || { echo "FAIL word list has $n entries"; fail=1; }

# 6. No file argument is an error.
"$lint" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && echo "ok   no args exits 2" || { echo "FAIL no args rc=$rc"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "PASS"
else
  echo "FAIL"
fi
exit "$fail"
