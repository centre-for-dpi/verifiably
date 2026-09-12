#!/usr/bin/env bash
# Fails when any package is below the floor (argument 1, percent).
# Packages named core/... must be at 100.
set -euo pipefail
cd "$(dirname "$0")/.."
floor="${1:-90}"
if [[ -n "${GO_TEST_CMD:-}" ]]; then
  # shellcheck disable=SC2086
  out=$($GO_TEST_CMD)
else
  out=$(go test -cover -count=1 ./...)
fi
echo "$out"
fail=0
while read -r line; do
  # "ok <pkg> 0.1s coverage: ..." or "<pkg> coverage: 0.0% ..." (no test files)
  pkg=$(awk '{ if ($1 == "ok") print $2; else print $1 }' <<<"$line")
  pct=$(grep -oE '[0-9]+\.[0-9]+%' <<<"$line" | head -1 | tr -d '%')
  [ -z "$pct" ] && continue
  want="$floor"
  case "$pkg" in */core/*|*/core) want=100 ;; */gen/*) continue ;; */cmd/*) continue ;; esac
  if awk -v p="$pct" -v w="$want" 'BEGIN{exit !(p<w)}'; then
    echo "FAIL: $pkg coverage $pct% below $want%"; fail=1
  fi
done < <(grep 'coverage:' <<<"$out")
exit $fail
