#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Tests check-commits.sh against good and bad subjects.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-commits.sh"

good=(
  "feat: add issuer service"
  "feat(issuer): add issuer service"
  "fix(core/did): reject empty method"
  "feat(api)!: drop v0 endpoints"
  "docs: describe release flow"
  "ci: add nightly workflow"
  "chore(deps): bump protobuf"
  "refactor!: rename package"
  "Merge pull request #1 from x/y"
)
bad=(
  "Add issuer service"
  "feat add issuer service"
  "feat:add issuer service"
  "feat(): empty scope"
  "feat(Issuer): upper case scope"
  "feature: unknown type"
  "fix(core):  two spaces"
  "fix:"
  "wip"
  ""
)

fail=0
for s in "${good[@]}"; do
  if ! "$script" --subject "$s" >/dev/null; then
    echo "FAIL: expected pass: $s"
    fail=1
  fi
done
for s in "${bad[@]}"; do
  if "$script" --subject "$s" >/dev/null; then
    echo "FAIL: expected reject: $s"
    fail=1
  fi
done

# A too-long subject is rejected.
long="feat: $(printf 'x%.0s' $(seq 1 100))"
if "$script" --subject "$long" >/dev/null; then
  echo "FAIL: expected reject: long subject"
  fail=1
fi

# The range mode works on the current repository.
if git -C "$here" rev-parse HEAD >/dev/null 2>&1; then
  if ! "$script" HEAD~1..HEAD >/dev/null; then
    echo "FAIL: range mode rejected HEAD~1..HEAD"
    fail=1
  fi
fi

if [[ $fail -eq 0 ]]; then
  echo "PASS: check-commits.sh (${#good[@]} good, $((${#bad[@]} + 1)) bad)"
fi
exit $fail
