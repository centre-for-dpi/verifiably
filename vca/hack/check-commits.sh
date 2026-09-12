#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Checks commit subjects against Conventional Commits 1.0.0 (ADR-006 decision 2).
#
# Usage:
#   check-commits.sh <git-range>        check every commit in the range
#   check-commits.sh --subject <text>   check one subject line (used by tests)
#
# Grammar: <type>[(<scope>)][!]: <description>
# Allowed types: build chore ci docs feat fix perf refactor revert style test.
# Merge commits ("Merge ...") are skipped.
set -euo pipefail

types='build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test'
pattern="^(${types})(\([a-z0-9][a-z0-9._/-]*\))?!?: [^ ].*$"

check_subject() {
  local subject="$1"
  case "$subject" in
    "Merge "*) return 0 ;;
  esac
  if [[ ${#subject} -gt 100 ]]; then
    echo "too long (max 100): $subject"
    return 1
  fi
  if ! [[ "$subject" =~ $pattern ]]; then
    echo "not Conventional Commits: $subject"
    return 1
  fi
  return 0
}

if [[ "${1:-}" == "--subject" ]]; then
  check_subject "${2:-}"
  exit $?
fi

range="${1:-}"
if [[ -z "$range" ]]; then
  echo "usage: $0 <git-range> | --subject <text>" >&2
  exit 2
fi

fail=0
count=0
while IFS= read -r subject; do
  [[ -z "$subject" ]] && continue
  count=$((count + 1))
  if ! check_subject "$subject"; then
    fail=1
  fi
done < <(git log --format=%s "$range")

echo "checked $count commit subject(s) in $range"
exit $fail
