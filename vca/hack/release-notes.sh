#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Writes a CHANGELOG section from Conventional Commits (ADR-006 decision 2).
#
# Usage: release-notes.sh <from-ref> <to-ref> [version]
#   from-ref  the previous tag, or an empty string for the whole history
#   to-ref    the new tag or HEAD
#   version   the heading text (default: to-ref)
#
# Sections: Breaking (footer "BREAKING CHANGE:" or "!" after the type),
# Features (feat), Fixes (fix). Other types are listed under Other.
set -euo pipefail

from="${1:-}"
to="${2:-HEAD}"
version="${3:-$to}"

if [[ -n "$from" ]]; then
  range="${from}..${to}"
else
  range="$to"
fi

subject_re='^([a-z]+)(\(([^)]+)\))?(!)?: (.*)$'

breaking=()
features=()
fixes=()
other=()

# Each record: <hash>\x1f<subject>\x1f<body>\x1e
while IFS=$'\x1f' read -r -d $'\x1e' hash subject body; do
  hash="${hash//[$'\n\r ']/}"
  [[ -z "$hash" ]] && continue
  case "$subject" in "Merge "*) continue ;; esac
  short="${hash:0:7}"
  if [[ "$subject" =~ $subject_re ]]; then
    type="${BASH_REMATCH[1]}"
    scope="${BASH_REMATCH[3]}"
    bang="${BASH_REMATCH[4]}"
    desc="${BASH_REMATCH[5]}"
  else
    type=""
    scope=""
    bang=""
    desc="$subject"
  fi
  entry="$desc ($short)"
  [[ -n "$scope" ]] && entry="**$scope:** $entry"

  if [[ -n "$bang" ]] || grep -qE '^BREAKING[ -]CHANGE: ' <<<"$body"; then
    note=$(grep -E '^BREAKING[ -]CHANGE: ' <<<"$body" | head -1 | sed -E 's/^BREAKING[ -]CHANGE: //')
    [[ -n "$note" ]] && entry="$entry: $note"
    breaking+=("$entry")
  fi
  case "$type" in
    feat) features+=("$entry") ;;
    fix) fixes+=("$entry") ;;
    *) other+=("$entry") ;;
  esac
done < <(git log --format=$'%H\x1f%s\x1f%b\x1e' "$range")

print_section() {
  local title="$1"
  shift
  [[ $# -eq 0 ]] && return 0
  echo
  echo "### $title"
  echo
  local e
  for e in "$@"; do
    echo "- $e"
  done
}

echo "## $version ($(date -u +%Y-%m-%d))"
print_section "Breaking" "${breaking[@]+"${breaking[@]}"}"
print_section "Features" "${features[@]+"${features[@]}"}"
print_section "Fixes" "${fixes[@]+"${fixes[@]}"}"
print_section "Other" "${other[@]+"${other[@]}"}"
