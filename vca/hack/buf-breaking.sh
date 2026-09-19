#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# buf-breaking.sh: run "buf breaking" for the proto module (ADR-003
# decision 4).
#
# Usage:
#   hack/buf-breaking.sh
#
# The script compares against the last v* release tag. A repository with
# no tag compares against the merge base with main instead, so a pull
# request before the first release still gets the check. A repository
# with neither a tag nor a main branch has nothing to compare against,
# so the script prints a message and exits 0.
#
# Environment:
#   BUF_BREAKING_REF  compare against this git reference and nothing else.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v buf >/dev/null 2>&1; then
  echo "buf-breaking: skip, buf is not on PATH (run make bootstrap)" >&2
  exit 0
fi

# has_proto reports whether the reference holds vca/proto.
has_proto() {
  local ref="$1" listing
  listing=$(git ls-tree -d "$ref" vca/proto 2>/dev/null || true)
  [ -n "$listing" ]
}

# compare runs buf breaking against one git reference.
compare() {
  local ref="$1" kind="$2"
  echo "buf-breaking: comparing against the $kind $ref"
  buf breaking --against "../.git#ref=${ref},subdir=vca"
}

ref="${BUF_BREAKING_REF:-}"
if [ -n "$ref" ]; then
  compare "$ref" "reference"
  exit 0
fi

tag=$(git tag --list 'v*' --sort=-v:refname | head -1)
if [ -n "$tag" ] && has_proto "$tag"; then
  compare "$tag" "release tag"
  exit 0
fi
if [ -n "$tag" ]; then
  echo "buf-breaking: the tag $tag has no vca/proto directory"
fi

for base in origin/main main; do
  if ! git rev-parse --verify --quiet "$base" >/dev/null; then
    continue
  fi
  merge_base=$(git merge-base HEAD "$base" 2>/dev/null || true)
  if [ -z "$merge_base" ] || ! has_proto "$merge_base"; then
    continue
  fi
  compare "$merge_base" "merge base with $base"
  exit 0
done

echo "buf-breaking: no release tag and no main branch, so there is nothing to compare against"
exit 0
