#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# secret-scan.sh: refuse a tree that tracks a secret (ADR-029 decision 6).
#
# Usage:
#   hack/secret-scan.sh [PATH...]
#
# The scan reads the files that git tracks. It never reads the history,
# because a purge of the history is a release step. See
# vca/docs/release-checklist.md.
#
# Rules:
#   keystore     a tracked .p12, .jks, .pfx, or .keystore file
#   private-key  a PEM private key header with key material after it
#   api-key      an apiKey value of 64 hex characters
#   password     a password value that is not a placeholder
#
# Output is "rule: file:line: detail", one finding per line.
# Exit status is 1 when it finds at least one secret, else 0.

set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
root=$(git rev-parse --show-toplevel)
cd "$root"

findings=$(mktemp)
trap 'rm -f "$findings"' EXIT INT TERM

if [ "$#" -gt 0 ]; then
  git ls-files -- "$@" > "$findings.files"
else
  git ls-files > "$findings.files"
fi
trap 'rm -f "$findings" "$findings.files"' EXIT INT TERM

report() { printf '%s\n' "$1" >> "$findings"; }

# Rule keystore: a key store never belongs in the tree.
while IFS= read -r file; do
  case "$file" in
    *.p12|*.jks|*.pfx|*.keystore)
      report "keystore: $file: a key store is tracked; generate it on the host instead"
      ;;
  esac
done < "$findings.files"

# Rule private-key: a PEM header with base64 key material on the next
# line. A header with a placeholder after it is documentation.
while IFS= read -r file; do
  [ -f "$file" ] || continue
  case "$file" in *.p12|*.jks|*.pfx|*.keystore|*.png|*.jpg|*.gif|*.pdf) continue ;; esac
  awk -v file="$file" '
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/ { pending = NR; next }
    pending && length($0) >= 40 && /^[A-Za-z0-9+\/=]+$/ {
      printf "private-key: %s:%d: a PEM private key is tracked\n", file, pending
      pending = 0
      next
    }
    { pending = 0 }
  ' "$file" >> "$findings" 2>/dev/null || true
done < "$findings.files"

# Rule api-key: 64 hex characters as an apiKey or api_key value.
# Rule password: a literal password value in a configuration file. A
# placeholder, a variable, and an empty value are allowed.
while IFS= read -r file; do
  [ -f "$file" ] || continue
  case "$file" in *.p12|*.jks|*.pfx|*.keystore|*.png|*.jpg|*.gif|*.pdf) continue ;; esac
  grep -nEIH '"?api[_]?[Kk]ey"?[[:space:]]*[:=][[:space:]]*"?[0-9a-fA-F]{64}"?' "$file" 2>/dev/null \
    | sed 's/^/api-key: /' >> "$findings" || true
  case "$file" in
    *.yaml|*.yml|*.json|*.properties|*.conf|*.ini|*.tf|*.env) ;;
    *) continue ;;
  esac
  grep -nEIH '(^|[[:space:]"])password"?[[:space:]]*:[[:space:]]*[^[:space:]]+' "$file" 2>/dev/null \
    | grep -vEi 'password"?[[:space:]]*:[[:space:]]*"?(\$|\{\{|""|'"''"'|<|REPLACE_ME|CHANGE|placeholder|example|null|~)' \
    | sed 's/^/password: /' >> "$findings" || true
done < "$findings.files"

# The allow list names a file per line, with a reason after a "#". A
# finding in such a file is a warning, not a failure. Every entry is a
# required removal of the first release, see vca/docs/release-checklist.md.
allow="$script_dir/secret-scan-allow.txt"
if [ -f "$allow" ]; then
  while IFS= read -r line; do
    path=${line%%#*}
    path=$(printf '%s' "$path" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -n "$path" ] || continue
    hits=$(grep -F ": $path:" "$findings" || true)
    if [ -n "$hits" ]; then
      printf '%s\n' "$hits" | sed 's/^/known exception, /'
      grep -vF ": $path:" "$findings" > "$findings.kept" || true
      mv "$findings.kept" "$findings"
    fi
  done < "$allow"
fi

count=$(wc -l < "$findings" | tr -d ' ')
if [ "$count" = "0" ]; then
  echo "secret-scan: no tracked secret found"
  exit 0
fi
cat "$findings"
echo "secret-scan: $count finding(s)" >&2
exit 1
