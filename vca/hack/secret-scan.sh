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
#   password     a password, secret or key value that is not a placeholder,
#                as key: value or as key=value
#   peer-identity  a tracked identity file, key file or authority key of the
#                peer authority (ADR-075), whatever it holds
#   private-jwk  a private JWK: a "d" member in a JSON file, or a key=value
#                whose value is a base64url JWK with a "d" member. Test
#                doubles under testdata and in _test.go files stay out.
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

# Rule peer-identity: the identity files, the key files and the
# authority key of ADR-075. The .gitignore of each peer directory keeps
# them out, so a tracked one is a forced add.
while IFS= read -r file; do
  case "$file" in
    peer/authority.pem|*/peer/authority.pem|peer/*.env|*/peer/*.env|peer/keys/*|*/peer/keys/*)
      report "peer-identity: $file: an identity of the peer authority is tracked; vca setup writes it on the host"
      ;;
  esac
done < "$findings.files"

# Rule private-jwk: a private JWK in a JSON file, or as the base64url
# value of a key=value line.
while IFS= read -r file; do
  [ -f "$file" ] || continue
  case "$file" in
    */testdata/*|testdata/*|*_test.go) continue ;;
    *.json|*.jwk|*.jwks) ;;
    *.env|*.properties|*.conf|*.ini) ;;
    *) continue ;;
  esac
  grep -nEIH '"d"[[:space:]]*:[[:space:]]*"[A-Za-z0-9_-]{20,}"' "$file" 2>/dev/null \
    | awk -F: '{ printf "private-jwk: %s:%s: a private JWK is tracked\n", $1, $2 }' >> "$findings" || true
  grep -nEI '^[^#]*[A-Za-z0-9_]*KEY"?[[:space:]]*=[[:space:]]*"?[A-Za-z0-9_-]{40,}"?[[:space:]]*$' "$file" 2>/dev/null \
    | while IFS= read -r hit; do
        line=${hit%%:*}
        value=$(printf '%s' "${hit#*=}" | tr -d ' "')
        pad=$(( (4 - ${#value} % 4) % 4 ))
        while [ "$pad" -gt 0 ]; do value="$value="; pad=$((pad - 1)); done
        if printf '%s' "$value" | tr '_-' '/+' | base64 -d 2>/dev/null | grep -q '"d"'; then
          report "private-jwk: $file:$line: a base64url private JWK is tracked"
        fi
      done
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
  # The key=value form of a .properties, .conf, .ini or .env file
  # (ADR-055 decision 5). The key ends in password, secret, secretkey,
  # clientsecret, pin, or a key of an API, a token or an encryption.
  case "$file" in
    *.properties|*.conf|*.ini|*.env) ;;
    *) continue ;;
  esac
  grep -nEIH '^[^#]*([Pp]assword|[Ss]ecret|[Ss]ecret[_.-]?[Kk]ey|[Cc]lient[_.-]?[Ss]ecret|[Pp]in|(api|token|encryption)[_.-]?[Kk]ey)"?[[:space:]]*=[[:space:]]*[^[:space:]]+' "$file" 2>/dev/null \
    | grep -vEi '=[[:space:]]*"?(\$|\{\{|""|'"''"'|<|REPLACE_ME|CHANGE|placeholder|example|null|~)' \
    | grep -vEi '(uri|url|file|path|alias|name|type|id|size|length|enabled|expiry|interval|method|methods|algorithm|store|location)[[:space:]]*=' \
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
