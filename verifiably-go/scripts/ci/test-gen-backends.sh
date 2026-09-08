#!/usr/bin/env bash
# Contract test for backends_for (scripts/gen-backends.sh): the walt.id DPG
# stanza must declare exactly the bulk sources the UI relies on. Pure
# rendering: no Docker, no network; the JSON is written to a temp dir.
#
#   Run:  bash scripts/ci/test-gen-backends.sh
#   CI:   exits non-zero on any failed assertion.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Hermetic: never read the operator's .env; /dev/null is not a regular file so
# common.sh skips sourcing and falls back to its built-in defaults.
export VERIFIABLY_ENV_FILE=/dev/null
export VERIFIABLY_PUBLIC_HOST=127.0.0.1
export VERIFIABLY_HOSTS_PATTERN=
export CREDEBL_API_URL=
# shellcheck source=/dev/null
source "$DIR/scripts/common.sh" >/dev/null 2>&1
# shellcheck source=/dev/null
source "$DIR/scripts/gen-backends.sh" >/dev/null 2>&1

fail=0
pass() { printf 'PASS  %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; fail=1; }

command -v jq >/dev/null || { bad "jq is required"; exit 1; }

# Render into the temp dir, not config/.
SCRIPT_DIR="$TMP"
mkdir -p "$TMP/config"
if backends_for waltid >/dev/null 2>"$TMP/err"; then
  pass "backends_for waltid renders"
else
  bad  "backends_for waltid failed: $(cat "$TMP/err")"
  exit 1
fi
out="$TMP/config/backends.json"
jq -e . "$out" >/dev/null 2>&1 && pass "backends.json is valid JSON" || { bad "backends.json is not valid JSON"; exit 1; }

walt='.backends[] | select(.type=="walt_community")'
keys=$(jq -r "$walt | .dpg.Capabilities[] | select(.Kind==\"bulk_source\") | .Key" "$out" | paste -sd, -)
[[ "$keys" == "csv,api,db" ]] && pass "walt_community bulk_source keys are exactly csv,api,db" || bad "walt_community bulk_source keys: got '$keys', want 'csv,api,db'"

# M3: the api chip is registry-capable — its capability text must say so.
api_body=$(jq -r "$walt | .dpg.Capabilities[] | select(.Kind==\"bulk_source\" and .Key==\"api\") | .Body" "$out")
[[ "$api_body" == *"Sunbird RC"* ]] && pass "walt_community api bulk_source Body mentions Sunbird RC" || bad "walt_community api Body does not mention Sunbird RC: '$api_body'"

n=$(jq "[$walt] | length" "$out")
[[ "$n" -eq 1 ]] && pass "exactly one walt_community backend" || bad "expected 1 walt_community backend, got $n"

if [[ $fail -eq 0 ]]; then
  echo "OK — all gen-backends assertions passed"
else
  echo "FAILURES above"
  exit 1
fi
