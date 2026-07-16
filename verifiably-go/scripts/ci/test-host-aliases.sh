#!/usr/bin/env bash
# Unit test for compute_host_aliases (scripts/common.sh) — the subdomain
# hairpin-NAT fix that pins public service subdomains to the caddy-public
# container IP via `docker run --add-host`. Pure logic: no Docker, no network.
#
#   Run:  bash scripts/ci/test-host-aliases.sh
#   CI:   exits non-zero on any failed assertion.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# common.sh sources .env(.example) + sets defaults; silence its chatter.
# shellcheck source=/dev/null
source "$DIR/scripts/common.sh" >/dev/null 2>&1

fail=0
pass() { printf 'PASS  %s\n' "$1"; }
bad()  { printf 'FAIL  %s\n' "$1"; fail=1; }

EXPECTED_SLUGS=$VERIFIABLY_PUBLIC_SLUGS
N=$(wc -w <<<"$EXPECTED_SLUGS")

# ── 1. subdomain mode: one --add-host pair per slug, all pinned to the ip ─────
out="$(compute_host_aliases example.com 10.0.0.5)"

for s in $EXPECTED_SLUGS; do
  if grep -qx -- "${s}.example.com:10.0.0.5" <<<"$out"; then
    pass "subdomain: ${s} pinned to caddy ip"
  else
    bad  "subdomain: ${s} missing or wrong ip"
  fi
done

n_flag=$(grep -cx -- '--add-host' <<<"$out")
n_val=$(grep -cE ':10\.0\.0\.5$' <<<"$out")
[[ "$n_flag" -eq "$N" ]] && pass "subdomain: $N --add-host flags" || bad "subdomain: expected $N --add-host flags, got $n_flag"
[[ "$n_val"  -eq "$N" ]] && pass "subdomain: $N pinned values"   || bad "subdomain: expected $N values, got $n_val"

# Tokens read into an array form well-shaped (--add-host, value) pairs.
mapfile -t arr < <(compute_host_aliases example.com 10.0.0.5)
[[ ${#arr[@]} -eq $((N * 2)) ]] && pass "array length is 2×slugs ($((N*2)))" || bad "array length ${#arr[@]} != $((N*2))"
[[ "${arr[0]}" == "--add-host" && "${arr[1]}" == *".example.com:10.0.0.5" ]] \
  && pass "array first pair is (--add-host, <fqdn>:<ip>)" || bad "array pair shape wrong: ${arr[0]} ${arr[1]:-}"

# ── 2. legacy host:port mode emits NOTHING (no domain and/or no ip) ───────────
[[ -z "$(compute_host_aliases '' '')"            ]] && pass "legacy: empty domain+ip → no output"  || bad "legacy: empty domain+ip leaked output"
[[ -z "$(compute_host_aliases example.com '')"   ]] && pass "legacy: domain but no ip → no output" || bad "legacy: domain-only leaked output"
[[ -z "$(compute_host_aliases '' 10.0.0.5)"      ]] && pass "legacy: ip but no domain → no output" || bad "legacy: ip-only leaked output"

echo "------------------------------------------------------------"
if [[ $fail -eq 0 ]]; then echo "OK — all compute_host_aliases assertions passed"; else echo "FAILURES above"; fi
exit $fail
