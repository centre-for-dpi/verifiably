# Independent Module Deployments — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow each DPG (Walt ID, CREDEBL, Inji) to be deployed with only the services needed for the requested roles (`issuer`, `verifier`, `holder`), and give the hub its own independent verifier so it never depends on federated nodes having a verifier active.

**Architecture:** A new `VERIFIABLY_ROLES` env var (comma-separated, default `issuer,verifier,holder`) selects which service subsets to start per DPG. The `--role` flag in `deploy.sh up` overrides the `.env` value for one run. The hub gets a `hub-verifier-api` (Walt ID verifier) added to its compose with a `verifier` Docker profile.

**Tech Stack:** Bash 4+, Docker Compose v2, Walt ID verifier-api (HOCON config), `awk` for dedup.

**Spec:** `docs/superpowers/specs/2026-06-11-independent-module-deployments-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `verifiably-go/tests/test_roles.sh` | Create | Bash test harness for role helper functions |
| `verifiably-go/scripts/common.sh` | Modify | Role arrays + `resolve_role`, `validate_roles`, `role_services`, `infra_services`; refactor `scenario_services` |
| `verifiably-go/deploy.sh` | Modify | Parse `--role` flag in `cmd_up`; update RAM check |
| `verifiably-go/.env.example` | Modify | Document `VERIFIABLY_ROLES` |
| `verifiably-go/deploy/compose/hub/.env.example` | Modify | Add `VERIFIABLY_ROLES=verifier` + `HUB_VERIFIER_PORT` + `HUB_VERIFIER_BASE_URL` |
| `verifiably-go/deploy/compose/hub/docker-compose.yml` | Modify | Add `hub-verifier-api` service (profile: verifier) |
| `verifiably-go/deploy/compose/hub/Caddyfile.hub` | Modify | Add `/verify` reverse-proxy route |
| `verifiably-go/deploy/compose/hub/config/verifier/web.conf` | Create | Walt ID verifier bind config |
| `verifiably-go/deploy/compose/hub/config/verifier/verifier-service.conf` | Create | Walt ID verifier baseUrl config |
| `verifiably-go/scripts/gen-backends.sh` | Modify | Add `verifier_url` top-level field per backend stanza |

---

## Task 1: Write failing tests for role helper functions

**Files:**
- Create: `verifiably-go/tests/test_roles.sh`

- [ ] **Step 1: Create the test file**

```bash
#!/usr/bin/env bash
# tests/test_roles.sh — tests for role-based deploy helper functions in common.sh.
# Run from repo root: bash verifiably-go/tests/test_roles.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- test harness -----------------------------------------------------------
_PASS=0; _FAIL=0
ok()   { echo "  PASS: $1"; (( _PASS++ )) || true; }
fail() { echo "  FAIL: $1"; (( _FAIL++ )) || true; }
assert_eq() {
  local label="$1" got="$2" want="$3"
  [[ "$got" == "$want" ]] && ok "$label" || fail "$label — got: $(printf '%q' "$got") want: $(printf '%q' "$want")"
}
assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  echo "$haystack" | grep -q "$needle" && ok "$label" || fail "$label — '$needle' not found in output"
}
assert_not_contains() {
  local label="$1" haystack="$2" needle="$3"
  echo "$haystack" | grep -q "$needle" && fail "$label — '$needle' should NOT be in output" || ok "$label"
}

# --- setup: stub .env so common.sh doesn't fail on missing file -------------
export VERIFIABLY_ENV_FILE=/dev/null
export VERIFIABLY_PUBLIC_HOST=localhost
export VERIFIABLY_SKIP_WSO2IS=1   # skip WSO2IS in tests to keep output simple

source "$SCRIPT_DIR/scripts/common.sh"

# ============================================================================
echo "--- resolve_role ---"
unset CLI_ROLE VERIFIABLY_ROLES
assert_eq "default when nothing set"        "$(resolve_role)" "issuer,verifier,holder"
export VERIFIABLY_ROLES=issuer
assert_eq ".env value used"                 "$(resolve_role)" "issuer"
export CLI_ROLE=verifier
assert_eq "CLI_ROLE overrides VERIFIABLY_ROLES" "$(resolve_role)" "verifier"
unset CLI_ROLE VERIFIABLY_ROLES

# ============================================================================
echo "--- validate_roles ---"
validate_roles "issuer"           && ok "issuer valid"        || fail "issuer valid"
validate_roles "verifier"         && ok "verifier valid"      || fail "verifier valid"
validate_roles "holder"           && ok "holder valid"        || fail "holder valid"
validate_roles "issuer,verifier"  && ok "multi-role valid"    || fail "multi-role valid"
validate_roles "issuer,verifier,holder" && ok "all-roles valid" || fail "all-roles valid"
( validate_roles "admin" 2>/dev/null ) && fail "unknown role should fail" || ok "unknown role rejected"
( validate_roles "" 2>/dev/null ) && fail "empty role should fail" || ok "empty role rejected"

# ============================================================================
echo "--- role_services waltid ---"
OUT=$(role_services waltid issuer)
assert_contains "waltid issuer has issuer-api"   "$OUT" "issuer-api"
assert_not_contains "waltid issuer no verifier-api" "$OUT" "verifier-api"
assert_not_contains "waltid issuer no wallet-api"   "$OUT" "wallet-api"

OUT=$(role_services waltid verifier)
assert_contains "waltid verifier has verifier-api"  "$OUT" "verifier-api"
assert_not_contains "waltid verifier no issuer-api" "$OUT" "issuer-api"

OUT=$(role_services waltid holder)
assert_contains "waltid holder has wallet-api"      "$OUT" "wallet-api"
assert_not_contains "waltid holder no issuer-api"   "$OUT" "issuer-api"

OUT=$(role_services waltid "issuer,verifier,holder")
assert_contains "waltid all has issuer-api"   "$OUT" "issuer-api"
assert_contains "waltid all has verifier-api" "$OUT" "verifier-api"
assert_contains "waltid all has wallet-api"   "$OUT" "wallet-api"
# dedup: postgres must appear exactly once
COUNT=$(echo "$OUT" | grep -c "^postgres$")
assert_eq "waltid all: postgres deduplicated" "$COUNT" "1"

# ============================================================================
echo "--- role_services inji ---"
OUT=$(role_services inji issuer)
assert_contains "inji issuer has inji-certify"    "$OUT" "inji-certify"
assert_not_contains "inji issuer no inji-verify"  "$OUT" "inji-verify-service"

OUT=$(role_services inji verifier)
assert_contains "inji verifier has inji-verify-service" "$OUT" "inji-verify-service"
assert_not_contains "inji verifier no inji-certify"     "$OUT" "inji-certify"

OUT=$(role_services inji holder)
assert_contains "inji holder has injiweb-ui"      "$OUT" "injiweb-ui"

# ============================================================================
echo "--- role_services credebl ---"
OUT=$(role_services credebl issuer)
assert_contains "credebl issuer has oid4vc-issuance"    "$OUT" "credebl-oid4vc-issuance"
assert_not_contains "credebl issuer no oid4vc-verif"    "$OUT" "credebl-oid4vc-verification"

OUT=$(role_services credebl verifier)
assert_contains "credebl verifier has oid4vc-verification" "$OUT" "credebl-oid4vc-verification"
assert_not_contains "credebl verifier no oid4vc-issuance"  "$OUT" "credebl-oid4vc-issuance"

OUT=$(role_services credebl holder)
assert_contains "credebl holder has cloud-wallet"   "$OUT" "credebl-cloud-wallet"

# ============================================================================
echo "--- infra_services ---"
OUT=$(infra_services "issuer")
assert_contains "issuer infra has keycloak"        "$OUT" "keycloak"
assert_contains "issuer infra has libretranslate"  "$OUT" "libretranslate"
assert_not_contains "issuer infra no wso2is"       "$OUT" "wso2is"

OUT=$(infra_services "issuer,verifier,holder")
assert_not_contains "all-roles: wso2is skipped (VERIFIABLY_SKIP_WSO2IS=1)" "$OUT" "wso2is"
export VERIFIABLY_SKIP_WSO2IS=0
IDP_WSO2IS=(wso2is)   # re-init since common.sh ran with SKIP=1
OUT=$(infra_services "issuer,verifier,holder")
assert_contains "all-roles + SKIP=0: wso2is included" "$OUT" "wso2is"
export VERIFIABLY_SKIP_WSO2IS=1
IDP_WSO2IS=()

# ============================================================================
echo ""
echo "Results: ${_PASS} passed, ${_FAIL} failed"
(( _FAIL == 0 )) && exit 0 || exit 1
```

- [ ] **Step 2: Run the tests — verify they fail**

```bash
bash verifiably-go/tests/test_roles.sh
```

Expected: errors about `resolve_role`, `role_services`, etc. not found. That's the failing-test state.

- [ ] **Step 3: Commit the test file**

```bash
git add verifiably-go/tests/test_roles.sh
git commit -m "test: add failing tests for role-based deploy helper functions"
```

---

## Task 2: Add role arrays and helper functions to common.sh

**Files:**
- Modify: `verifiably-go/scripts/common.sh:184-241` (service arrays section)
- Modify: `verifiably-go/scripts/common.sh:310-371` (scenario_services + helpers section)

- [ ] **Step 1: Replace the monolithic service arrays with role-specific ones**

In `verifiably-go/scripts/common.sh`, replace lines 184–241 (from `WALTID_SERVICES=(` to the closing `)` of `CREDEBL_SERVICES`) with:

```bash
# ── Walt ID — role-specific service arrays ───────────────────────────────────
WALTID_ISSUER_SVCS=(postgres caddy issuer-api)
WALTID_VERIFIER_SVCS=(postgres caddy verifier-api)
WALTID_HOLDER_SVCS=(postgres caddy wallet-api)
# Backward-compat aliases (not used internally — kept for external scripts)
WALTID_SERVICES=(postgres caddy issuer-api verifier-api wallet-api)
INJI_CORE_SERVICES=(
  certify-postgres inji-certify
  certify-preauth-postgres inji-certify-preauth-backend inji-preauth-proxy
  certify-nginx certify-preauth-nginx
  inji-verify-postgres inji-verify-service inji-verify-ui
  citizens-postgres vc-adapter
)

# ── Inji — role-specific service arrays ──────────────────────────────────────
INJI_ISSUER_SVCS=(
  certify-postgres inji-certify
  certify-preauth-postgres inji-certify-preauth-backend inji-preauth-proxy
  certify-nginx certify-preauth-nginx
  citizens-postgres
)
INJI_VERIFIER_SVCS=(
  inji-verify-postgres inji-verify-service inji-verify-ui
  vc-adapter
)
# INJI holder = INJIWEB_SERVICES defined below

INJIWEB_SERVICES=(
  injiweb-postgres injiweb-redis
  injiweb-mock-identity injiweb-esignet injiweb-oidc-ui
  injiweb-minio injiweb-datashare injiweb-mimoto injiweb-ui
)

# ── CREDEBL — role-specific service arrays ────────────────────────────────────
# Infra: required for every CREDEBL role
CREDEBL_INFRA_SVCS=(
  credebl-postgres credebl-redis credebl-nats
)
# Shared: lightweight orchestration services needed by all roles
CREDEBL_SHARED_SVCS=(
  credebl-seed credebl-platform-admin-bootstrap
  credebl-api-gateway credebl-user credebl-utility
  credebl-agent-provisioning credebl-agent-service
  credebl-ecosystem
)
# Issuer-specific: schema storage, notification, issuance pipeline
CREDEBL_ISSUER_SVCS=(
  credebl-minio credebl-minio-setup
  credebl-mailpit
  credebl-schema-file-server credebl-oob-redirector
  credebl-connection credebl-issuance credebl-ledger
  credebl-organization
  credebl-oid4vc-issuance
  credebl-oid4vci-rewriter
)
# Verifier-specific
CREDEBL_VERIFIER_SVCS=(
  credebl-connection credebl-verification
  credebl-oid4vc-verification
)
# Holder-specific
CREDEBL_HOLDER_SVCS=(
  credebl-cloud-wallet
)
# Backward-compat alias (union of all roles)
CREDEBL_SERVICES=(
  credebl-postgres credebl-redis credebl-nats
  credebl-minio credebl-minio-setup
  credebl-mailpit
  credebl-schema-file-server credebl-oob-redirector
  credebl-seed credebl-platform-admin-bootstrap
  credebl-api-gateway credebl-user credebl-utility
  credebl-connection credebl-issuance credebl-ledger
  credebl-organization credebl-verification
  credebl-agent-provisioning credebl-agent-service
  credebl-cloud-wallet credebl-oid4vc-issuance
  credebl-oid4vc-verification credebl-ecosystem
  credebl-oid4vci-rewriter
)
```

- [ ] **Step 2: Add helper functions after the arrays (before `# ---- helpers`)**

Insert the following four functions immediately before the `# ---- helpers` comment (currently at line 244 after the old service arrays):

```bash
# ── Role helpers ─────────────────────────────────────────────────────────────

# resolve_role: returns the active role string.
# Precedence: CLI_ROLE (set by deploy.sh --role flag)
#           > VERIFIABLY_ROLES (from .env)
#           > default "issuer,verifier,holder" (full deployment, backward-compat)
resolve_role() {
  printf '%s' "${CLI_ROLE:-${VERIFIABLY_ROLES:-issuer,verifier,holder}}"
}

# validate_roles <role-string>
# Exits non-zero on unknown roles or empty string.
# Warns (with interactive prompt) if 'holder' is requested without 'issuer'.
validate_roles() {
  local role_str="$1"
  if [[ -z "${role_str// /}" ]]; then
    red "VERIFIABLY_ROLES cannot be empty. Valid values: issuer, verifier, holder"
    return 1
  fi
  local r
  IFS=',' read -ra _roles <<< "$role_str"
  local has_issuer=0 has_holder=0
  for r in "${_roles[@]}"; do
    r="${r// /}"
    case "$r" in
      issuer|verifier|holder) ;;
      *) red "unknown role '$r'. Valid: issuer, verifier, holder"; return 1 ;;
    esac
    [[ "$r" == "issuer" ]] && has_issuer=1
    [[ "$r" == "holder" ]] && has_holder=1
  done
  if [[ "$has_holder" == "1" && "$has_issuer" == "0" ]]; then
    yellow "  Warning: deploying 'holder' without 'issuer' — wallet cannot receive new credentials."
    if [[ -t 0 ]]; then
      printf '  Continue? [y/N] '
      local _ans; read -r _ans
      [[ "$_ans" =~ ^[Yy]$ ]] || { red "Aborted."; return 1; }
    fi
  fi
}

# role_services <dpg> <role-string>
# Prints service names (one per line) for the given DPG × role combination.
# <role-string> may be comma-separated (e.g. "issuer,verifier").
# Output is deduplicated preserving first-occurrence order.
role_services() {
  local dpg="$1" role_str="$2"
  local -a _svc=()
  local r
  IFS=',' read -ra _roles <<< "$role_str"
  for r in "${_roles[@]}"; do
    r="${r// /}"
    case "${dpg}:${r}" in
      waltid:issuer)    _svc+=( "${WALTID_ISSUER_SVCS[@]}" ) ;;
      waltid:verifier)  _svc+=( "${WALTID_VERIFIER_SVCS[@]}" ) ;;
      waltid:holder)    _svc+=( "${WALTID_HOLDER_SVCS[@]}" ) ;;
      inji:issuer)      _svc+=( "${INJI_ISSUER_SVCS[@]}" ) ;;
      inji:verifier)    _svc+=( "${INJI_VERIFIER_SVCS[@]}" ) ;;
      inji:holder)      _svc+=( "${INJIWEB_SERVICES[@]}" ) ;;
      credebl:issuer)   _svc+=( "${CREDEBL_INFRA_SVCS[@]}" "${CREDEBL_SHARED_SVCS[@]}" "${CREDEBL_ISSUER_SVCS[@]}" ) ;;
      credebl:verifier) _svc+=( "${CREDEBL_INFRA_SVCS[@]}" "${CREDEBL_SHARED_SVCS[@]}" "${CREDEBL_VERIFIER_SVCS[@]}" ) ;;
      credebl:holder)   _svc+=( "${CREDEBL_INFRA_SVCS[@]}" "${CREDEBL_SHARED_SVCS[@]}" "${CREDEBL_HOLDER_SVCS[@]}" ) ;;
      *)
        red "unknown DPG:role '${dpg}:${r}' (valid roles: issuer, verifier, holder)"
        return 1
        ;;
    esac
  done
  printf '%s\n' "${_svc[@]}" | awk '!seen[$0]++'
}

# infra_services <role-string>
# Returns IdP and translator services for the given role set.
# WSO2IS is included only when VERIFIABLY_SKIP_WSO2IS=0|false OR when all 3 roles
# are active (matching prior full-deployment behaviour).
infra_services() {
  local role_str="$1"
  printf '%s\n' "${IDP_KEYCLOAK[@]}" "${TRANSLATOR_SERVICES[@]}"
  local role_count
  role_count=$(tr ',' '\n' <<< "$role_str" | grep -c '[^[:space:]]' || true)
  if [[ "$role_count" -ge 3 ]] || \
     [[ "${VERIFIABLY_SKIP_WSO2IS:-}" == "0" ]] || \
     [[ "${VERIFIABLY_SKIP_WSO2IS:-}" == "false" ]]; then
    printf '%s\n' "${IDP_WSO2IS[@]}"
  fi
}
```

- [ ] **Step 3: Refactor `scenario_services()` to use the new helpers**

Replace the current `scenario_services()` function (lines ~310–352) with:

```bash
scenario_services() {
  local scenario="$1"
  local _role
  _role=$(resolve_role)
  case "$scenario" in
    all)
      { role_services waltid "$_role"; role_services inji "$_role"; } \
        | awk '!seen[$0]++'
      infra_services "$_role"
      if [[ -z "$CREDEBL_API_URL" ]]; then
        role_services credebl "$_role"
      fi
      ;;
    waltid)
      role_services waltid "$_role"
      infra_services "$_role"
      ;;
    inji)
      role_services inji "$_role"
      infra_services "$_role"
      ;;
    credebl)
      role_services credebl "$_role"
      infra_services "$_role"
      ;;
    *)
      red "unknown scenario: $scenario (want: all | waltid | inji | credebl)"; return 1;;
  esac
}
```

- [ ] **Step 4: Run the tests — verify they pass**

```bash
bash verifiably-go/tests/test_roles.sh
```

Expected output ends with: `Results: N passed, 0 failed`

- [ ] **Step 5: Commit**

```bash
git add verifiably-go/scripts/common.sh
git commit -m "feat(deploy): role-based service arrays and helper functions in common.sh"
```

---

## Task 3: Parse `--role` flag in `deploy.sh`

**Files:**
- Modify: `verifiably-go/deploy.sh:49-52` (`cmd_up` function opening)

- [ ] **Step 1: Replace the opening of `cmd_up` to parse the flag**

Find the current `cmd_up()` opening (around lines 49–52):

```bash
cmd_up() {
  local scenario="${1:-}"
  [[ -n "$scenario" ]] || { red "usage: deploy.sh up <all|waltid|inji|credebl>"; exit 2; }
  scenario_services "$scenario" > /dev/null  # validate
```

Replace with:

```bash
cmd_up() {
  local scenario="${1:-}"
  shift || true
  # Parse optional flags after the scenario argument
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --role)
        [[ -n "${2:-}" ]] || { red "--role requires a value (e.g. --role issuer)"; exit 2; }
        CLI_ROLE="$2"; export CLI_ROLE; shift 2 ;;
      --role=*)
        CLI_ROLE="${1#--role=}"; export CLI_ROLE; shift ;;
      *)
        red "unknown option: $1"; exit 2 ;;
    esac
  done
  [[ -n "$scenario" ]] || {
    red "usage: deploy.sh up <all|waltid|inji|credebl> [--role issuer[,verifier[,holder]]]"
    exit 2
  }
  validate_roles "$(resolve_role)" || exit 1
  scenario_services "$scenario" > /dev/null  # validate scenario
```

- [ ] **Step 2: Update the RAM check to account for role-filtered scenarios**

Find the RAM check block in `cmd_up` (around line 113):

```bash
    local _needed_gib=4
    case "$scenario" in
      all|credebl) _needed_gib=8 ;;
      inji)        _needed_gib=6 ;;
    esac
```

Replace with:

```bash
    local _needed_gib=4
    local _active_role; _active_role=$(resolve_role)
    case "$scenario" in
      all|credebl) _needed_gib=8 ;;
      inji)        _needed_gib=6 ;;
    esac
    # Reduce estimate for single-role deployments
    local _role_count
    _role_count=$(tr ',' '\n' <<< "$_active_role" | grep -c '[^[:space:]]' || true)
    if [[ "$_role_count" -lt 3 ]]; then
      _needed_gib=$(( _needed_gib * _role_count / 3 ))
      (( _needed_gib < 2 )) && _needed_gib=2
    fi
```

- [ ] **Step 3: Smoke test — verify the flag is parsed correctly**

```bash
# Should print services without verifier-api
bash -c 'source verifiably-go/scripts/common.sh; CLI_ROLE=issuer scenario_services waltid' 2>/dev/null
```

Expected output includes `issuer-api` but NOT `verifier-api`.

```bash
# Should print an error and exit non-zero
bash verifiably-go/deploy.sh up waltid --role admin 2>&1 || true
```

Expected output: `unknown role 'admin'. Valid: issuer, verifier, holder`

- [ ] **Step 4: Commit**

```bash
git add verifiably-go/deploy.sh
git commit -m "feat(deploy): add --role flag to deploy.sh up; validate roles before compose"
```

---

## Task 4: Update `.env.example` files

**Files:**
- Modify: `verifiably-go/.env.example`
- Modify: `verifiably-go/deploy/compose/hub/.env.example`

- [ ] **Step 1: Add `VERIFIABLY_ROLES` to the main `.env.example`**

Find the section in `verifiably-go/.env.example` near `VERIFIABLY_SKIP_WSO2IS` (the variable it conceptually extends). Add after that block:

```bash
# Roles to deploy for the selected DPG. Comma-separated subset of:
#   issuer    — credential issuance services only
#   verifier  — credential verification services only
#   holder    — holder wallet / web UI services only
# Default (empty / unset): issuer,verifier,holder  — full deployment, backward-compat.
# Examples:
#   Issuance-only node:   VERIFIABLY_ROLES=issuer
#   Typical demo:         VERIFIABLY_ROLES=issuer,holder
#   Override per-run:     ./deploy.sh up waltid --role verifier
VERIFIABLY_ROLES=
```

- [ ] **Step 2: Add verifier vars to `deploy/compose/hub/.env.example`**

Append the following block to `verifiably-go/deploy/compose/hub/.env.example`, after the `VERIFIABLY_IMAGE` line:

```bash

# --- Hub roles ---
# Controls which services start in the hub compose stack.
# Default: verifier (the hub's primary function — trust registry + verification).
# Set to "issuer,verifier" only if this hub instance also needs to issue credentials.
VERIFIABLY_ROLES=verifier

# Walt ID verifier used by the hub for independent VC verification.
# Published port for the hub's internal verifier-api (no public exposure needed
# when behind Caddy — set to 127.0.0.1:7053 in production).
HUB_VERIFIER_PORT=7053

# Base URL the verifier-api advertises in presentation_definition_uri and request_uri.
# Must be browser-reachable. In TLS mode: https://<VERIFIABLY_PUBLIC_DOMAIN>/verify
# In localhost/dev mode: http://localhost:<HUB_VERIFIER_PORT>
HUB_VERIFIER_BASE_URL=http://localhost:7053

# Walt ID verifier image tag (pin to match your hub's Walt ID version)
WALTID_VERSION=0.18.2
```

- [ ] **Step 3: Commit**

```bash
git add verifiably-go/.env.example verifiably-go/deploy/compose/hub/.env.example
git commit -m "docs(deploy): add VERIFIABLY_ROLES to .env.example files"
```

---

## Task 5: Add `hub-verifier-api` to the hub compose stack

**Files:**
- Create: `verifiably-go/deploy/compose/hub/config/verifier/web.conf`
- Create: `verifiably-go/deploy/compose/hub/config/verifier/verifier-service.conf`
- Modify: `verifiably-go/deploy/compose/hub/docker-compose.yml`
- Modify: `verifiably-go/deploy/compose/hub/Caddyfile.hub`

- [ ] **Step 1: Create `config/verifier/web.conf`**

```
verifiably-go/deploy/compose/hub/config/verifier/web.conf
```

Content:
```
webHost = "0.0.0.0"
webPort = "${VERIFIER_API_PORT}"
```

- [ ] **Step 2: Create `config/verifier/verifier-service.conf`**

```
verifiably-go/deploy/compose/hub/config/verifier/verifier-service.conf
```

Content:
```
baseUrl = "${HUB_VERIFIER_BASE_URL}"
```

- [ ] **Step 3: Add `hub-verifier-api` service to `docker-compose.yml`**

In `verifiably-go/deploy/compose/hub/docker-compose.yml`, find the `libretranslate:` service block and insert the following **before** it (after the `grafana:` block's closing `networks:` section):

```yaml
  hub-verifier-api:
    image: waltid/verifier-api:${WALTID_VERSION:-0.18.2}
    container_name: hub-verifier-api
    restart: unless-stopped
    profiles:
      - verifier
    environment:
      VERIFIER_API_PORT: "7053"
      HUB_VERIFIER_BASE_URL: ${HUB_VERIFIER_BASE_URL:-http://localhost:7053}
    volumes:
      - ./config/verifier:/waltid-verifier-api/config:ro
    ports:
      - "${HUB_VERIFIER_PORT:-127.0.0.1:7053}:7053"
    networks:
      - hub

```

- [ ] **Step 4: Add `/verify` route to `Caddyfile.hub`**

In `verifiably-go/deploy/compose/hub/Caddyfile.hub`, add the `/verify` reverse proxy to the existing `{$HUB_DOMAIN}` block. Replace the block:

```
{$HUB_DOMAIN} {
	reverse_proxy verifiably-go:8080
}
```

With:

```
{$HUB_DOMAIN} {
	# /verify routes to the hub's own Walt ID verifier (independent of federated nodes)
	handle /verify* {
		reverse_proxy hub-verifier-api:7053
	}
	reverse_proxy verifiably-go:8080
}
```

- [ ] **Step 5: Verify compose config parses cleanly**

```bash
cd verifiably-go/deploy/compose/hub
docker compose config --quiet 2>&1
```

Expected: no YAML errors. The `hub-verifier-api` service appears when `--profile verifier` is added.

```bash
docker compose --profile verifier config --services 2>&1
```

Expected output includes `hub-verifier-api`.

- [ ] **Step 6: Commit**

```bash
git add verifiably-go/deploy/compose/hub/
git commit -m "feat(hub): add hub-verifier-api service (profile: verifier) for independent VC verification"
```

---

## Task 6: Add `verifier_url` field to `gen-backends.sh`

**Files:**
- Modify: `verifiably-go/scripts/gen-backends.sh`

This is forward-compatibility preparation for hub Phase 2 (orchestration). The field is populated when the `verifier` role is active; empty otherwise. The hub reads it to know whether to delegate or verify locally.

- [ ] **Step 1: Add role-awareness variables at the top of `backends_for()`**

In `verifiably-go/scripts/gen-backends.sh`, after the `esignet_url=$(url_for ...)` line (line ~30), add:

```bash
  # Determine verifier URLs to advertise based on active roles.
  # Empty = this node has no verifier; hub falls back to local verification (Phase 2).
  local _active_role
  _active_role=$(resolve_role)
  local _walt_verifier_advertised=""
  local _inji_verify_advertised=""
  local _credebl_verify_advertised=""
  if [[ "$_active_role" == *verifier* ]]; then
    _walt_verifier_advertised="$walt_verifier_url"
    _inji_verify_advertised="$inji_verify_svc_url"
    _credebl_verify_advertised=$(url_for credebl-verifier "$VERIFIABLY_PUBLIC_HOST" "$CREDEBL_API_PORT" "/api/v1/verification")
  fi
```

- [ ] **Step 2: Add `verifier_url` to `waltid_stanza` (line ~34)**

The `waltid_stanza` heredoc starts with `{`. Add `"verifier_url"` as the first field:

```json
    {
      "verifier_url": "${_walt_verifier_advertised}",
      "vendor": "Walt Community Stack",
```

- [ ] **Step 3: Add `verifier_url` to `inji_verify_stanza` (line ~164)**

The `inji_verify_stanza` heredoc starts with `{`. Add:

```json
    {
      "verifier_url": "${_inji_verify_advertised}",
      "vendor": "Inji Verify",
```

(Use the exact `"vendor":` value already present in the stanza — just prepend the `"verifier_url"` line.)

- [ ] **Step 4: Add `verifier_url` to `credebl_stanza` (line ~274)**

The `credebl_stanza` heredoc starts with `{`. Add:

```json
    {
      "verifier_url": "${_credebl_verify_advertised}",
      "vendor": "CREDEBL",
```

(Use the exact `"vendor":` value already present in the stanza.)

- [ ] **Step 5: Smoke test — verify JSON output for issuer-only role**

```bash
bash -c '
  export VERIFIABLY_ENV_FILE=verifiably-go/.env.example
  export CLI_ROLE=issuer
  source verifiably-go/scripts/common.sh
  source verifiably-go/scripts/gen-backends.sh
  backends_for waltid
  grep verifier_url verifiably-go/config/backends.json
'
```

Expected: `"verifier_url": ""`

```bash
bash -c '
  export VERIFIABLY_ENV_FILE=verifiably-go/.env.example
  export CLI_ROLE=issuer,verifier,holder
  source verifiably-go/scripts/common.sh
  source verifiably-go/scripts/gen-backends.sh
  backends_for waltid
  grep verifier_url verifiably-go/config/backends.json
'
```

Expected: `"verifier_url": "http://localhost:7003"` (or VERIFIABLY_HOSTS_PATTERN URL)

- [ ] **Step 6: Commit**

```bash
git add verifiably-go/scripts/gen-backends.sh
git commit -m "feat(backends): add verifier_url field per backend stanza based on active roles"
```

---

## Task 7: Run full test suite and smoke test

- [ ] **Step 1: Run role tests**

```bash
bash verifiably-go/tests/test_roles.sh
```

Expected: `Results: N passed, 0 failed`

- [ ] **Step 2: Validate issuer-only deploy path (dry run)**

```bash
# Dry-run: print services that would start for waltid issuer-only
source verifiably-go/scripts/common.sh
CLI_ROLE=issuer scenario_services waltid
```

Expected: `postgres`, `caddy`, `issuer-api`, `keycloak`, `libretranslate` — no `verifier-api`, no `wallet-api`, no `wso2is`.

- [ ] **Step 3: Validate default (backward-compat) path**

```bash
unset CLI_ROLE VERIFIABLY_ROLES
source verifiably-go/scripts/common.sh
scenario_services waltid
```

Expected: same as before — `postgres caddy issuer-api verifier-api wallet-api keycloak wso2is libretranslate` (wso2is present because default includes all 3 roles).

- [ ] **Step 4: Validate hub compose with verifier profile**

```bash
cd verifiably-go/deploy/compose/hub
docker compose --profile verifier config --services
```

Expected list includes: `postgres`, `verifiably-go`, `prometheus`, `grafana`, `libretranslate`, `hub-verifier-api`.

Without profile:

```bash
docker compose config --services
```

Expected list does NOT include `hub-verifier-api`.

- [ ] **Step 5: Final commit — update todo.md**

```bash
git add verifiably-go/tests/ docs/
git commit -m "chore: mark independent-module-deployments plan complete"
```

---

## Appendix: Testing the full flow manually

Once deployed, verify an issuer-only Walt ID node works:

```bash
./deploy.sh up waltid --role issuer
# Confirm verifier-api is NOT running
docker ps | grep verifier-api   # should return nothing for waltid
# Confirm issuer is healthy
curl -s http://localhost:7002/issuer-api/swagger | grep -q swagger && echo "issuer-api OK"
```

Verify the hub verifies independently:

```bash
# In deploy/compose/hub/ with VERIFIABLY_ROLES=verifier in .env
docker compose --profile verifier up -d
# Hub verifier should respond on 7053
curl -s http://localhost:7053/openapi | grep -q verifier && echo "hub-verifier-api OK"
```
