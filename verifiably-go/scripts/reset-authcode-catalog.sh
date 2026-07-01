#!/usr/bin/env bash
# reset-authcode-catalog.sh — wipe the Inji auth-code issuance catalog back to a
# pristine, empty state so you can test issuance from scratch.
#
# The auth-code "Claim with eSignet" catalog at /holder/wallet/inji is backed by
# certify.credential_config in the inji_certify DB (the auth-code Inji Certify
# stack: certify-postgres / inji-certify). Each credential the issuer UI creates
# (internal/handlers/inji_schema.go applyAuthcodeSchema) leaves five things; this
# script undoes ALL of them, for EVERY credential, in one go:
#
#   1. certify.credential_config row           (the catalog itself)
#   2. certify.vc_credential_owner row         (issuer owner-scoping)
#   3. a certify.vc_subject_<slug> VIEW        (per-cred extraction view)
#   4. a certify scope-query-mapping entry     (certify-postgres-dataprovider.properties)
#   5. two eSignet scope entries               (credential-scopes.properties)
#
# What it deliberately KEEPS: the base data table certify.vc_subject (the
# provisioned claim data), certify.identity_registry (enrolled foundational
# identities), and every non-scope property in the two .properties files. The
# scope-mapping lines are restored to their committed baseline (only
# mock_identity_vc_ldp — the fresh-install default), NOT blanked, so certify and
# eSignet start cleanly.
#
# certify + eSignet cache configs/scopes at startup, so we restart inji-certify +
# injiweb-esignet at the end (the same pair applyAuthcodeSchema restarts).
#
# Idempotent: safe to run repeatedly. Usage:
#   scripts/reset-authcode-catalog.sh          # prompts for confirmation
#   scripts/reset-authcode-catalog.sh --yes    # no prompt (scripted use)
set -euo pipefail

YES=0
[[ "${1:-}" == "--yes" || "${1:-}" == "-y" ]] && YES=1

VGO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERTIFY_PG="${CERTIFY_PG_CONTAINER:-certify-postgres}"
CERTIFY_DB="${CERTIFY_DB:-inji_certify}"
CERTIFY_PROPS="$VGO/deploy/compose/stack/inji/certify/certify-postgres-dataprovider.properties"
ESIGNET_PROPS="$VGO/deploy/compose/stack/inji/esignet/credential-scopes.properties"
CERTIFY_KEY='mosip.certify.data-provider-plugin.postgres.scope-query-mapping'
ESIGNET_KEYS=('mosip.esignet.supported.credential.scopes' 'mosip.esignet.credential.scope-resource-mapping')

psql() { docker exec -i "$CERTIFY_PG" psql -U postgres -d "$CERTIFY_DB" "$@"; }

# --- confirm ---------------------------------------------------------------
n=$(psql -tAc "SELECT count(*) FROM certify.credential_config" 2>/dev/null || echo '?')
echo "About to DELETE all ${n} auth-code credential(s) from ${CERTIFY_DB} (catalog, owners,"
echo "extraction views) and restore the scope files to their committed baseline."
if [[ "$YES" -ne 1 ]]; then
  read -r -p "Continue? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted."; exit 1; }
fi

# --- 1+2. delete credential_config + owner rows ----------------------------
psql -v ON_ERROR_STOP=1 <<'SQL'
DELETE FROM certify.vc_credential_owner;
DELETE FROM certify.credential_config;
SQL
echo "  cleared credential_config + vc_credential_owner"

# --- 3. drop the per-credential extraction views (NOT the base vc_subject table) ---
psql -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE v text;
BEGIN
  FOR v IN
    SELECT table_name FROM information_schema.views
    WHERE table_schema = 'certify' AND table_name LIKE 'vc_subject\_%'
  LOOP
    EXECUTE format('DROP VIEW IF EXISTS certify.%I CASCADE', v);
  END LOOP;
END $$;
SQL
echo "  dropped certify.vc_subject_* extraction views"

# --- 4+5. restore scope-property lines to their committed baseline ----------
# Replace only the scope-mapping line(s) in each runtime .properties file with the
# committed HEAD version of that exact property — every other property untouched.
restore_props() {
  local file="$1"; shift
  local gitpath; gitpath="$(git -C "$VGO" ls-files --full-name -- "$file" 2>/dev/null || true)"
  if [[ -z "$gitpath" ]]; then echo "  WARN: $file not tracked in git — skipping scope restore"; return; fi
  local baseline; baseline="$(git -C "$VGO" show "HEAD:$gitpath" 2>/dev/null || true)"
  [[ -n "$baseline" ]] || { echo "  WARN: no committed baseline for $gitpath — skipping"; return; }
  BASELINE="$baseline" FILE="$file" KEYS="$*" python3 - <<'PY'
import os
baseline = os.environ["BASELINE"].splitlines()
path = os.environ["FILE"]
keys = os.environ["KEYS"].split()
base = {}
for ln in baseline:
    for k in keys:
        if ln.startswith(k + "="):
            base[k] = ln
with open(path) as f:
    lines = f.read().splitlines()
for i, ln in enumerate(lines):
    for k in keys:
        if ln.startswith(k + "=") and k in base:
            lines[i] = base[k]
with open(path, "w") as f:
    f.write("\n".join(lines) + "\n")
print(f"  restored {len(base)}/{len(keys)} scope prop(s) in {os.path.basename(path)}")
PY
}
restore_props "$CERTIFY_PROPS" "$CERTIFY_KEY"
restore_props "$ESIGNET_PROPS" "${ESIGNET_KEYS[@]}"

# --- 6. restart certify + esignet so they drop cached configs/scopes --------
echo "  restarting inji-certify + injiweb-esignet ..."
docker restart inji-certify injiweb-esignet >/dev/null
printf "  waiting for inji-certify"
for _ in $(seq 1 40); do
  if curl -sk -o /dev/null -m 5 http://localhost:8090/v1/certify/.well-known/openid-credential-issuer 2>/dev/null; then
    echo " — ready"; break
  fi
  printf "."; sleep 4
done

echo "DONE — auth-code catalog is empty. Create a schema in the issuer UI to test issuance afresh."
