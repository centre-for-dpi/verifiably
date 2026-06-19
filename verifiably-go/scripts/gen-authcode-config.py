#!/usr/bin/env python3
"""gen-authcode-config.py — generate the verifiably AUTH-CODE Inji Certify config.

Emits two files into deploy/compose/stack/inji/certify/:

  init-authcode.sql
      Self-contained schema for the auth-code (authorization_code via eSignet)
      Certify instance. Reuses the DDL from init-preauth.sql, then adds:
        * certify.vc_subject  — a verifiably-owned dynamic claims table. The
          PostgresDataProviderPlugin reads a row keyed by individual_id (matched
          to the eSignet token `sub`) at issuance time. Nothing is seeded.
        * ONE generic VerifiablePersonCredential credential_config (no farmer /
          workshop data). vc_template mirrors injicertify/db.go buildVCTemplate.

  certify-postgres-dataprovider.properties
      Same base as certify-csvdp-farmer.properties but swaps the data provider to
      PostgresDataProviderPlugin + a scope->query mapping over certify.vc_subject.

Generic for verifiably; the colombo/farmer config is reference-only.
"""
import base64
import json
import os

CERTDIR = os.environ.get(
    "CERTDIR", "/root/verifiably/verifiably-go/deploy/compose/stack/inji/certify"
)

# --- the generic credential shape ------------------------------------------
TYPES = ["VerifiableCredential", "VerifiablePersonCredential"]  # alpha-sorted
FIELDS = ["fullName", "givenName", "familyName", "gender",
          "dateOfBirth", "email", "phoneNumber"]
LABELS = {"fullName": "Full Name", "givenName": "Given Name",
          "familyName": "Family Name", "gender": "Gender",
          "dateOfBirth": "Date of Birth", "email": "Email",
          "phoneNumber": "Phone Number"}
VOCAB = "https://vocab.verifiably.local/"
SCOPE = "mock_identity_vc_ldp"          # reuse eSignet's already-wired scope (Flow C)
CONFIG_KEY = "VerifiablePersonCredential"

# --- vc_template: mirror injicertify/db.go buildVCTemplate (VCDM 1.1) -------
terms = {"@vocab": VOCAB}
for t in TYPES:
    if t != "VerifiableCredential":
        terms[t] = VOCAB + t
for f in FIELDS:
    terms[f] = VOCAB + f
sub = {"id": "${_holderId}"}
for f in FIELDS:
    sub[f] = "${" + f + "}"
template = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
        terms,
    ],
    "issuer": "${_issuer}",
    "type": TYPES,
    "issuanceDate": "${validFrom}",
    "expirationDate": "${validUntil}",
    "credentialSubject": sub,
}
B64 = base64.b64encode(json.dumps(template, indent=2).encode()).decode()

display = json.dumps([{
    "name": "Verifiable Person Credential", "locale": "en",
    "logo": {"url": "https://verifiably.id/static/credential-logo.svg",
             "alt_text": "Verifiably"},
    "background_color": "#0f172a", "text_color": "#FFFFFF",
    "background_image": {"uri": "https://verifiably.id/static/credential-logo.svg"},
}])
credential_subject = json.dumps(
    {f: {"display": [{"name": LABELS[f], "locale": "en"}]} for f in FIELDS})
display_order = "ARRAY[" + ", ".join("'%s'" % f for f in FIELDS) + "]"

# --- certify.vc_subject DDL -------------------------------------------------
cols_ddl = ",\n".join('    "%s"%sVARCHAR' % (f, " " * (16 - len(f)))
                      for f in FIELDS)
vc_subject_ddl = """
-- ---------------------------------------------------------------------------
-- certify.vc_subject — verifiably-owned DYNAMIC claims table for the auth-code
-- flow. PostgresDataProviderPlugin reads one row keyed by individual_id (matched
-- to the eSignet token `sub`); the returned columns fill the vc_template ${{...}}
-- markers. Provisioning writes a row per holder -- NOTHING is seeded here.
-- Decoupled from the upstream mock-identity identity_json schema by design.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS certify.vc_subject (
    individual_id   VARCHAR(64) PRIMARY KEY,
{cols},
    cr_dtimes       TIMESTAMP DEFAULT NOW(),
    upd_dtimes      TIMESTAMP
);
""".format(cols=cols_ddl)

# --- the generic credential_config INSERT (29 cols, mirrors init-preauth) ---
insert = """
-- ---------------------------------------------------------------------------
-- VerifiablePersonCredential -- generic W3C VCDM 1.1 identity credential issued
-- over the authorization_code flow. Claims come dynamically from
-- certify.vc_subject via PostgresDataProviderPlugin (certify-postgres-dataprovider
-- .properties). @context mirrors injicertify/db.go (VC base + Ed25519 suite +
-- inline @vocab) so strict-JSON-LD wallets can hold it.
-- ---------------------------------------------------------------------------
INSERT INTO certify.credential_config (
    credential_config_key_id, config_id, status, vc_template, doctype, sd_jwt_vct,
    context, credential_type, credential_format, did_url,
    key_manager_app_id, key_manager_ref_id, signature_algo, signature_crypto_suite,
    sd_claim, display, display_order, scope,
    cryptographic_binding_methods_supported, credential_signing_alg_values_supported,
    proof_types_supported, credential_subject, mso_mdoc_claims, plugin_configurations,
    credential_status_purpose, qr_settings, qr_signature_algo, cr_dtimes, upd_dtimes
) VALUES (
    '{key}',
    gen_random_uuid()::VARCHAR(255),
    'active',
    '{b64}',
    NULL,
    NULL,
    'https://www.w3.org/2018/credentials/v1',
    '{ctype}',
    'ldp_vc',
    'did:web:certify-nginx',
    'CERTIFY_VC_SIGN_ED25519',
    'ED25519_SIGN',
    'EdDSA',
    'Ed25519Signature2020',
    NULL,
    '{display}'::JSONB,
    {display_order},
    '{scope}',
    ARRAY['did:jwk'],
    ARRAY['Ed25519Signature2020'],
    '{{"jwt": {{"proof_signing_alg_values_supported": ["RS256", "ES256"]}}}}'::JSONB,
    '{credsub}'::JSONB,
    NULL,
    NULL,
    ARRAY['revocation'],
    NULL,
    NULL,
    NOW(),
    NULL
);
""".format(key=CONFIG_KEY, b64=B64, ctype=",".join(TYPES), display=display,
           display_order=display_order, scope=SCOPE, credsub=credential_subject)

# --- assemble init-authcode.sql --------------------------------------------
# Base on init.sql (the auth-code instance's original seed: correct DID
# did:web:certify-nginx + the key_policy_def rows Certify's keymanager needs at
# boot). Keep ALL of it EXCEPT the farmer credential_config INSERTs: take the DDL
# prefix (up to the first credential_config INSERT) and the suffix from the first
# key_policy_def INSERT onward (the 8 key policies + any trailing seeds). Dropping
# that suffix is what crashed inji-certify with "ApplicationId not found in Key
# Policy" (AppConfig.initKeys) — do NOT slice it away again.
src = open(os.path.join(CERTDIR, "init.sql")).read()
idx_cc = src.find("INSERT INTO certify.credential_config")
idx_kp = src.find("INSERT INTO certify.key_policy_def")
assert 0 < idx_cc < idx_kp, "could not locate credential_config/key_policy_def INSERTs in init.sql"
ddl = src[:idx_cc].rstrip()
seed_suffix = src[idx_kp:]

header = (
    "-- init-authcode.sql -- schema + credential_config for the verifiably\n"
    "-- AUTH-CODE (authorization_code via eSignet) Inji Certify instance.\n"
    "--\n"
    "-- Built from init.sql (auth-code base) but: (a) adds certify.vc_subject\n"
    "-- (dynamic claims), (b) replaces the farmer credential_config rows with ONE\n"
    "-- generic VerifiablePersonCredential (no farmer/workshop data), (c) KEEPS the\n"
    "-- key_policy_def seeds verbatim (Certify's keymanager needs them at boot).\n"
    "-- did_url = did:web:certify-nginx (deploy.sh rewrites it to the public DID).\n"
    "-- GENERATED by scripts/gen-authcode-config.py -- edit there, not here.\n"
    "-- ==========================================================================\n\n"
)
out_sql = (header + ddl + "\n" + vc_subject_ddl + "\n" + insert
           + "\n\n-- --- key policies + remaining seed data (verbatim from init.sql) ---\n"
           + seed_suffix)
open(os.path.join(CERTDIR, "init-authcode.sql"), "w").write(out_sql)

# --- certify-postgres-dataprovider.properties ------------------------------
props_src = open(os.path.join(CERTDIR, "certify-csvdp-farmer.properties")).read()
query = ('select %s from certify.vc_subject where individual_id=:id'
         % ", ".join('"%s"' % f for f in FIELDS))
out_lines, header_done = [], False
for line in props_src.splitlines():
    s = line.strip()
    if s.startswith("mosip.certify.mock.data-provider.csv"):     # drop CSV settings
        continue
    if s.startswith("mosip.certify.indexed-mappings."):          # drop farmer indexes
        continue
    if s.startswith("mosip.certify.integration.data-provider-plugin="):
        out_lines.append("mosip.certify.integration.data-provider-plugin=PostgresDataProviderPlugin")
        continue
    if line.startswith("# certify-csvdp-farmer"):
        out_lines.append("# certify-postgres-dataprovider.properties -- verifiably auth-code data provider.")
        out_lines.append("# GENERATED by scripts/gen-authcode-config.py.")
        header_done = True
        continue
    out_lines.append(line)
out_lines += [
    "",
    "# --- PostgreSQL data provider (verifiably dynamic claims) ------------------",
    "# Claims are read from certify.vc_subject keyed by the eSignet token `sub` (:id).",
    "# One mapping per credential scope; the query string is taken verbatim.",
    "mosip.certify.data-provider-plugin.postgres.scope-query-mapping={'%s':'%s'}" % (SCOPE, query),
]
open(os.path.join(CERTDIR, "certify-postgres-dataprovider.properties"),
     "w").write("\n".join(out_lines) + "\n")

print("WROTE init-authcode.sql            (%d bytes)" % len(out_sql))
print("WROTE certify-postgres-dataprovider.properties")
print("scope-query-mapping :", "{'%s':'%s'}" % (SCOPE, query))
print("vc_template (decoded):")
print(base64.b64decode(B64).decode())
