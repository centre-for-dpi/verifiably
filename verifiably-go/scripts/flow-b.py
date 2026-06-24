#!/usr/bin/env python3
# Flow B engine: ONE schema definition -> ALL per-credential artifacts, so a new
# credential becomes discoverable + claimable over the eSignet auth-code flow,
# auto-compatible by construction (schema is the single source of truth):
#   1. certify.credential_config INSERT  (vc_template @context-per-field + scope)
#   2. certify.<view>  extraction VIEW over claims jsonb
#   3. the scope-query-mapping entry for the per-credential scope
#   4. the eSignet credential-scope additions (SUPPORTED + RESOURCE_MAPPING)
# Emits SQL to /tmp/flowb-config.sql and prints the scope-query + eSignet scope.
import base64, json, sys, re

SCHEMA = {
    "config_key": "FarmerLandCredential",
    "types": ["VerifiableCredential", "FarmerLandCredential"],
    "scope": "farmer_land_vc_ldp",
    "display_name": "Farmer Land Credential",
    "fields": [
        {"name": "holderName",   "label": "Holder Name"},
        {"name": "parcelId",     "label": "Parcel ID"},
        {"name": "areaHectares", "label": "Area (hectares)"},
        {"name": "village",      "label": "Village"},
        {"name": "tenureType",   "label": "Tenure Type"},
    ],
}
if len(sys.argv) > 1:
    SCHEMA = json.load(open(sys.argv[1]))

VOCAB = "https://vocab.verifiably.local/"
TYPES = SCHEMA["types"]
FIELDS = [f["name"] for f in SCHEMA["fields"]]
LABELS = {f["name"]: f["label"] for f in SCHEMA["fields"]}
SCOPE = SCHEMA["scope"]
CONFIG_KEY = SCHEMA["config_key"]
VIEW = "vc_subject_" + re.sub(r"[^a-z0-9_]", "", CONFIG_KEY.lower())

# vc_template (mirrors gen-authcode-config.py / injicertify buildVCTemplate)
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
    "@context": ["https://www.w3.org/2018/credentials/v1",
                 "https://w3id.org/security/suites/ed25519-2020/v1", terms],
    "issuer": "${_issuer}", "type": TYPES,
    "issuanceDate": "${validFrom}", "expirationDate": "${validUntil}",
    "credentialSubject": sub,
}
B64 = base64.b64encode(json.dumps(template, indent=2).encode()).decode()
display = json.dumps([{"name": SCHEMA["display_name"], "locale": "en",
                       "logo": {"url": "https://verifiably.id/static/credential-logo.svg", "alt_text": "Verifiably"},
                       "background_color": "#0f172a", "text_color": "#FFFFFF",
                       "background_image": {"uri": "https://verifiably.id/static/credential-logo.svg"}}])
credential_subject = json.dumps({f: {"display": [{"name": LABELS[f], "locale": "en"}]} for f in FIELDS})
display_order = "ARRAY[" + ", ".join("'%s'" % f for f in FIELDS) + "]"

insert = """INSERT INTO certify.credential_config (
    credential_config_key_id, config_id, status, vc_template, doctype, sd_jwt_vct,
    context, credential_type, credential_format, did_url,
    key_manager_app_id, key_manager_ref_id, signature_algo, signature_crypto_suite,
    sd_claim, display, display_order, scope,
    cryptographic_binding_methods_supported, credential_signing_alg_values_supported,
    proof_types_supported, credential_subject, mso_mdoc_claims, plugin_configurations,
    credential_status_purpose, qr_settings, qr_signature_algo, cr_dtimes, upd_dtimes
) VALUES (
    '{key}', gen_random_uuid()::VARCHAR(255), 'active', '{b64}', NULL, NULL,
    'https://www.w3.org/2018/credentials/v1', '{ctype}', 'ldp_vc', 'did:web:certify-nginx',
    'CERTIFY_VC_SIGN_ED25519', 'ED25519_SIGN', 'EdDSA', 'Ed25519Signature2020',
    NULL, '{display}'::JSONB, {display_order}, '{scope}',
    ARRAY['did:jwk'], ARRAY['Ed25519Signature2020'],
    '{{"jwt": {{"proof_signing_alg_values_supported": ["RS256", "ES256"]}}}}'::JSONB,
    '{credsub}'::JSONB, NULL, NULL, ARRAY['revocation'], NULL, NULL, NOW(), NULL
) ON CONFLICT (credential_config_key_id) DO NOTHING;
""".format(key=CONFIG_KEY, b64=B64, ctype=",".join(sorted(TYPES)), display=display,
           display_order=display_order, scope=SCOPE, credsub=credential_subject)
# NOTE: credential_type is alpha-sorted -- Certify's config lookup keys on the
# request's sorted types; an unsorted stored value is silently "not found".

view_cols = ",\n".join("  claims->>'%s' AS \"%s\"" % (f, f) for f in FIELDS)
view = ("-- Flow B per-schema extraction view\nCREATE OR REPLACE VIEW certify.%s AS\n"
        "SELECT individual_id,\n%s\nFROM certify.vc_subject;\n" % (VIEW, view_cols))

scope_query = "'%s':'select %s from certify.%s where individual_id=:id'" % (
    SCOPE, ", ".join('"%s"' % f for f in FIELDS), VIEW)

open("/tmp/flowb-config.sql", "w").write(view + "\n" + insert)
print("SCOPE_QUERY_ENTRY=" + scope_query)
print("ESIGNET_SCOPE=" + SCOPE)
print("CONFIG_KEY=" + CONFIG_KEY)
print("VIEW=" + VIEW)
print("FIELDS=" + ",".join(FIELDS))
