package injicertify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/verifiably/verifiably-go/vctypes"
)

// defaultCredentialLogoURL is the fallback display logo for a custom config
// when injicertify Config.DB.LogoURL is unset. gen-backends.sh normally points
// LogoURL at verifiably-go's own /static/credential-logo.svg (neutral, no
// external dependency); this reachable default just guarantees the display
// logo is never null (a null logo crashes some wallet UIs with "undefined is
// not a function"). Override via the backends config `db.logoUrl`.
const defaultCredentialLogoURL = "https://mosip.github.io/inji-config/logos/agro-vertias-logo.png"

// credentialTypesSorted returns "VerifiableCredential" plus the schema's specific
// type(s), ALPHABETICALLY sorted. Inji Certify v0.14 sorts a credential's type
// array when building its credential_config lookup key but matches it RAW against
// the stored credential_type, so both the stored credential_type column and the VC
// template's type[] must be pre-sorted — a "VerifiableCredential"-first order makes
// issuance fail with "Credentialconfig not found" / ERROR_SIGNING_QR_DATA. (The
// seeded configs store it sorted, which is why they work.)
func credentialTypesSorted(schema vctypes.Schema) []string {
	t := []string{"VerifiableCredential"}
	if len(schema.AdditionalTypes) > 0 {
		t = append(t, schema.AdditionalTypes...)
	} else {
		t = append(t, strings.ReplaceAll(schema.Name, " ", ""))
	}
	sort.Strings(t)
	return t
}

// SaveCustomSchema registers a verifiably-go custom schema as a
// credential_configuration row in inji-certify's PostgreSQL database.
// credential_config_key_id is set to schema.ID so subsequent calls to
// POST /v1/certify/pre-authorized-data with that ID will succeed.
// No-op when DB.DSN is not configured.
func (a *Adapter) SaveCustomSchema(ctx context.Context, schema vctypes.Schema) error {
	if a.cfg.DB.DSN == "" {
		return nil
	}
	conn, err := pgx.Connect(ctx, a.cfg.DB.DSN)
	if err != nil {
		return fmt.Errorf("injicertify db: connect: %w", err)
	}
	defer conn.Close(ctx)

	credFormat := stdToCredentialFormat(schema.Std)
	vcTemplate := buildVCTemplate(schema)

	scope := a.cfg.DB.Scope
	if scope == "" {
		scope = "mock_identity_vc_ldp"
	}

	displayOrder := make([]string, 0, len(schema.FieldsSpec))
	for _, f := range schema.FieldsSpec {
		displayOrder = append(displayOrder, f.Name)
	}

	// NOTE: do NOT add a "description" key here. Although OID4VCI allows it in a
	// `display` object, Inji Certify v0.14's credential_config display model
	// can't deserialize a display entry containing `description` — it throws
	// "IllegalArgumentException: ... cannot be transformed to Json object" while
	// loading credential_configurations_supported, which poisons the ENTIRE
	// config load and makes every pre-authorized-data issuance fail with
	// `unknown_error` (not just the custom schema). Empirically isolated against
	// inji-certify-preauth:0.14 on 2026-06-18: an otherwise-identical display
	// WITH `description` fails, WITHOUT it issues fine. The issuer display name
	// has nowhere to live in Certify's display model, so we drop it here — the
	// walt.id adapter (catalog.go) still surfaces it via its own display block,
	// where it is supported.
	// logo MUST be a non-null object. Inji Certify's display model always
	// serialises a `logo` key in the wellknown — null when we don't set one —
	// and some wallet UIs crash ("undefined is not a function") rendering a
	// credential card whose logo is null. (The seeded farmer configs ship a
	// logo object, which is why they hold while a bare custom config did not.)
	// Use the configured LogoURL, else a built-in reachable default.
	logoURL := a.cfg.DB.LogoURL
	if logoURL == "" {
		logoURL = defaultCredentialLogoURL
	}
	displayEntry := map[string]any{
		"name":             schema.Name,
		"locale":           "en",
		"background_color": "#12107c",
		"text_color":       "#FFFFFF",
		"logo": map[string]any{
			"url":      logoURL,
			"alt_text": schema.Name + " Logo",
		},
		"background_image": map[string]any{"uri": logoURL},
	}
	displayRaw, _ := json.Marshal([]map[string]any{displayEntry})

	fieldDisplay := buildFieldDisplay(schema.FieldsSpec)
	fieldDisplayRaw, _ := json.Marshal(fieldDisplay)

	var sdJwtVct, context_, credType *string
	var credSubject, sdJwtClaims []byte

	switch credFormat {
	case "vc+sd-jwt", "dc+sd-jwt":
		vct := schema.Vct
		if vct == "" {
			vct = "https://verifiably.example.com/credentials/" + schema.ID
		}
		sdJwtVct = &vct
		// Deliberately leave sd_jwt_claims NULL. It only feeds the OPTIONAL
		// `claims` display block in the issuer metadata, but walt.id's OID4VCI
		// parser (ClaimDescriptorNamespacedMapSerializer) treats `claims` as a
		// 2-level mdoc-style namespaced map {namespace:{claim:descriptor}}. Our
		// flat SD-JWT shape {claim:{display:[...]}} makes it read the claim name
		// as a namespace and the `display` ARRAY as a descriptor object →
		// "JsonArray is not a JsonObject", which aborts parsing the ENTIRE
		// credential-issuer metadata (so NO credential is claimable in walt.id
		// while any SD-JWT config carries `claims`). Issuance is unaffected —
		// the disclosed claims come from vc_template + the data, not this
		// display block; Credo-based wallets derive SD-JWT display from the
		// credential payload, not metadata `claims`. (sdJwtClaims stays nil.)
	default: // ldp_vc, jwt_vc_json
		c := vcdmContextURL(schema.Std)
		context_ = &c
		joined := strings.Join(credentialTypesSorted(schema), ",")
		credType = &joined
		credSubject = fieldDisplayRaw
	}

	_, err = conn.Exec(ctx, `
INSERT INTO certify.credential_config (
	credential_config_key_id, config_id, status, vc_template,
	doctype, sd_jwt_vct, context, credential_type, credential_format,
	did_url, key_manager_app_id, key_manager_ref_id,
	signature_algo, signature_crypto_suite, sd_claim,
	display, display_order, scope,
	cryptographic_binding_methods_supported,
	credential_signing_alg_values_supported,
	proof_types_supported,
	credential_subject, sd_jwt_claims, mso_mdoc_claims,
	plugin_configurations, cr_dtimes, upd_dtimes
) VALUES (
	$1, $1, 'active', $2,
	NULL, $3, $4, $5, $6,
	$7, 'CERTIFY_VC_SIGN_ED25519', 'ED25519_SIGN',
	'EdDSA', 'Ed25519Signature2020', NULL,
	$8, $9, $10,
	ARRAY['did:jwk'],
	ARRAY['Ed25519Signature2020'],
	'{"jwt":{"proof_signing_alg_values_supported":["RS256","ES256"]}}'::JSONB,
	$11, $12, NULL,
	NULL, NOW(), NULL
)
ON CONFLICT (credential_config_key_id) DO UPDATE SET
	vc_template        = EXCLUDED.vc_template,
	sd_jwt_vct         = EXCLUDED.sd_jwt_vct,
	context            = EXCLUDED.context,
	credential_type    = EXCLUDED.credential_type,
	credential_format  = EXCLUDED.credential_format,
	display            = EXCLUDED.display,
	display_order      = EXCLUDED.display_order,
	credential_subject = EXCLUDED.credential_subject,
	sd_jwt_claims      = EXCLUDED.sd_jwt_claims,
	upd_dtimes         = NOW()
`,
		schema.ID,       // $1
		vcTemplate,      // $2
		sdJwtVct,        // $3 *string → NULL or TEXT
		context_,        // $4 *string → NULL or TEXT
		credType,        // $5 *string → NULL or TEXT
		credFormat,      // $6
		a.cfg.DB.DIDUrl, // $7
		displayRaw,      // $8 JSONB
		displayOrder,    // $9 TEXT[]
		scope,           // $10
		credSubject,     // $11 []byte → NULL or JSONB
		sdJwtClaims,     // $12 []byte → NULL or JSONB
	)
	if err != nil {
		return fmt.Errorf("injicertify db: upsert credential_config %q: %w", schema.ID, err)
	}
	return nil
}

// DeleteCustomSchema removes a custom credential configuration from
// inji-certify's database by its verifiably-go schema ID.
// No-op when DB.DSN is not configured.
func (a *Adapter) DeleteCustomSchema(ctx context.Context, id string) error {
	if a.cfg.DB.DSN == "" {
		return nil
	}
	conn, err := pgx.Connect(ctx, a.cfg.DB.DSN)
	if err != nil {
		return fmt.Errorf("injicertify db: connect: %w", err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx,
		`DELETE FROM certify.credential_config WHERE credential_config_key_id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("injicertify db: delete credential_config %q: %w", id, err)
	}
	return nil
}

// stdToCredentialFormat maps verifiably-go's Std string to inji-certify's
// credential_format column value.
func stdToCredentialFormat(std string) string {
	switch std {
	case "sd_jwt_vc (IETF)":
		return "vc+sd-jwt"
	default:
		return "ldp_vc"
	}
}

// isVCDM2 reports whether the schema's declared standard is W3C VC Data Model
// 2.0 (vs 1.1). VCDM 2.0 uses the credentials/v2 @context and the validFrom/
// validUntil date fields instead of credentials/v1 + issuanceDate/expirationDate.
func isVCDM2(std string) bool { return std == "w3c_vcdm_2" }

// vcdmContextURL returns the base VC Data Model @context URL for the schema's
// declared standard.
func vcdmContextURL(std string) string {
	if isVCDM2(std) {
		return "https://www.w3.org/ns/credentials/v2"
	}
	return "https://www.w3.org/2018/credentials/v1"
}

// buildVCTemplate generates the base64-encoded VC template that inji-certify
// uses to mint credentials. For SD-JWT the template is a flat JSON object with
// ${fieldName} substitution markers. For ldp_vc / jwt_vc_json it is a JSON-LD
// credential skeleton.
func buildVCTemplate(schema vctypes.Schema) string {
	credFormat := stdToCredentialFormat(schema.Std)
	var tmpl any
	switch credFormat {
	case "vc+sd-jwt", "dc+sd-jwt":
		vct := schema.Vct
		if vct == "" {
			vct = "https://verifiably.example.com/credentials/" + schema.ID
		}
		m := map[string]any{"vct": vct}
		for _, f := range schema.FieldsSpec {
			m[f.Name] = "${" + f.Name + "}"
		}
		tmpl = m
	default:
		// Same sorted order as the credential_type column so the issued
		// credential's type[] matches Certify's config-lookup key.
		types := credentialTypesSorted(schema)
		sub := map[string]any{"id": "${_holderId}"}
		for _, f := range schema.FieldsSpec {
			sub[f.Name] = "${" + f.Name + "}"
		}
		// Inline JSON-LD context for the custom type(s) + credentialSubject
		// fields: a single @vocab so any NON-STANDARD term (the custom type,
		// the custom fields) expands to https://vocab.verifiably.local/<term>.
		//
		// We deliberately do NOT add explicit per-term entries (e.g.
		// "name": "https://vocab.verifiably.local/name"). The base VCDM-2.0
		// context (credentials/v2) is @protected and already defines common
		// terms like `name`/`description`/`id`/`type`/`issuer`; an explicit
		// entry that re-maps one of those is a PROTECTED_TERM_REDEFINITION,
		// which makes inji-certify's JSON-LD canonicalization throw at signing
		// time (ERROR_SIGNING_QR_DATA — "Error occurred during canonicalization")
		// and blocks the claim. @vocab applies ONLY to terms the base context
		// leaves undefined, so custom fields still resolve to the same vocab
		// IRIs the old explicit entries produced, while a standard-named field
		// keeps its protected base definition — valid under JSON-LD safe mode
		// for ANY field name. (The `type` array below is unchanged, so
		// Certify's config-lookup-by-type still matches.)
		const vocabBase = "https://vocab.verifiably.local/"
		terms := map[string]any{"@vocab": vocabBase}
		m := map[string]any{
			// VC Data Model base context (credentials/v1 for VCDM 1.1,
			// credentials/v2 for VCDM 2.0) + the Ed25519Signature2020 suite
			// context + the inline custom-term context. Inji Certify signs the
			// VC verbatim from this template and does NOT inject the suite
			// context itself, so without it the issued proof's terms
			// (Ed25519Signature2020 / proofValue / Ed25519VerificationKey2020)
			// are undefined and a strict JSON-LD wallet fails to verify with
			// "undefined is not a function". Empirically: the bare base context
			// issues HTTP 200 but the wallet can't hold the credential.
			"@context": []any{
				vcdmContextURL(schema.Std),
				"https://w3id.org/security/suites/ed25519-2020/v1",
				terms,
			},
			"issuer":            "${_issuer}",
			"type":              types,
			"credentialSubject": sub,
		}
		// VCDM 2.0 renamed the validity dates: validFrom/validUntil replace
		// VCDM 1.1's issuanceDate/expirationDate. Emit the pair that matches
		// the schema's declared data model so the issued credential is valid
		// under its own @context (a v2 credential with issuanceDate, or a v1
		// credential with validFrom, is malformed). Both source from the same
		// ${validFrom}/${validUntil} substitution markers Inji fills.
		if isVCDM2(schema.Std) {
			m["validFrom"] = "${validFrom}"
			m["validUntil"] = "${validUntil}"
		} else {
			m["issuanceDate"] = "${validFrom}"
			m["expirationDate"] = "${validUntil}"
		}
		tmpl = m
	}
	b, _ := json.MarshalIndent(tmpl, "", "  ")
	return base64.StdEncoding.EncodeToString(b)
}

type displayItem struct {
	Display []struct {
		Name   string `json:"name"`
		Locale string `json:"locale"`
	} `json:"display"`
}

// buildFieldDisplay produces the per-field display metadata used in both
// credential_subject (ldp_vc) and sd_jwt_claims (SD-JWT) columns.
func buildFieldDisplay(fields []vctypes.FieldSpec) map[string]displayItem {
	out := make(map[string]displayItem, len(fields))
	for _, f := range fields {
		out[f.Name] = displayItem{
			Display: []struct {
				Name   string `json:"name"`
				Locale string `json:"locale"`
			}{{Name: fieldLabel(f.Name), Locale: "en"}},
		}
	}
	return out
}

// fieldLabel converts a snake_case or camelCase field name to a human-readable
// label used in the credential display metadata.
func fieldLabel(name string) string {
	words := strings.Split(name, "_")
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
