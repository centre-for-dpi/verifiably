package injicertify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/verifiably/verifiably-go/vctypes"
)

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

	displayRaw, _ := json.Marshal([]map[string]any{{
		"name":             schema.Name,
		"locale":           "en",
		"background_color": "#12107c",
		"text_color":       "#FFFFFF",
	}})

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
		sdJwtClaims = fieldDisplayRaw
	default: // ldp_vc, jwt_vc_json
		c := "https://www.w3.org/2018/credentials/v1"
		context_ = &c
		types := "VerifiableCredential"
		if len(schema.AdditionalTypes) > 0 {
			types += "," + strings.Join(schema.AdditionalTypes, ",")
		} else {
			types += "," + strings.ReplaceAll(schema.Name, " ", "")
		}
		credType = &types
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
		schema.ID,   // $1
		vcTemplate,  // $2
		sdJwtVct,    // $3 *string → NULL or TEXT
		context_,    // $4 *string → NULL or TEXT
		credType,    // $5 *string → NULL or TEXT
		credFormat,  // $6
		a.cfg.DB.DIDUrl,  // $7
		displayRaw,  // $8 JSONB
		displayOrder, // $9 TEXT[]
		scope,       // $10
		credSubject, // $11 []byte → NULL or JSONB
		sdJwtClaims, // $12 []byte → NULL or JSONB
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
		types := []string{"VerifiableCredential"}
		if len(schema.AdditionalTypes) > 0 {
			types = append(types, schema.AdditionalTypes...)
		} else {
			types = append(types, strings.ReplaceAll(schema.Name, " ", ""))
		}
		sub := map[string]any{"id": "${_holderId}"}
		for _, f := range schema.FieldsSpec {
			sub[f.Name] = "${" + f.Name + "}"
		}
		tmpl = map[string]any{
			"@context":          []string{"https://www.w3.org/2018/credentials/v1"},
			"issuer":            "${_issuer}",
			"type":              types,
			"issuanceDate":      "${validFrom}",
			"expirationDate":    "${validUntil}",
			"credentialSubject": sub,
		}
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
