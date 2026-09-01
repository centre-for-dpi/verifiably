package injicertify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

// verifiablyPublicBase returns the verifiably platform's public origin
// (VERIFIABLY_PUBLIC_URL) — the schema-authority host used to mint SD-JWT `vct`
// identifiers so issuance and the verifier agree. This is deliberately NOT the
// certify offer host (Config.PublicBaseURL): the vct is a verifiably-defined
// type identifier, and the verifier requests it from the same env var.
func verifiablyPublicBase() string {
	return strings.TrimRight(os.Getenv("VERIFIABLY_PUBLIC_URL"), "/")
}

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

	// mdoc's columns (doctype, mso_mdoc_claims, EC signing config) are entirely
	// disjoint from the SD-JWT/ldp_vc columns the rest of this function builds
	// (sd_jwt_vct, context, credential_type, Ed25519 signing config), so it gets
	// its own INSERT rather than threading NULLs through the shared one below.
	if credFormat == "mso_mdoc" {
		return a.saveMdocSchema(ctx, conn, schema)
	}

	// Pre-auth SD-JWT credentials must be revocable: embed the IETF Token Status
	// List pointer (status.status_list.{idx:${statusIdx}, uri:${statusUri}}) in
	// the template. IssueToWallet(ModePreAuth) POSTs statusIdx/statusUri from the
	// allocated StatusList binding, and — crucially — statusIdx/statusUri must be
	// DECLARED in display_order below so certify's PreAuthDataProviderPlugin
	// surfaces those POSTed values into the Velocity context. Without the
	// declaration the template markers stay unresolved and certify 400s on the
	// unquoted `"idx": ${statusIdx}` (json_processing_error). The auth-code path
	// resolves the same markers from its vc_subject data-provider view instead.
	// SD-JWT gets an IETF token-status pointer; VCDM2 ldp_vc gets a W3C
	// BitstringStatusListEntry credentialStatus (F14 — W3C revocation). Both are
	// resolved from the same POSTed statusIdx/statusUri (declared in display_order
	// below) on the pre-auth path.
	withTokenStatus := credFormat == "vc+sd-jwt" || credFormat == "ldp_vc"
	vcTemplate := buildVCTemplate(schema, withTokenStatus)

	scope := a.cfg.DB.Scope
	if scope == "" {
		scope = "mock_identity_vc_ldp"
	}

	displayOrder := make([]string, 0, len(schema.FieldsSpec)+2)
	for _, f := range schema.FieldsSpec {
		displayOrder = append(displayOrder, f.Name)
	}
	if withTokenStatus {
		// Declare the token-status markers so the pre-auth data-provider passes
		// the POSTed statusIdx/statusUri into the template's Velocity context.
		displayOrder = append(displayOrder, "statusIdx", "statusUri")
	}
	// Same for the validity-window markers: undeclared markers stay unresolved,
	// and certify 400s on the unquoted `"nbf": ${validFromEpoch}`. SD-JWT takes
	// epoch seconds (nbf/exp); ldp_vc takes RFC3339 (validFrom/validUntil) — the
	// vc_template for each asks for the right shape. Declared only when the
	// schema expires, matching the markers buildVCTemplate emits.
	if schema.ExpiresWithWindow() {
		displayOrder = append(displayOrder, validityMarkerNames(credFormat)...)
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
		vct := schema.CredentialVct(verifiablyPublicBase())
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
		if withTokenStatus {
			// Register statusIdx/statusUri as ACCEPTED pre-auth claims (F14). Unlike
			// SD-JWT (which validates against display_order), certify's ldp_vc
			// pre-auth data provider validates POSTed claims against
			// credential_subject — so the staged statusIdx/statusUri are rejected as
			// `unknown_claims` unless declared here. They resolve the credentialStatus
			// template markers and are NOT rendered as credentialSubject fields (the
			// vc_template controls the subject shape — it lists only the real fields).
			csMap := map[string]any{}
			for k, v := range fieldDisplay {
				csMap[k] = v
			}
			marker := map[string]any{"display": []map[string]any{{"name": "Status", "locale": "en"}}}
			csMap["statusIdx"] = marker
			csMap["statusUri"] = marker
			// The validity markers need the same declaration, and for the same
			// reason: ldp_vc's pre-auth data provider validates POSTed claims
			// against credential_subject, so an undeclared validFrom/validUntil
			// is rejected as unknown_claims. They resolve the template's
			// top-level validFrom/validUntil (credential metadata) and are NOT
			// rendered as credentialSubject fields — the vc_template controls
			// the subject shape and lists only the real fields.
			if schema.ExpiresWithWindow() {
				validityMarker := map[string]any{"display": []map[string]any{{"name": "Validity", "locale": "en"}}}
				for _, n := range validityMarkerNames(credFormat) {
					csMap[n] = validityMarker
				}
			}
			credSubject, _ = json.Marshal(csMap)
		}
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

// mdocDocTypeForSchema resolves the ISO docType from a schema the same way
// waltid/issuer2.go's mdocDocTypeFor does: AdditionalTypes[0] first (what
// the schema builder writes for a custom mdoc schema — see
// handlers/schema.go's SaveSchema), falling back to BaseType(), falling
// back to the raw ID. schema.ID is a generated "custom-<nano>" string for
// every custom schema and is NEVER the docType directly.
func mdocDocTypeForSchema(schema vctypes.Schema) string {
	if len(schema.AdditionalTypes) > 0 {
		if dt := strings.TrimSpace(schema.AdditionalTypes[0]); dt != "" {
			return dt
		}
	}
	if dt := schema.BaseType(); dt != "" {
		return dt
	}
	return schema.ID
}

// mdocNamespaceForDocType derives the ISO namespace from a docType via
// mdoc.NamespaceForDocType, the allowlist shared with waltid/issuer2.go's
// docTypeProfiles — NOT a dot-stripping heuristic. That heuristic gives the
// right answer for org.iso.18013.5.1.mDL by coincidence of its shape, but the
// wrong one for org.iso.23220.photoid.1 (whose real base namespace is
// org.iso.23220.1, not org.iso.23220.photoid) — this function used to
// reimplement that exact heuristic locally, silently producing a wrong
// namespace the moment an operator created an Inji Certify Photo ID schema.
// See mdoc.NamespaceForDocType's own comment for the full history.
//
// The dot-stripping fallback below only fires for a docType absent from the
// shared allowlist — i.e. one with no provisioned mso_mdoc profile at all —
// matching waltid/issuer2.go's mdocNamespaceFor posture: never the primary
// path, only a last resort for an as-yet-unprovisioned docType.
func mdocNamespaceForDocType(docType string) string {
	if ns, ok := mdoc.NamespaceForDocType(docType); ok {
		return ns
	}
	if i := strings.LastIndex(docType, "."); i > 0 {
		return docType[:i]
	}
	return docType
}

// mdocVCTemplate builds the base64-encoded Velocity template Inji Certify
// needs to render an mso_mdoc credential. Unlike buildVCTemplate's other
// branches, this is NOT optional/NULL — confirmed against a real Inji
// Certify v0.14.0 in the 2026-08-25 validation spike (see
// C:\tmp\spike\run\mdl_config.json's vcTemplate field, the only artifact
// from that spike that captured a template Inji actually accepted and
// issued a valid mdoc from).
//
// Each nameSpaces item is marshaled individually (compact, one line) rather
// than via a single json.MarshalIndent over the whole document: MarshalIndent
// recursively indents every nested object onto its own line, which does not
// match the one-object-per-line shape the real spike template uses (and
// which Inji Certify was actually validated against) — e.g.
// `{"digestID": 0, "elementIdentifier": "family_name", "elementValue": "${rootContext['org.iso.18013.5.1'].family_name}"}`
// on a single line, not one field per line.
//
// Field markers use Velocity's bracket-notation nested access
// (${rootContext['<namespace>'].<field>}), NOT the bare ${field} form.
// Confirmed empirically during Task 6 end-to-end verification: our claims
// are POSTed nested under the ISO namespace (required — see issuer.go's
// mso_mdoc claims-nesting comment), and Velocity's rootContext only
// resolves bare ${field} markers against TOP-LEVEL context keys. Against a
// namespace-nested claims map, every bare marker silently fails to
// resolve — a decoded test credential showed elementValue literally as the
// string "${family_name}", not the posted value — which Inji Certify then
// fails to sign as valid JSON/CBOR (ERROR_SIGNING_QR_DATA). Switching to
// ${rootContext['<namespace>'].field} resolves correctly; verified by
// decoding a real issued credential and confirming the CBOR elementValue
// matched the posted value exactly.
//
// driving_privileges needs its own variant: it must decode to a real CBOR
// array of maps, not a string. Two things had to be true together, each
// confirmed by a separate empirical test:
//   - The template marker must be UNQUOTED
//     (${rootContext[...].driving_privileges}, no surrounding "...") — the
//     quoted form (matching every scalar field) forces Velocity's
//     substitution through Java's List/Map toString(), producing a
//     malformed, unusable string like
//     "[{issue_date=2015-03-01, vehicle_category_code=A, ...}]" instead of
//     real JSON. The unquoted form lets Velocity substitute the value's
//     own serialized text directly into the JSON structure.
//   - The posted claim value must already be a pre-serialized JSON STRING
//     (via json.Marshal), not a decoded array (see issuer.go) — posting a
//     real array with the unquoted marker made Velocity emit invalid
//     Java-syntax (unquoted, "="-separated) text that breaks JSON parsing
//     entirely (ERROR_SIGNING_QR_DATA again). Only pre-serialized-string +
//     unquoted-marker together decode to a real, correctly-typed CBOR
//     array — confirmed by decoding a real issued test credential and
//     finding driving_privileges as an actual CBOR array of maps with
//     proper full-date-tagged issue_date/expiry_date, not a string.
func mdocVCTemplate(doctype string, fields []vctypes.FieldSpec) string {
	namespace := mdocNamespaceForDocType(doctype)
	itemLines := make([]string, 0, len(fields))
	for digestID, f := range fields {
		accessor := fmt.Sprintf(`rootContext['%s'].%s`, namespace, f.Name)
		elementValue := "\"${" + accessor + "}\""
		if f.Format == mdoc.FormatDrivingPrivileges {
			elementValue = "${" + accessor + "}"
		}
		itemLines = append(itemLines, fmt.Sprintf(
			`      {"digestID": %d, "elementIdentifier": %q, "elementValue": %s}`,
			digestID, f.Name, elementValue,
		))
	}
	out := "{\n" +
		"  \"nameSpaces\": {\n" +
		"    " + strconv.Quote(namespace) + ": [\n" +
		strings.Join(itemLines, ",\n") + "\n" +
		"    ]\n" +
		"  },\n" +
		"  \"docType\": \"${_doctype}\",\n" +
		"  \"validityInfo\": {\"validFrom\": \"${_validFrom}\", \"validUntil\": \"${_validUntil}\"}\n" +
		"}"
	return base64.StdEncoding.EncodeToString([]byte(out))
}

// mdocCredentialConfigValues builds every mso_mdoc-specific value
// SaveCustomSchema's mdoc branch needs. Extracted so it is testable without
// a live Postgres connection.
func mdocCredentialConfigValues(schema vctypes.Schema) (doctype, vcTemplate string, claims []byte, signatureAlgo, keyManagerAppID, keyManagerRefID, cryptoSuite string) {
	doctype = mdocDocTypeForSchema(schema)
	vcTemplate = mdocVCTemplate(doctype, schema.FieldsSpec)

	nsClaims := map[string]any{}
	for _, f := range schema.FieldsSpec {
		nsClaims[f.Name] = map[string]any{
			"display": []map[string]any{{"name": fieldLabel(f.Name), "locale": "en"}},
		}
	}
	claimsMap := map[string]any{mdocNamespaceForDocType(doctype): nsClaims}
	claims, _ = json.Marshal(claimsMap)

	// Values captured verbatim from C:\tmp\spike\run\mdl_config.json — the
	// exact configuration Inji Certify v0.14.0 accepted and issued a real,
	// cryptographically valid mdoc from. Do not approximate these.
	return doctype, vcTemplate, claims, mdoc.MdocSignatureAlgo, "CERTIFY_VC_SIGN_EC_R1", "EC_SECP256R1_SIGN", "EcdsaSecp256r1Signature2019"
}

// saveMdocSchema is SaveCustomSchema's mso_mdoc branch — a separate INSERT
// because mdoc's columns (doctype, mso_mdoc_claims, EC signing config) are
// entirely disjoint from the shared INSERT's SD-JWT/ldp_vc-specific
// columns (sd_jwt_vct, context, credential_type, Ed25519 signing config),
// which stay NULL/irrelevant for mdoc.
func (a *Adapter) saveMdocSchema(ctx context.Context, conn *pgx.Conn, schema vctypes.Schema) error {
	doctype, vcTemplate, claims, signatureAlgo, keyManagerAppID, keyManagerRefID, cryptoSuite := mdocCredentialConfigValues(schema)

	displayOrder := make([]string, 0, len(schema.FieldsSpec))
	for _, f := range schema.FieldsSpec {
		displayOrder = append(displayOrder, f.Name)
	}

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

	scope := a.cfg.DB.Scope
	if scope == "" {
		scope = "mock_identity_vc_ldp"
	}

	_, err := conn.Exec(ctx, `
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
	$3, NULL, NULL, NULL, $4,
	$5, $6, $7,
	$8, $9, NULL,
	$10, $11, $12,
	ARRAY['cose_key'],
	ARRAY['ES256'],
	'{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}'::JSONB,
	NULL, NULL, $13,
	NULL, NOW(), NULL
)
ON CONFLICT (credential_config_key_id) DO UPDATE SET
	vc_template              = EXCLUDED.vc_template,
	doctype                  = EXCLUDED.doctype,
	credential_format        = EXCLUDED.credential_format,
	key_manager_app_id       = EXCLUDED.key_manager_app_id,
	key_manager_ref_id       = EXCLUDED.key_manager_ref_id,
	signature_algo           = EXCLUDED.signature_algo,
	signature_crypto_suite   = EXCLUDED.signature_crypto_suite,
	display                  = EXCLUDED.display,
	display_order            = EXCLUDED.display_order,
	mso_mdoc_claims          = EXCLUDED.mso_mdoc_claims,
	upd_dtimes               = NOW()
`,
		schema.ID,       // $1
		vcTemplate,      // $2
		doctype,         // $3
		"mso_mdoc",      // $4
		a.cfg.DB.DIDUrl, // $5
		keyManagerAppID, // $6
		keyManagerRefID, // $7
		signatureAlgo,   // $8
		cryptoSuite,     // $9
		displayRaw,      // $10 JSONB
		displayOrder,    // $11 TEXT[]
		scope,           // $12
		claims,          // $13 JSONB
	)
	if err != nil {
		return fmt.Errorf("injicertify db: upsert mdoc credential_config %q: %w", schema.ID, err)
	}
	return nil
}

// stdToCredentialFormat maps verifiably-go's Std string to inji-certify's
// credential_format column value.
func stdToCredentialFormat(std string) string {
	switch std {
	case "sd_jwt_vc (IETF)":
		return "vc+sd-jwt"
	case "mso_mdoc":
		return "mso_mdoc"
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
// statusIdxPlaceholder is a valid-JSON stand-in for the unquoted `${statusIdx}`
// template marker. json.Marshal can't emit a bare (unquoted) ${…} token, so we
// marshal this quoted placeholder and swap it for the unquoted marker afterwards
// — yielding `"idx": ${statusIdx}`, which certify renders to a JSON *number*.
const statusIdxPlaceholder = "@@STATUS_IDX@@"

// nbf/exp are JWT NumericDate — JSON *numbers* — so their markers must render
// unquoted, exactly like ${statusIdx}. Same placeholder trick, same reason:
// json.Marshal can't emit a bare ${…} token.
const (
	validFromEpochPlaceholder  = "@@VALID_FROM_EPOCH@@"
	validUntilEpochPlaceholder = "@@VALID_UNTIL_EPOCH@@"
)

// validityMarkerNames returns the template markers a format's validity window
// resolves from. The names differ because the shapes differ: SD-JWT's nbf/exp
// are epoch seconds, W3C's validFrom/validUntil are RFC3339 strings.
//
// Single source of truth for both sides of the contract — SaveCustomSchema
// DECLARES these (so certify's data provider surfaces them) and IssueToWallet
// POSTS them. If the two ever disagree the markers render unresolved and
// certify rejects the issuance, so they must be derived from one place.
func validityMarkerNames(credFormat string) []string {
	switch credFormat {
	case "vc+sd-jwt", "dc+sd-jwt":
		return []string{"validFromEpoch", "validUntilEpoch"}
	case "ldp_vc", "jwt_vc_json":
		return []string{"validFrom", "validUntil"}
	}
	return nil
}

// isInternalMarker reports whether a credential_config `order` entry is an
// internal template marker rather than a claim the operator types.
//
// display_order does double duty: it declares which POSTed claims certify's
// pre-auth data provider will surface into the Velocity context, AND it is what
// ListSchemas turns into the issue form's fields. Markers must be declared (or
// the template renders unresolved) but must never reach the form — they are
// supplied by verifiably: the status pointer from the allocated StatusList
// binding, the validity window from the issue form's own datetime pickers.
//
// Miss this and the markers appear as bare required text boxes the operator
// cannot fill ("validFromEpoch *"), which is exactly what happened.
func isInternalMarker(name string) bool {
	switch name {
	case "statusIdx", "statusUri":
		return true
	}
	return isValidityMarker(name)
}

// isValidityMarker reports whether a config `order` entry is one of the
// validity-window markers.
//
// Doubles as the round-trip signal for Schema.Expires. Expires is verifiably's
// own concept — no vendor advertises it — and ListSchemas rebuilds a Schema
// from certify's wellknown, so without reading it back here the flag is lost
// the moment a schema round-trips: the template (written while Expires was
// true) asks for ${validUntilEpoch}, while issuance (reading the rebuilt
// schema, Expires false) declines to POST it, and certify rejects the
// unresolved marker. SaveCustomSchema declares these markers precisely when the
// schema expires, so their presence IS the flag.
func isValidityMarker(name string) bool {
	for _, n := range allValidityMarkerNames() {
		if n == name {
			return true
		}
	}
	return false
}

// allValidityMarkerNames is every validity marker across formats. Derived from
// validityMarkerNames so a marker cannot be added to a template without also
// being filtered out of the issue form.
func allValidityMarkerNames() []string {
	return append(validityMarkerNames("vc+sd-jwt"), validityMarkerNames("ldp_vc")...)
}

// validityClaims renders an RFC3339 validity window into the claim values that
// resolve this format's template markers. Empty/unparseable bounds yield ""
// so the marker renders empty rather than leaking a literal ${…} into the
// credential — an absent bound simply imposes no constraint, which is correct
// for a credential that genuinely never expires.
//
// The marker names come from validityMarkerNames so the POSTed keys and the
// DECLARED keys are the same by construction.
func validityClaims(credFormat, validFrom, validUntil string) map[string]string {
	names := validityMarkerNames(credFormat)
	if len(names) != 2 {
		return nil
	}
	out := map[string]string{names[0]: "", names[1]: ""}
	epoch := credFormat == "vc+sd-jwt" || credFormat == "dc+sd-jwt"
	for i, raw := range []string{validFrom, validUntil} {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if epoch {
			// JWT NumericDate: seconds since the epoch, rendered unquoted into
			// nbf/exp by the template's placeholder swap.
			out[names[i]] = strconv.FormatInt(t.Unix(), 10)
			continue
		}
		out[names[i]] = t.UTC().Format(time.RFC3339)
	}
	return out
}

func buildVCTemplate(schema vctypes.Schema, withTokenStatus bool) string {
	credFormat := stdToCredentialFormat(schema.Std)
	var tmpl any
	switch credFormat {
	case "vc+sd-jwt", "dc+sd-jwt":
		vct := schema.CredentialVct(verifiablyPublicBase())
		m := map[string]any{"vct": vct}
		for _, f := range schema.FieldsSpec {
			m[f.Name] = "${" + f.Name + "}"
		}
		// Validity window as the registered JWT claims nbf/exp, mirroring what
		// the walt.id adapter already emits (buildSDJWTCredentialData). This is
		// where a validity window BELONGS for SD-JWT VC: registered claims live
		// in the plain JWT payload, so — unlike a `valid_until` data claim — a
		// holder cannot withhold the expiry under selective disclosure and
		// escape the temporal gate. backend.TemporalBounds already reads both.
		//
		// Without these the credential carries no window at all and every
		// verification of an expired credential passes: an absent bound imposes
		// no constraint.
		//
		// ONLY for schemas that declare an expiry. The markers are unquoted
		// (NumericDate is a JSON number), so an issuance with no window would
		// render `"nbf": ,` — invalid JSON, which certify rejects outright.
		// Non-expiring schemas simply carry no temporal claims.
		if schema.ExpiresWithWindow() {
			m["nbf"] = validFromEpochPlaceholder
			m["exp"] = validUntilEpochPlaceholder
		}
		// IETF Token Status List reference — the idx/uri are filled per-holder by
		// the Postgres data-provider (statusIdx from certify.vc_subject via the
		// scope-query, uri a constant column in the extraction view). Only added
		// for the auth-code path (withTokenStatus); the pre-auth path issues from
		// staged claims with no data-provider, so the markers would go unresolved.
		if withTokenStatus {
			m["status"] = map[string]any{
				"status_list": map[string]any{
					"idx": statusIdxPlaceholder, // → unquoted ${statusIdx} (a number)
					"uri": "${statusUri}",
				},
			}
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
		// W3C revocation: embed a BitstringStatusListEntry credentialStatus pointing
		// at verifiably's PUBLIC bitstring list (${statusUri}), mirroring the SD-JWT
		// status.status_list. Emitted for BOTH the pre-auth (F14) and the auth-code
		// callers when a status list is configured — the auth-code data-provider view
		// now resolves ${statusUri} to the BITSTRING list (statusURLFor) so the block
		// points at the right list and external verifiers (Inji Verify) read it. VCDM2
		// only: the credentials/v2 context defines the type + statusPurpose/
		// statusListIndex/statusListCredential, so there's no PROTECTED_TERM
		// redefinition at canonicalization (VCDM 1.1 would need explicit @context
		// terms — left statusless for now). statusListIndex is a STRING here, so
		// "${statusIdx}" stays quoted (unlike the SD-JWT numeric idx).
		if withTokenStatus && isVCDM2(schema.Std) {
			m["credentialStatus"] = map[string]any{
				"id":                   "${statusUri}#${statusIdx}",
				"type":                 "BitstringStatusListEntry",
				"statusPurpose":        "revocation",
				"statusListIndex":      "${statusIdx}",
				"statusListCredential": "${statusUri}",
			}
		}
		tmpl = m
	}
	b, _ := json.MarshalIndent(tmpl, "", "  ")
	// Unquote the numeric markers so they render as JSON numbers, not strings.
	// statusIdx is an index; nbf/exp are JWT NumericDate — all three are numbers.
	out := strings.Replace(string(b), `"`+statusIdxPlaceholder+`"`, "${statusIdx}", 1)
	out = strings.Replace(out, `"`+validFromEpochPlaceholder+`"`, "${validFromEpoch}", 1)
	out = strings.Replace(out, `"`+validUntilEpochPlaceholder+`"`, "${validUntilEpoch}", 1)
	return base64.StdEncoding.EncodeToString([]byte(out))
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
