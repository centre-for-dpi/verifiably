package injicertify

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

func TestStdToCredentialFormatMsoMdoc(t *testing.T) {
	got := stdToCredentialFormat("mso_mdoc")
	if got != "mso_mdoc" {
		t.Errorf("stdToCredentialFormat(%q) = %q, want %q", "mso_mdoc", got, "mso_mdoc")
	}
}

func TestMdocCredentialConfigValues(t *testing.T) {
	// Construido igual que internal/handlers/schema.go's SaveSchema construye
	// un schema mdoc real: ID es el "custom-<nano>" generado, el docType ISO
	// vive en AdditionalTypes[0] — NUNCA en ID. Un test que ponga el docType
	// directamente en Schema.ID (como el borrador anterior de este plan
	// hacía) no habría detectado que mdocCredentialConfigValues necesita
	// leer AdditionalTypes.
	schema := vctypes.Schema{
		ID:              "custom-abc123",
		Std:             "mso_mdoc",
		Name:            "Mobile Driving Licence",
		AdditionalTypes: []string{"org.iso.18013.5.1.mDL"},
		FieldsSpec:      mdoc.MandatoryFields("org.iso.18013.5.1.mDL"),
	}

	doctype, vcTemplate, claims, signatureAlgo, keyManagerAppID, keyManagerRefID, cryptoSuite := mdocCredentialConfigValues(schema)

	if doctype != "org.iso.18013.5.1.mDL" {
		t.Errorf("doctype = %q, want %q (from AdditionalTypes[0], not schema.ID=%q)", doctype, "org.iso.18013.5.1.mDL", schema.ID)
	}
	if signatureAlgo != mdoc.MdocSignatureAlgo {
		t.Errorf("signatureAlgo = %q, want %q", signatureAlgo, mdoc.MdocSignatureAlgo)
	}
	if keyManagerAppID != "CERTIFY_VC_SIGN_EC_R1" {
		t.Errorf("keyManagerAppID = %q, want the real EC value captured from the spike, %q", keyManagerAppID, "CERTIFY_VC_SIGN_EC_R1")
	}
	if keyManagerRefID != "EC_SECP256R1_SIGN" {
		t.Errorf("keyManagerRefID = %q, want %q", keyManagerRefID, "EC_SECP256R1_SIGN")
	}
	if cryptoSuite != "EcdsaSecp256r1Signature2019" {
		t.Errorf("cryptoSuite = %q, want the real value captured from the spike, %q", cryptoSuite, "EcdsaSecp256r1Signature2019")
	}

	// vc_template must NOT be empty/NULL — the spike confirmed Inji needs a
	// real Velocity template for mdoc, unlike this plan's first (wrong) draft.
	if len(vcTemplate) == 0 {
		t.Fatal("vc_template is empty — Inji Certify needs a real template for mso_mdoc, confirmed by the spike")
	}
	decoded, err := base64.StdEncoding.DecodeString(vcTemplate)
	if err != nil {
		t.Fatalf("vc_template is not valid base64: %v", err)
	}
	if !strings.Contains(string(decoded), `"docType": "${_doctype}"`) {
		t.Errorf("vc_template missing docType marker, got: %s", decoded)
	}
	// Bracket-notation nested access, NOT bare ${field} — confirmed live
	// against Inji Certify v0.14.0 that bare markers never resolve once
	// claims are nested under the ISO namespace (Velocity's rootContext
	// only resolves bare markers against top-level context keys). See this
	// function's doc comment for the full empirical trace.
	if !strings.Contains(string(decoded), `"family_name", "elementValue": "${rootContext['org.iso.18013.5.1'].family_name}"`) {
		t.Errorf("vc_template's family_name marker must use bracket-notation nested access (quoted, it's a string), got: %s", decoded)
	}
	// driving_privileges' marker must be UNQUOTED (it's a JSON array, not a
	// string) — confirmed live that the quoted form forces Velocity's
	// substitution through Java's List/Map toString(), producing malformed
	// non-JSON text instead of a real array.
	if !strings.Contains(string(decoded), `"driving_privileges", "elementValue": ${rootContext['org.iso.18013.5.1'].driving_privileges}`) {
		t.Errorf("vc_template's driving_privileges marker must be UNQUOTED bracket-notation nested access, got: %s", decoded)
	}

	var claimsMap map[string]any
	if err := json.Unmarshal(claims, &claimsMap); err != nil {
		t.Fatalf("mso_mdoc_claims is not valid JSON: %v", err)
	}
	ns, ok := claimsMap["org.iso.18013.5.1"].(map[string]any)
	if !ok {
		t.Fatalf("mso_mdoc_claims missing namespace org.iso.18013.5.1, got: %v", claimsMap)
	}
	if _, ok := ns["driving_privileges"]; !ok {
		t.Error("mso_mdoc_claims missing driving_privileges")
	}
	if _, ok := ns["portrait"]; !ok {
		t.Error("mso_mdoc_claims missing portrait — ISO 18013-5 Table 3 mandatory element (NOTE: the spike's own working config did NOT include portrait — Task 4 Step 7 must verify this empirically; if it fails, this claim declaration alone is not sufficient and this task must be revisited)")
	}
}
