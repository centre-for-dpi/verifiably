package waltid

import (
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

func TestBuildClaimsBlockEmitsPerLocaleDisplay(t *testing.T) {
	fields := []vctypes.FieldSpec{
		{
			Name:   "family_name",
			Labels: map[string]string{"en": "Family Name", "es-DO": "Apellidos"},
		},
		{Name: "document_number"}, // no labels — must derive
	}

	got := buildClaimsBlock(fields, "")

	for _, want := range []string{
		"family_name",
		`name = "Family Name"`,
		`locale = "en"`,
		`name = "Apellidos"`,
		`locale = "es-DO"`,
		"document_number",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("claims block missing %q:\n%s", want, got)
		}
	}
	// document_number declares no labels at all, so it gets an EMPTY display
	// list — not a synthesised English entry carrying the derived identifier.
	// claimLocales used to emit "en" unconditionally; a wallet then received
	// "Document Number" as though the issuer had authored it. With the schema
	// builder's base language now operator-chosen, that synthesis is wrong:
	// absent metadata means "wallet, derive it yourself", which is exactly
	// what wallets do and what the field's contract says.
	if strings.Contains(got, `name = "Document Number"`) {
		t.Errorf("field with no labels must not get a synthesised English display entry:\n%s", got)
	}
}

// TestBuildClaimsBlockOmitsEnglishWhenNotDeclared is the Commit 3 guard on
// claimLocales: the schema builder's first language row is freely editable,
// so a deployment issuing only in Spanish declares {"es-DO": ...} and no
// English. Synthesising an "en" entry there publishes a phantom English label
// carrying the DERIVED identifier — a translation the issuer never authored,
// which a wallet would then prefer over the Spanish for any en-* holder.
func TestBuildClaimsBlockOmitsEnglishWhenNotDeclared(t *testing.T) {
	got := buildClaimsBlock([]vctypes.FieldSpec{
		{Name: "family_name", Labels: map[string]string{"es-DO": "Apellidos"}},
	}, "")

	if !strings.Contains(got, `{ name = "Apellidos", locale = "es-DO" }`) {
		t.Errorf("expected the declared Spanish display entry, got:\n%s", got)
	}
	if strings.Contains(got, `locale = "en"`) {
		t.Errorf("Spanish-only field must not emit an English display entry:\n%s", got)
	}
	if strings.Contains(got, `name = "Family Name"`) {
		t.Errorf("derived English label leaked into a Spanish-only field:\n%s", got)
	}
}

// English keeps its FRONT position when the field DOES declare it — it is
// still the data model's base language (vctypes.FieldSpec.Label falls back to
// "en" for any locale it cannot resolve), even though the form no longer
// forces the operator to supply it.
func TestBuildClaimsBlockKeepsEnglishFirstWhenDeclared(t *testing.T) {
	got := buildClaimsBlock([]vctypes.FieldSpec{
		{Name: "family_name", Labels: map[string]string{
			"ht": "Siyati", "en": "Family Name", "es-DO": "Apellidos",
		}},
	}, "")
	en := strings.Index(got, `locale = "en"`)
	esDO := strings.Index(got, `locale = "es-DO"`)
	ht := strings.Index(got, `locale = "ht"`)
	if en < 0 || esDO < 0 || ht < 0 {
		t.Fatalf("expected all three locales, got:\n%s", got)
	}
	if !(en < esDO && esDO < ht) {
		t.Errorf("expected en first then the rest sorted (en=%d es-DO=%d ht=%d):\n%s", en, esDO, ht, got)
	}
}

func TestBuildClaimsBlockEmptyForNoFields(t *testing.T) {
	// Stock (non-custom) schemas carry no FieldsSpec. They must emit no
	// claims block at all rather than an empty one, which walt.id's HOCON
	// parser would reject.
	if got := buildClaimsBlock(nil, ""); got != "" {
		t.Errorf("expected empty string for no fields, got:\n%s", got)
	}
}

// TestBuildClaimsBlockFlatObjectForW3C pins that a blank namespace (used by
// every non-mdoc builder: buildJWTVCJsonEntry, buildLinkedDataEntry,
// buildSDJWTEntry) emits a `credentialSubject` HOCON OBJECT keyed by field
// name, NOT a `claims` array of {path, display} entries.
//
// The legacy issuer-api (walt.id 0.23.1, package id.walt.oid4vc.data)'s
// CredentialSupported declares TWO separate, differently-shaped fields —
// confirmed by decompiling waltid-openid4vc-jvm-0.23.1.jar:
//   - credentialSubject: Map<String, ClaimDescriptor>       (flat, one level)
//   - claims:            Map<String, Map<String, ClaimDescriptor>> (namespaced)
//
// There is no `path` field on ClaimDescriptor at all, and `claims` is ALWAYS
// two levels deep (ClaimDescriptorNamespacedMapSerializer, the only
// serializer wired to it) — a flat format has no second-level key to supply.
// issuer-api2's shipped baseline uses `claims = [ {path=...} ]` because it
// runs the unrelated id.walt.openid4vci.metadata.issuer package (draft 13
// style, buildMDocEntry's target only); that shape does not exist in legacy
// issuer-api's model at all.
//
// Emitting `claims` as an array here — walt.id's own shipped legacy config
// never contains this field for flat formats — throws
// JsonDecodingException: Expected JsonObject, but had JsonArray … at path:
// $.claims during CIProvider.<init>, which crash-loops the entire issuer-api
// container before its web server binds. See the 2026-08-24 incident: POST
// /onboard/issuer failed with connection refused because issuer-api never
// came up.
func TestBuildClaimsBlockFlatObjectForW3C(t *testing.T) {
	got := buildClaimsBlock([]vctypes.FieldSpec{{Name: "family_name"}}, "")
	if !strings.Contains(got, `credentialSubject = {`) {
		t.Errorf("expected a credentialSubject HOCON object, got:\n%s", got)
	}
	if strings.Contains(got, "claims") {
		t.Errorf("flat (non-mdoc) claims block must use credentialSubject, not claims at all, got:\n%s", got)
	}
	if strings.Contains(got, `path`) {
		t.Errorf("non-mdoc claims block must not contain a path key (ClaimDescriptor has none), got:\n%s", got)
	}
	if !strings.Contains(got, `family_name = {`) {
		t.Errorf("expected the field name as the object key, got:\n%s", got)
	}
}

// TestBuildClaimsBlockNamespacedPathForMDoc pins the two-element
// ["<namespace>", "<field>"] path shape mdoc claims require — confirmed
// against walt.id's own shipped metadata
// (deploy/k8s/config/issuer2/credential-issuer-metadata.baseline.conf) and against
// verifier.go's buildSelectiveInputDescriptor, which resolves mdoc claims
// the same namespace-qualified way.
func TestBuildClaimsBlockNamespacedPathForMDoc(t *testing.T) {
	got := buildClaimsBlock([]vctypes.FieldSpec{{Name: "family_name"}}, "org.iso.18013.5.1")
	if !strings.Contains(got, `path = ["org.iso.18013.5.1", "family_name"]`) {
		t.Errorf("expected namespaced two-element path, got:\n%s", got)
	}
}

// TestBuildMDocEntry_ClaimsUseCorrectNamespacePerDocType pins that
// buildMDocEntry resolves the base namespace per docType via
// docTypeProfiles rather than the mdocNamespaceFor dot-stripping heuristic,
// which is wrong for Photo ID (org.iso.23220.photoid.1 strips to
// org.iso.23220.photoid; the real namespace is org.iso.23220.1).
func TestBuildMDocEntry_ClaimsUseCorrectNamespacePerDocType(t *testing.T) {
	cases := []struct {
		name          string
		docType       string
		wantNamespace string
	}{
		{"mDL", "org.iso.18013.5.1.mDL", "org.iso.18013.5.1"},
		{"Photo ID", "org.iso.23220.photoid.1", "org.iso.23220.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			schema := vctypes.Schema{
				ID:              "custom-" + tc.name,
				Name:            tc.name,
				Std:             "mso_mdoc",
				Custom:          true,
				AdditionalTypes: []string{tc.docType},
				FieldsSpec:      []vctypes.FieldSpec{{Name: "portrait"}},
			}
			got := buildMDocEntry("configid", "TypeName", schema)
			want := `path = ["` + tc.wantNamespace + `", "portrait"]`
			if !strings.Contains(got, want) {
				t.Errorf("[%s] expected %q in mdoc entry, got:\n%s", tc.name, want, got)
			}
		})
	}
}
