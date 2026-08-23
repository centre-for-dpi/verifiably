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

// TestBuildClaimsBlockFlatPathForW3C pins that a blank namespace (used by
// every non-mdoc builder) produces a single-element path. This matters as
// much as the mdoc namespacing fix below: it proves the fix did not
// namespace every format's claims, only mdoc's.
func TestBuildClaimsBlockFlatPathForW3C(t *testing.T) {
	got := buildClaimsBlock([]vctypes.FieldSpec{{Name: "family_name"}}, "")
	if !strings.Contains(got, `path = ["family_name"]`) {
		t.Errorf("expected flat single-element path for non-mdoc formats, got:\n%s", got)
	}
	if strings.Contains(got, `path = ["org`) {
		t.Errorf("non-mdoc claims block unexpectedly namespaced:\n%s", got)
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
