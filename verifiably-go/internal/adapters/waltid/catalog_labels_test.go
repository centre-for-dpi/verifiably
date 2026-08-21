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
		`name = "Document Number"`, // derived, not blank
	} {
		if !strings.Contains(got, want) {
			t.Errorf("claims block missing %q:\n%s", want, got)
		}
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
// (deploy/k8s/config/issuer2/credential-issuer-metadata.conf) and against
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
