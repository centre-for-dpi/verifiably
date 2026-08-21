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

	got := buildClaimsBlock(fields)

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
	if got := buildClaimsBlock(nil); got != "" {
		t.Errorf("expected empty string for no fields, got:\n%s", got)
	}
}
