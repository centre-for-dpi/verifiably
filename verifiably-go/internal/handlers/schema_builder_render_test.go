package handlers

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/internal/mdoc"
	"github.com/verifiably/verifiably-go/vctypes"
)

// loadSchemaBuilderTemplate parses templates/pages/issuer_schema_builder.html
// with the minimal FuncMap its directives touch across the whole file
// (`t`, `list`, `hasPrefix`, `dict` — needed by
// {{template "_field_row" (dict "Idx" $i "Field" $f)}} — and
// `mdocMandatoryNames`, needed by the doctype-aware Locked lookup in the
// same range). ParseFiles parses every {{define}} block in the file, not
// just the one under test, so all of them need to resolve even though only
// _field_row gets executed below. Mirrors the loadPageTemplate/
// loadTestTemplates pattern used elsewhere in this package
// (inji_holder_test.go, status_list_e2e_test.go) rather than reconstructing
// the full production funcMap from cmd/server/main.go.
func loadSchemaBuilderTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl := template.New("").Funcs(template.FuncMap{
		"t":         func(s string, _ ...any) string { return s },
		"list":      func(args ...any) []any { return args },
		"hasPrefix": strings.HasPrefix,
		"dict": func(pairs ...any) (map[string]any, error) {
			m := make(map[string]any, len(pairs)/2)
			for i := 0; i+1 < len(pairs); i += 2 {
				k, _ := pairs[i].(string)
				m[k] = pairs[i+1]
			}
			return m, nil
		},
		"mdocMandatoryNames": func(std, docType string) map[string]bool {
			out := map[string]bool{}
			if std != "mso_mdoc" {
				return out
			}
			for _, f := range mdoc.MandatoryFields(docType) {
				out[f.Name] = true
			}
			return out
		},
	})
	files, err := filepath.Glob("../../templates/pages/issuer_schema_builder.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("locate issuer_schema_builder.html: err=%v files=%v", err, files)
	}
	if _, err := tmpl.ParseFiles(files...); err != nil {
		t.Fatalf("parse template: %v", err)
	}
	return tmpl
}

// TestFieldRowRendersLabels renders _field_row with a FieldSpec carrying
// en/es-DO/ht labels and checks the label column, the per-locale rows, and
// the add-a-locale row all appear with escaped, correctly-keyed field names.
func TestFieldRowRendersLabels(t *testing.T) {
	tmpl := loadSchemaBuilderTemplate(t)
	field := vctypes.FieldSpec{
		Name:     "family_name",
		Datatype: "string",
		Labels: map[string]string{
			"en":    "Family Name",
			"es-DO": "Apellidos",
			"ht":    "Siyati",
		},
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "_field_row", map[string]any{"Idx": 0, "Field": field}); err != nil {
		t.Fatalf("render _field_row: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`name="field_label_0"`,
		`value="Family Name"`,
		`name="field_label_0_es-DO"`,
		`value="Apellidos"`,
		`name="field_label_0_ht"`,
		`value="Siyati"`,
		`name="new_locale_0"`,
		`name="new_label_0"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestFieldRowRendersWithNilLabels confirms a FieldSpec with no Labels at
// all (the common case — most fields never get a translated label) renders
// without panicking on the nil-map index and without leaking another
// field's label into the empty one.
func TestFieldRowRendersWithNilLabels(t *testing.T) {
	tmpl := loadSchemaBuilderTemplate(t)
	field := vctypes.FieldSpec{Name: "document_number", Datatype: "string"}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "_field_row", map[string]any{"Idx": 1, "Field": field}); err != nil {
		t.Fatalf("render _field_row with nil Labels: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `name="field_label_1"`) {
		t.Errorf("expected the empty-label input for a field with no labels, got:\n%s", out)
	}
	if strings.Contains(out, `value="Family Name"`) {
		t.Errorf("field with no labels leaked another field's label:\n%s", out)
	}
}
