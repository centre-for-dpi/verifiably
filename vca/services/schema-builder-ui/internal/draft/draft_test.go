// SPDX-License-Identifier: Apache-2.0

package draft_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/jsonschema"
	"github.com/centre-for-dpi/vc-adapters/core/preview"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/draft"
)

func sample() draft.Draft {
	return draft.Draft{
		Type: "DiplomaCredential", Title: "Diploma", Description: "A school diploma.",
		Wire: []string{preview.FormatDcSdJwt},
		Fields: []draft.Field{
			{Name: "given_name", Label: "Given name", Type: "string", Required: true, SelectivelyDisclosable: true},
			{Name: "birth_date", Label: "Birth date", Type: "string", Format: "date"},
			{Name: "grade", Label: "Grade", Description: "The final grade.", Type: "integer", Enum: []string{"1", "2", "3"}},
		},
	}
}

func TestEmptyIsUsable(t *testing.T) {
	d := draft.Empty().Normalize()
	if len(d.Problems()) != 0 {
		t.Fatalf("problems: %v", d.Problems())
	}
	if _, err := jsonschema.Parse([]byte(d.Document())); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func TestDocumentKeepsFieldOrder(t *testing.T) {
	doc := sample().Normalize().Document()
	parsed, err := jsonschema.Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"given_name", "birth_date", "grade"}
	got := parsed.Properties()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("properties = %v, want %v", got, want)
	}
	if r := parsed.Required(); len(r) != 1 || r[0] != "given_name" {
		t.Errorf("required = %v", r)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if root["$schema"] != draft.Dialect {
		t.Errorf("$schema = %v", root["$schema"])
	}
	if root["additionalProperties"] != false {
		t.Errorf("additionalProperties = %v", root["additionalProperties"])
	}
	props := mustAs[map[string]any](t, root["properties"])
	grade := mustAs[map[string]any](t, props["grade"])
	if got := mustAs[[]any](t, grade["enum"]); len(got) != 3 || got[0] != float64(1) {
		t.Errorf("enum = %v, want numbers", got)
	}
	date := mustAs[map[string]any](t, props["birth_date"])
	if date["format"] != "date" {
		t.Errorf("format = %v", date["format"])
	}
	if grade["description"] != "The final grade." {
		t.Errorf("description = %v", grade["description"])
	}
}

func TestDocumentEscapesText(t *testing.T) {
	d := draft.Draft{
		Type: "T", Title: "A \"quoted\"\ttitle\\", Description: "Line\none\rtwo\x01",
		Fields: []draft.Field{{Name: "a", Label: "é", Type: "string"}},
	}.Normalize()
	var root map[string]any
	if err := json.Unmarshal([]byte(d.Document()), &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if root["title"] != "A \"quoted\"\ttitle\\" {
		t.Errorf("title = %q", root["title"])
	}
	if root["description"] != "Line\none\rtwo\x01" {
		t.Errorf("description = %q", root["description"])
	}
	props := mustAs[map[string]any](t, root["properties"])
	if mustAs[map[string]any](t, props["a"])["title"] != "é" {
		t.Errorf("label = %v", props["a"])
	}
}

func TestDocumentEmptyDraft(t *testing.T) {
	doc := draft.Draft{Type: "T"}.Normalize().Document()
	var root map[string]any
	if err := json.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := mustAs[[]any](t, root["required"]); len(got) != 0 {
		t.Errorf("required = %v, want empty", got)
	}
	if _, has := root["description"]; has {
		t.Errorf("an empty description must not appear")
	}
}

func TestEnumValueConversion(t *testing.T) {
	d := draft.Draft{Type: "T", Fields: []draft.Field{
		{Name: "n", Type: "number", Enum: []string{"1.5", "x"}},
		{Name: "b", Type: "boolean", Enum: []string{"true", "maybe"}},
		{Name: "i", Type: "integer", Enum: []string{"7", "x"}},
	}}.Normalize()
	var root map[string]any
	if err := json.Unmarshal([]byte(d.Document()), &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	props := mustAs[map[string]any](t, root["properties"])
	cases := map[string][]any{
		"n": {1.5, "x"},
		"b": {true, "maybe"},
		"i": {float64(7), "x"},
	}
	for key, want := range cases {
		got := mustAs[[]any](t, mustAs[map[string]any](t, props[key])["enum"])
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s enum[%d] = %v, want %v", key, i, got[i], want[i])
			}
		}
	}
}

func TestNormalizeFillsAndDrops(t *testing.T) {
	d := draft.Draft{
		Type: "  T  ", Wire: []string{"nope", preview.FormatLdpVc, preview.FormatLdpVc},
		Fields: []draft.Field{
			{Name: "  "},
			{Name: " ok ", Type: "weird", Format: "date"},
			{Name: "num", Type: "number", Format: "date"},
		},
	}.Normalize()
	if d.Type != "T" || d.Title != "T" || d.Locale != "en" {
		t.Errorf("draft = %+v", d)
	}
	if len(d.Wire) != 1 || d.Wire[0] != preview.FormatLdpVc {
		t.Errorf("wire = %v", d.Wire)
	}
	if len(d.Fields) != 2 {
		t.Fatalf("fields = %v", d.Fields)
	}
	if d.Fields[0].Name != "ok" || d.Fields[0].Label != "ok" || d.Fields[0].Type != "string" || d.Fields[0].Format != "date" {
		t.Errorf("field 0 = %+v", d.Fields[0])
	}
	if d.Fields[1].Format != "" {
		t.Errorf("a number keeps no format: %+v", d.Fields[1])
	}
}

func TestNormalizeDefaultsWire(t *testing.T) {
	d := draft.Draft{Type: "T", Wire: []string{"nope"}}.Normalize()
	if len(d.Wire) != 1 || d.Wire[0] != preview.FormatDcSdJwt {
		t.Errorf("wire = %v", d.Wire)
	}
}

func TestNormalizeCaps(t *testing.T) {
	var fields []draft.Field
	for i := 0; i < draft.MaxFields+5; i++ {
		fields = append(fields, draft.Field{Name: "f", Type: "string"})
	}
	var values []string
	for i := 0; i < draft.MaxEnumValues+5; i++ {
		values = append(values, "v")
	}
	fields[0].Enum = values
	d := draft.Draft{Type: "T", Fields: fields}.Normalize()
	if len(d.Fields) != draft.MaxFields {
		t.Errorf("fields = %d, want %d", len(d.Fields), draft.MaxFields)
	}
	if len(d.Fields[0].Enum) != draft.MaxEnumValues {
		t.Errorf("enum = %d, want %d", len(d.Fields[0].Enum), draft.MaxEnumValues)
	}
}

func TestProblems(t *testing.T) {
	cases := []struct {
		name  string
		draft draft.Draft
		want  int
	}{
		{"ok", sample(), 0},
		{"no type", draft.Draft{Fields: sample().Fields}, 1},
		{"no field", draft.Draft{Type: "T"}, 1},
		{"bad name", draft.Draft{Type: "T", Fields: []draft.Field{{Name: "9x", Type: "string"}}}, 1},
		{"twice", draft.Draft{Type: "T", Fields: []draft.Field{{Name: "a", Type: "string"}, {Name: "a", Type: "string"}}}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.draft.Normalize().Problems(); len(got) != c.want {
				t.Errorf("problems = %v, want %d", got, c.want)
			}
		})
	}
}

func TestPreviewSchemaRenders(t *testing.T) {
	d := sample().Normalize()
	s := d.PreviewSchema()
	if len(s.SDClaims) != 1 || s.SDClaims[0] != "given_name" {
		t.Errorf("sd claims = %v", s.SDClaims)
	}
	values, err := preview.SampleData(s.JSONSchema)
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	p, err := preview.PreviewCredential(s, values, preview.Options{})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if p.Card.Title != "Diploma" {
		t.Errorf("title = %q", p.Card.Title)
	}
	if len(p.Problems) != 0 {
		t.Errorf("problems = %v", p.Problems)
	}
}

func TestParse(t *testing.T) {
	values := url.Values{
		"type": {"Diploma"}, "title": {"Diploma"}, "locale": {"en-GB"},
		"logo_uri": {"https://example.test/l.png"}, "background_color": {"#112233"},
		"text_color": {"#ffffff"}, "expires": {"on"}, "wire": {preview.FormatLdpVc},
		"id":                  {"schema-1"},
		"description":         {"A diploma."},
		"field.1.name":        {"family_name"},
		"field.1.label":       {"Family name"},
		"field.1.type":        {"string"},
		"field.1.required":    {"on"},
		"field.1.sd":          {"on"},
		"field.0.name":        {"grade"},
		"field.0.type":        {"integer"},
		"field.0.enum":        {" 1 , 2 ,, 3 "},
		"field.0.description": {"The final grade."},
		"field.x.name":        {"skip"},
		"field.-1.name":       {"skip"},
		"fieldnope":           {"skip"},
		"field.2":             {"skip"},
	}
	d := draft.Parse(values)
	if d.ID != "schema-1" || d.Locale != "en-GB" || !d.Expires {
		t.Errorf("draft = %+v", d)
	}
	if len(d.Wire) != 1 || d.Wire[0] != preview.FormatLdpVc {
		t.Errorf("wire = %v", d.Wire)
	}
	if len(d.Fields) != 2 {
		t.Fatalf("fields = %+v", d.Fields)
	}
	if d.Fields[0].Name != "grade" || len(d.Fields[0].Enum) != 3 {
		t.Errorf("field 0 = %+v", d.Fields[0])
	}
	if d.Fields[1].Name != "family_name" || !d.Fields[1].Required || !d.Fields[1].SelectivelyDisclosable {
		t.Errorf("field 1 = %+v", d.Fields[1])
	}
}

func TestParseCheckedValues(t *testing.T) {
	for _, on := range []string{"on", "true", "YES", "1"} {
		d := draft.Parse(url.Values{"type": {"T"}, "expires": {on}, "field.0.name": {"a"}})
		if !d.Expires {
			t.Errorf("%q must mean on", on)
		}
	}
	d := draft.Parse(url.Values{"type": {"T"}, "expires": {"off"}, "field.0.name": {"a"}})
	if d.Expires {
		t.Error("off must mean off")
	}
}

func TestEnumText(t *testing.T) {
	if got := draft.EnumText([]string{"a", "b"}); got != "a, b" {
		t.Errorf("got %q", got)
	}
	if got := draft.EnumText(nil); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestFromDocument(t *testing.T) {
	doc := `{
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "title": "Imported",
      "description": "An imported schema.",
      "type": "object",
      "properties": {
        "given_name": {"type": "string", "title": "Given name", "minLength": 1},
        "birth_date": {"type": "string", "format": "date"},
        "shoe_size": {"type": "number", "format": "date"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "level": {"type": "string", "enum": ["a", "b"]},
        "plain": {}
      },
      "required": ["given_name"]
    }`
	d, warnings, err := draft.FromDocument(doc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if d.Title != "Imported" || d.Description != "An imported schema." {
		t.Errorf("draft = %+v", d)
	}
	if len(d.Fields) != 6 {
		t.Fatalf("fields = %d", len(d.Fields))
	}
	byName := map[string]draft.Field{}
	for _, f := range d.Fields {
		byName[f.Name] = f
	}
	if !byName["given_name"].Required || byName["given_name"].Label != "Given name" {
		t.Errorf("given_name = %+v", byName["given_name"])
	}
	if byName["birth_date"].Format != "date" {
		t.Errorf("birth_date = %+v", byName["birth_date"])
	}
	if byName["shoe_size"].Format != "" {
		t.Errorf("a number keeps no format: %+v", byName["shoe_size"])
	}
	if byName["tags"].Type != "string" {
		t.Errorf("an array becomes a string: %+v", byName["tags"])
	}
	if len(byName["level"].Enum) != 2 {
		t.Errorf("level = %+v", byName["level"])
	}
	if byName["plain"].Type != "string" {
		t.Errorf("plain = %+v", byName["plain"])
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"minLength", "items", `"tags"`, `"shoe_size"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings %q have no %q", joined, want)
		}
	}
}

func TestFromDocumentErrors(t *testing.T) {
	if _, _, err := draft.FromDocument("{"); err == nil {
		t.Error("a broken document must fail")
	}
	if _, _, err := draft.FromDocument("true"); err == nil {
		t.Error("a boolean document must fail")
	}
}

func TestFromDocumentDropsBooleanSchema(t *testing.T) {
	d, warnings, err := draft.FromDocument(`{"type":"object","properties":{"ok":{"type":"string"},"any":true}}`)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(d.Fields) != 1 || d.Fields[0].Name != "ok" {
		t.Errorf("fields = %+v", d.Fields)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "any") {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestFromDocumentNoProperty(t *testing.T) {
	d, warnings, err := draft.FromDocument(`{"type": "object"}`)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(d.Fields) != 0 {
		t.Errorf("fields = %v", d.Fields)
	}
	if len(warnings) != 1 {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestFromCatalog(t *testing.T) {
	doc := `{"type":"object","title":"Cat","properties":{"a":{"type":"string"},"b":{"type":"string"}}}`
	display := `[{"Name":"Card","Description":"A card.","Locale":"fr","LogoURI":"https://e.test/l.png","BackgroundColor":"#000000","TextColor":"#ffffff"}]`
	d, warnings, err := draft.FromCatalog("CatCredential", doc, display, []string{"b"}, preview.FormatMsoMdoc)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if d.Type != "CatCredential" || d.Title != "Card" || d.Locale != "fr" || d.TextColor != "#ffffff" {
		t.Errorf("draft = %+v", d)
	}
	if len(d.Wire) != 1 || d.Wire[0] != preview.FormatMsoMdoc {
		t.Errorf("wire = %v", d.Wire)
	}
	if d.Fields[0].SelectivelyDisclosable || !d.Fields[1].SelectivelyDisclosable {
		t.Errorf("sd flags = %+v", d.Fields)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v", warnings)
	}
}

func TestFromCatalogFallbacks(t *testing.T) {
	doc := `{"type":"object","title":"Cat","properties":{"a":{"type":"string"}}}`
	d, warnings, err := draft.FromCatalog("T", doc, "not json", nil, "nope")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if d.Title != "Cat" {
		t.Errorf("title = %q", d.Title)
	}
	if len(d.Wire) != 1 || d.Wire[0] != preview.FormatDcSdJwt {
		t.Errorf("wire = %v", d.Wire)
	}
	if len(warnings) != 1 {
		t.Errorf("warnings = %v", warnings)
	}
	if _, _, err := draft.FromCatalog("T", "{", "", nil, ""); err == nil {
		t.Error("a broken document must fail")
	}
}

func TestFromCatalogEmptyDisplayList(t *testing.T) {
	doc := `{"type":"object","title":"Cat","properties":{"a":{"type":"string"}}}`
	_, warnings, err := draft.FromCatalog("T", doc, "[]", nil, "")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(warnings) != 1 {
		t.Errorf("warnings = %v", warnings)
	}
}
