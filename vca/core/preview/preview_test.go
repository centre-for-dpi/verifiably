// SPDX-License-Identifier: Apache-2.0

package preview

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

const degree = `{
  "type": "object",
  "properties": {
    "name": {"type": "string", "title": "Full name", "minLength": 3},
    "degree": {"type": "string", "enum": ["BSc", "MSc"]},
    "year": {"type": "integer", "minimum": 1900},
    "gpa": {"type": "number"},
    "honours": {"type": "boolean"},
    "email": {"type": "string", "format": "email"},
    "born": {"type": "string", "format": "date"},
    "seen": {"type": "string", "format": "date-time"},
    "site": {"type": "string", "format": "uri"},
    "tags": {"type": "array", "items": {"type": "string"}},
    "empty": {"type": "array"},
    "addr": {"$ref": "#/$defs/address"},
    "bad": {"$ref": "#/nope"},
    "fixed": {"const": "X"},
    "ex": {"examples": ["from example"]},
    "def": {"default": 7},
    "nothing": {"type": "null"},
    "either": {"type": ["null", "integer"]},
    "short": {"type": "string", "maxLength": 3},
    "titled": {"type": "string", "title": "T"},
    "sub": {"type": "object", "properties": {"a": {"type": "string"}, "b": false}},
    "flag": true
  },
  "required": ["name"],
  "$defs": {"address": {"type": "object", "properties": {"street": {"type": "string"}}}}
}`

func schema() Schema {
	return Schema{
		Type:       "UniversityDegree",
		JSONSchema: degree,
		Display:    []Display{{Name: "Degree", Description: "A university degree", Locale: "en", BackgroundColor: "#112233", TextColor: "#ffffff"}, {Name: "Diplôme", Locale: "fr"}},
		SDClaims:   []string{"name", "ghost"},
		Formats:    []string{FormatJwtVcJson, FormatDcSdJwt},
		Expires:    true,
	}
}

func TestSampleData(t *testing.T) {
	sample, sampleErr := SampleData(degree)
	if sampleErr != nil {
		t.Fatal(sampleErr)
	}
	want := map[string]any{
		"name": "Sample Full name", "degree": "BSc", "year": 1900.0, "gpa": 1.5, "honours": true,
		"email": "citizen@example.org", "born": "1990-01-31", "seen": "2024-01-31T10:00:00Z", "site": "https://example.org/site",
		"fixed": "X", "ex": "from example", "def": 7.0, "nothing": nil, "either": 1.0, "short": "Sam", "titled": "Sample T",
	}
	for k, v := range want {
		if sample[k] != v {
			t.Errorf("%s: got %#v want %#v", k, sample[k], v)
		}
	}
	if tags := anyval.As[[]any](sample["tags"]); len(tags) != 1 || tags[0] != "Sample tags" {
		t.Errorf("tags: %v", sample["tags"])
	}
	if empty := anyval.As[[]any](sample["empty"]); len(empty) != 0 {
		t.Errorf("empty: %v", sample["empty"])
	}
	if addr := anyval.As[map[string]any](sample["addr"]); addr["street"] != "Sample street" {
		t.Errorf("addr: %v", sample["addr"])
	}
	if bad := sample["bad"]; bad != "Sample bad" {
		t.Errorf("bad ref: %v", bad)
	}
	if sub := anyval.As[map[string]any](sample["sub"]); sub["a"] != "Sample a" || len(sub) != 1 {
		t.Errorf("sub: %v", sub)
	}
	if _, has := sample["flag"]; has {
		t.Error("boolean schema property has a sample")
	}
	if _, err := SampleData("{"); err == nil {
		t.Fatal("bad schema")
	}
	long, err := SampleData(`{"properties": {"n": {"type": "string", "minLength": 20}}}`)
	if err != nil || len(anyval.As[string](long["n"])) != 20 {
		t.Fatalf("minLength: %v %v", long, err)
	}
	loop, err := SampleData(`{"properties": {"n": {"$ref": "#/properties/n"}}}`)
	if err != nil || loop["n"] != nil {
		t.Fatalf("loop: %v %v", loop, err)
	}
	num, err := SampleData(`{"properties": {"n": {"type": "number", "minimum": 2}, "s": {"$ref": "#/title"}}, "title": "x"}`)
	if err != nil || num["n"] != 2.0 || num["s"] != "Sample s" {
		t.Fatalf("minimum: %v %v", num, err)
	}
}

func TestPreviewCredentialFormats(t *testing.T) {
	s := schema()
	sample, sampleErr := SampleData(degree)
	if sampleErr != nil {
		t.Fatalf("SampleData: %v", sampleErr)
	}
	sample["extra"] = "e"
	sample["iss"] = "spoof"
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	p, pErr := PreviewCredential(s, sample, Options{Now: now, SchemaURL: "https://issuer.example/schemas/1"})
	if pErr != nil {
		t.Fatal(pErr)
	}
	if p.Format != FormatJwtVcJson {
		t.Fatalf("format: %s", p.Format)
	}
	var vc map[string]any
	if err := json.Unmarshal([]byte(p.CredentialJSON), &vc); err != nil {
		t.Fatal(err)
	}
	if vc["validFrom"] != "2025-06-01T00:00:00Z" || vc["validUntil"] != "2026-06-01T00:00:00Z" || vc["issuer"] != DefaultIssuer {
		t.Fatalf("vc: %v", vc)
	}
	if anyval.As[map[string]any](vc["credentialSchema"])["id"] != "https://issuer.example/schemas/1" {
		t.Fatalf("schema: %v", vc["credentialSchema"])
	}
	if anyval.As[map[string]any](vc["credentialSubject"])["name"] != "Sample Full name" {
		t.Fatalf("subject: %v", vc["credentialSubject"])
	}
	if p.Card.Title != "Degree" || p.Card.BackgroundColor != "#112233" || len(p.Card.Rows) == 0 {
		t.Fatalf("card: %+v", p.Card)
	}
	if p.Card.Rows[0].Label != "Full name" || !p.Card.Rows[0].SelectivelyDisclosable || p.Card.Rows[1].SelectivelyDisclosable {
		t.Fatalf("rows: %+v", p.Card.Rows[:2])
	}
	last := p.Card.Rows[len(p.Card.Rows)-1]
	if last.Label != "iss" {
		t.Fatalf("extra rows: %+v", last)
	}
	if !strings.Contains(strings.Join(p.Problems, "\n"), "ghost") {
		t.Fatalf("problems: %v", p.Problems)
	}
	if len(p.PDFRef) != 32 {
		t.Fatalf("ref: %s", p.PDFRef)
	}

	sd, sdErr := PreviewCredential(s, sample, Options{Format: FormatDcSdJwt, Locale: "fr", Issuer: "did:web:issuer.example"})
	if sdErr != nil {
		t.Fatal(sdErr)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(sd.CredentialJSON), &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if payload["vct"] != "UniversityDegree" || payload["iss"] != "did:web:issuer.example" || payload["iat"] != float64(DefaultNow.Unix()) || payload["exp"] == nil {
		t.Fatalf("sd-jwt: %v", payload)
	}
	if payload["_sd_alg"] != "sha-256" || sd.Card.Title != "Diplôme" || sd.PDFRef == p.PDFRef {
		t.Fatalf("sd-jwt: %v %+v", payload, sd.Card)
	}

	expiring, err := PreviewCredential(s, nil, Options{Format: FormatMsoMdoc})
	if err != nil || !strings.Contains(expiring.CredentialJSON, `"validUntil": "2025-01-30T10:00:00Z"`) {
		t.Fatalf("mdoc validUntil: %v %s", err, expiring.CredentialJSON)
	}
	s.Expires = false
	s.SDClaims = nil
	s.Display = nil
	mdoc, err := PreviewCredential(s, nil, Options{Format: FormatMsoMdoc})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if gotErr := json.Unmarshal([]byte(mdoc.CredentialJSON), &doc); gotErr != nil {
		t.Fatalf("json.Unmarshal: %v", gotErr)
	}
	if doc["docType"] != "UniversityDegree" || anyval.As[map[string]any](doc["validityInfo"])["validUntil"] != nil {
		t.Fatalf("mdoc: %v", doc)
	}
	if mdoc.Card.Title != "UniversityDegree" || len(mdoc.Card.Rows) != 0 {
		t.Fatalf("card: %+v", mdoc.Card)
	}
	if !strings.Contains(strings.Join(mdoc.Problems, "\n"), "required") || !strings.Contains(strings.Join(mdoc.Problems, "\n"), "display") {
		t.Fatalf("problems: %v", mdoc.Problems)
	}
	ldp, err := PreviewCredential(s, nil, Options{Format: FormatLdpVc})
	if err != nil || strings.Contains(ldp.CredentialJSON, "validUntil") || strings.Contains(ldp.CredentialJSON, "credentialSchema") {
		t.Fatalf("ldp: %v %s", err, ldp.CredentialJSON)
	}
	plain, err := PreviewCredential(Schema{Type: "", JSONSchema: `{}`}, nil, Options{})
	if err != nil || plain.Format != FormatDcSdJwt || !strings.Contains(strings.Join(plain.Problems, "\n"), "no credential type") || strings.Contains(plain.CredentialJSON, "_sd_alg") {
		t.Fatalf("plain: %v %+v", err, plain)
	}
	if plain.Card.Title != "" {
		t.Fatal("empty title")
	}
	if _, err := PreviewCredential(Schema{JSONSchema: "["}, nil, Options{}); err == nil {
		t.Fatal("bad schema")
	}
	if _, err := PreviewCredential(Schema{JSONSchema: "{}"}, nil, Options{Format: "xml"}); err == nil {
		t.Fatal("bad format")
	}
	if _, err := PreviewCredential(Schema{JSONSchema: "{}"}, map[string]any{"f": func() {}}, Options{}); err == nil {
		t.Fatal("unencodable sample")
	}
}

func TestStringify(t *testing.T) {
	cases := map[string]any{"": nil, "a": "a", "3": 3.0, "1.5": 1.5, "yes": true, "no": false, `["x"]`: []any{"x"}, `{"a":1}`: map[string]any{"a": 1}}
	for want, v := range cases {
		if got := Stringify(v); got != want {
			t.Errorf("%v: got %q want %q", v, got, want)
		}
	}
	if got := Stringify(func() {}); !strings.HasPrefix(got, "0x") {
		t.Errorf("func: %q", got)
	}
}

func TestPDF(t *testing.T) {
	s := schema()
	sample, err := SampleData(degree)
	if err != nil {
		t.Fatalf("SampleData: %v", err)
	}
	sample["name"] = strings.Repeat("word ", 40) + "(end)\\"
	sample["long"] = strings.Repeat("x", 200) + "é€"
	p, err := PreviewCredential(s, sample, Options{})
	if err != nil {
		t.Fatal(err)
	}
	doc := string(PDF(p))
	if !strings.HasPrefix(doc, "%PDF-1.4\n") || !strings.HasSuffix(doc, "%%EOF\n") {
		t.Fatalf("frame: %q", doc[:20])
	}
	for _, want := range []string{"(Degree) Tj", "(A university degree) Tj", "Format: jwt_vc_json", "selectively disclosable", `\(end\)\\`, "(Problems) Tj", "xref", "/Helvetica", "?"} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(doc, "é") {
		t.Error("non latin text not replaced")
	}
	var many []Row
	for i := 0; i < 80; i++ {
		many = append(many, Row{Label: "row", Value: "v"})
	}
	tall := PDF(Preview{Card: Card{Title: "T", Rows: many}})
	if strings.Count(string(tall), " Tj") >= 80 {
		t.Error("page overflow not cut")
	}
	if parts := wrap(strings.Repeat("a", 100)); len(parts) != 2 || len(parts[0]) != maxLine {
		t.Errorf("wrap without spaces: %v", parts)
	}
	if parts := wrap("short"); len(parts) != 1 {
		t.Errorf("wrap short: %v", parts)
	}
}
