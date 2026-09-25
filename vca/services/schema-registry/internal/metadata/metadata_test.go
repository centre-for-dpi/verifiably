// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
)

const doc = `{"type": "object", "properties": {"name": {"type": "string", "title": "Full name", "description": "The legal name"}, "age": {"type": "integer"}}, "required": ["name"]}`

var now = time.Date(2024, 1, 31, 10, 0, 0, 0, time.UTC)

func published() record.Record {
	return record.Record{
		ID: "degree", Version: 2, Type: "UniversityDegree", JSONSchema: doc, State: record.StatePublished,
		Formats:  []string{record.FormatDcSdJwt, record.FormatJwtVcJSON, record.FormatLdpVc, record.FormatMsoMdoc, record.FormatVcSdJwt},
		Display:  []record.Display{{Name: "Degree", Description: "A degree", Locale: "en", LogoURI: "https://x/logo.png", BackgroundColor: "#fff", TextColor: "#000"}},
		SDClaims: []string{"name"}, PublishedAt: now, ConfigurationIDs: map[string]string{record.FormatDcSdJwt: "dpg-id"},
	}
}

func TestURLsAndVct(t *testing.T) {
	if SchemaURL("https://r/", "a b", 2) != "https://r/schemas/a%20b/2" {
		t.Fatal(SchemaURL("https://r/", "a b", 2))
	}
	if VctURL("https://r", "T") != "https://r/.well-known/vct/T" {
		t.Fatal("vct url")
	}
	r := published()
	if Vct("https://r", r) != "https://r/.well-known/vct/UniversityDegree" {
		t.Fatal("derived vct")
	}
	r.Type = "https://types.example/degree"
	if Vct("https://r", r) != r.Type {
		t.Fatal("url type stays")
	}
}

func TestClaimsAndSchemaObject(t *testing.T) {
	claims := Claims(published())
	if len(claims) != 2 || claims[0].Name != "name" || claims[0].Title != "Full name" || !claims[0].Required || !claims[0].SD {
		t.Fatalf("claims %+v", claims)
	}
	if claims[1].Title != "age" || claims[1].Required || claims[1].SD {
		t.Fatalf("age %+v", claims[1])
	}
	bad := record.Record{JSONSchema: "{"}
	if Claims(bad) != nil || len(SchemaObject(bad)) != 0 {
		t.Fatal("bad document")
	}
	if len(SchemaObject(record.Record{JSONSchema: "null"})) != 0 {
		t.Fatal("null document")
	}
}

func TestConfigurations(t *testing.T) {
	opts := Options{BaseURL: "https://r"}
	r := published()
	configs := Configurations([]record.Record{r}, opts)
	if len(configs) != 5 {
		t.Fatalf("configs %d", len(configs))
	}
	sd := configs["dpg-id"]
	if sd["vct"] != "https://r/.well-known/vct/UniversityDegree" || sd["format"] != record.FormatDcSdJwt {
		t.Fatalf("sd-jwt %v", sd)
	}
	claims := mustAs[[]map[string]any](t, sd["claims"])
	if len(claims) != 2 || claims[0]["mandatory"] != true {
		t.Fatalf("claims %v", claims)
	}
	if configs["UniversityDegree_mso_mdoc"]["doctype"] != "UniversityDegree" {
		t.Fatal("mdoc")
	}
	ldp := mustAs[map[string]any](t, configs["UniversityDegree_ldp_vc"]["credential_definition"])
	if ctx := mustAs[[]any](t, ldp["@context"]); len(ctx) != 1 || ctx[0] != VCDMContext {
		t.Fatal("ldp context")
	}
	jwt := mustAs[map[string]any](t, configs["UniversityDegree_jwt_vc_json"]["credential_definition"])
	if _, has := jwt["@context"]; has {
		t.Fatal("jwt_vc_json has no context")
	}
	d := mustAs[[]map[string]any](t, sd["display"])[0]
	if mustAs[map[string]any](t, d["logo"])["uri"] != "https://x/logo.png" || d["background_color"] != "#fff" || d["text_color"] != "#000" {
		t.Fatalf("display %v", d)
	}
	r.Display = nil
	c := Configuration(r, record.FormatDcSdJwt, Options{BaseURL: "https://r", SigningAlgs: []string{"ES384"}})
	if mustAs[[]map[string]any](t, mustAs[[]map[string]any](t, c["claims"])[0]["display"])[0]["name"] != "Full name" {
		t.Fatal("claim display without locale")
	}
	if mustAs[[]string](t, c["credential_signing_alg_values_supported"])[0] != "ES384" {
		t.Fatal("algs")
	}
}

func TestIssuerMetadata(t *testing.T) {
	opts := Options{BaseURL: "https://r/", CredentialIssuer: "https://issuer/", AuthorizationServers: []string{"https://as"}, Now: now}
	doc := IssuerMetadata([]record.Record{published()}, opts)
	if doc["credential_issuer"] != "https://issuer" || doc["credential_endpoint"] != "https://issuer/credential" {
		t.Fatalf("issuer %v", doc)
	}
	if mustAs[[]string](t, doc["authorization_servers"])[0] != "https://as" || doc["generated_at"] != "2024-01-31T10:00:00Z" {
		t.Fatal("servers or time")
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	doc = IssuerMetadata(nil, Options{BaseURL: "https://r", CredentialEndpoint: "https://dpg/credential"})
	if doc["credential_issuer"] != "https://r" || doc["credential_endpoint"] != "https://dpg/credential" {
		t.Fatal("defaults")
	}
	if _, has := doc["authorization_servers"]; has {
		t.Fatal("no servers")
	}
	if _, has := doc["generated_at"]; has {
		t.Fatal("no time")
	}
}

func TestPublicListAndSchemaDocument(t *testing.T) {
	opts := Options{BaseURL: "https://r", Now: now}
	r := published()
	doc := PublicList([]record.Record{r}, opts)
	list := mustAs[[]map[string]any](t, doc["schemas"])
	if len(list) != 1 || list[0]["url"] != "https://r/schemas/degree/2" || list[0]["published_at"] != "2024-01-31T10:00:00Z" {
		t.Fatalf("list %v", list)
	}
	if mustAs[map[string]string](t, list[0]["configuration_ids"])[record.FormatDcSdJwt] != "dpg-id" || list[0]["vct"] == nil {
		t.Fatal("ids or vct")
	}
	if doc["issuer_metadata"] != "https://r"+IssuerMetadataPath {
		t.Fatal("issuer metadata link")
	}
	r.Formats = []string{record.FormatLdpVc}
	r.PublishedAt = time.Time{}
	e := PublicSchema(r, Options{})
	if _, has := e["vct"]; has {
		t.Fatal("no vct without sd-jwt")
	}
	if _, has := e["published_at"]; has {
		t.Fatal("no published_at")
	}
	s := SchemaDocument(r, opts)
	if s["$id"] != "https://r/schemas/degree/2" || s["title"] != "Degree" || !strings.Contains(mustAs[string](t, s["$schema"]), "2020-12") {
		t.Fatalf("schema document %v", s)
	}
	r.JSONSchema = `{"$schema": "x", "title": "Keep"}`
	s = SchemaDocument(r, opts)
	if s["$schema"] != "x" || s["title"] != "Keep" {
		t.Fatal("existing fields stay")
	}
}

func TestTypeMetadataAndFindVct(t *testing.T) {
	opts := Options{BaseURL: "https://r"}
	r := published()
	doc := TypeMetadata(r, opts)
	if doc["vct"] != "https://r/.well-known/vct/UniversityDegree" || doc["name"] != "Degree" || doc["description"] != "A degree" {
		t.Fatalf("type metadata %v", doc)
	}
	claims := mustAs[[]map[string]any](t, doc["claims"])
	if claims[0]["sd"] != "allowed" || claims[1]["sd"] != "never" {
		t.Fatal("sd flags")
	}
	texts := mustAs[[]map[string]any](t, claims[0]["display"])
	if texts[0]["label"] != "Full name" || texts[0]["description"] != "The legal name" || texts[0]["lang"] != "en" {
		t.Fatalf("claim display %v", texts)
	}
	rendering := mustAs[map[string]any](t, mustAs[map[string]any](t, mustAs[[]map[string]any](t, doc["display"])[0]["rendering"])["simple"])
	if rendering["background_color"] != "#fff" {
		t.Fatal("rendering")
	}
	r.Display = []record.Display{{Name: "Plain", Locale: "fr"}}
	doc = TypeMetadata(r, opts)
	if _, has := mustAs[[]map[string]any](t, doc["display"])[0]["rendering"]; has {
		t.Fatal("no rendering without colours")
	}
	r.Display = nil
	doc = TypeMetadata(r, opts)
	if mustAs[[]map[string]any](t, mustAs[[]map[string]any](t, doc["claims"])[0]["display"])[0]["label"] != "Full name" {
		t.Fatal("label without locale")
	}
	old := published()
	old.Version = 1
	found, ok := FindVct([]record.Record{old, published()}, "UniversityDegree", opts)
	if !ok || found.Version != 2 {
		t.Fatal("newest version")
	}
	if _, ok := FindVct([]record.Record{old}, "https://r/.well-known/vct/UniversityDegree", opts); !ok {
		t.Fatal("full vct")
	}
	if _, ok := FindVct(nil, "x", opts); ok {
		t.Fatal("missing")
	}
}

// mapped returns the published record with two context extensions and
// a mapping of the name claim.
func mapped() record.Record {
	r := published()
	r.Contexts = []string{"https://w3id.org/citizenship/v1", "https://schema.org/"}
	r.ClaimMappings = []record.ClaimMapping{{
		Claim: "name", IRI: "https://schema.org/name",
		Labels: []record.ClaimLabel{{Locale: "en", Label: "Name", Description: "The name on the card"}, {Locale: "sw", Label: "Jina"}},
	}}
	return r
}

// TestLdpConfigurationCarriesContexts checks that an ldp_vc
// configuration carries the VCDM 2.0 context, then each context
// extension in order, then the term IRIs of the mapping, and that the
// other formats carry no context.
func TestLdpConfigurationCarriesContexts(t *testing.T) {
	cfg := Configuration(mapped(), record.FormatLdpVc, Options{BaseURL: "https://r"})
	def := mustAs[map[string]any](t, cfg["credential_definition"])
	ctx := mustAs[[]any](t, def["@context"])
	if len(ctx) != 4 || ctx[0] != VCDMContext || ctx[1] != "https://w3id.org/citizenship/v1" || ctx[2] != "https://schema.org/" {
		t.Fatalf("context %v", ctx)
	}
	terms := mustAs[map[string]any](t, ctx[3])
	if terms["name"] != "https://schema.org/name" || len(terms) != 1 {
		t.Fatalf("terms %v", terms)
	}
	// Without a mapped IRI the context holds the IRIs only.
	plain := mapped()
	plain.ClaimMappings[0].IRI = ""
	ctx = mustAs[[]any](t, mustAs[map[string]any](t, Configuration(plain, record.FormatLdpVc, Options{})["credential_definition"])["@context"])
	if len(ctx) != 3 {
		t.Fatalf("context without terms %v", ctx)
	}
	jwt := mustAs[map[string]any](t, Configuration(mapped(), record.FormatJwtVcJSON, Options{})["credential_definition"])
	if _, ok := jwt["@context"]; ok {
		t.Fatal("a jwt_vc_json configuration carries a context")
	}
	// The issuer metadata shows the mapped labels of a claim.
	claims := mustAs[[]map[string]any](t, cfg["claims"])
	labels := mustAs[[]map[string]any](t, claims[0]["display"])
	if len(labels) != 2 || labels[0]["name"] != "Name" || labels[1]["locale"] != "sw" || labels[1]["name"] != "Jina" {
		t.Fatalf("claim display %v", labels)
	}
}

// TestVctCarriesClaimMapping checks that the vct document shows the
// labels of the mapping, and the title of the property without one.
func TestVctCarriesClaimMapping(t *testing.T) {
	doc := TypeMetadata(mapped(), Options{BaseURL: "https://r"})
	claims := mustAs[[]map[string]any](t, doc["claims"])
	name := mustAs[[]map[string]any](t, claims[0]["display"])
	if len(name) != 2 || name[0]["label"] != "Name" || name[0]["description"] != "The name on the card" || name[1]["lang"] != "sw" || name[1]["label"] != "Jina" {
		t.Fatalf("name display %v", name)
	}
	if _, ok := name[1]["description"]; ok {
		t.Fatal("an empty description shows")
	}
	age := mustAs[[]map[string]any](t, claims[1]["display"])
	if age[0]["label"] != "age" {
		t.Fatalf("age display %v", age)
	}
}

// TestMappingValidatesIRIs checks every rule of a mapping: each context
// is an absolute http or https IRI with a host, named once; each term
// IRI is absolute; each mapped claim is a property of the document and
// named once; each label has a locale and a text, one per locale.
func TestMappingValidatesIRIs(t *testing.T) {
	if got := CheckMapping(mapped()); len(got) != 0 {
		t.Fatalf("a good mapping: %v", got)
	}
	for _, iri := range []string{"https://schema.org/name", "urn:example:term", "https://example.org/terms#given-name", "https://例え.jp/語"} {
		if err := CheckIRI(iri); err != nil {
			t.Errorf("CheckIRI(%q): %v", iri, err)
		}
	}
	for _, iri := range []string{"", "name", "/terms/name", "#name", "https://exa mple.org/", "https://example.org/<x>", "https://example.org/{x}", "1ab:c", strings.Repeat("a", MaxIRILength) + ":x"} {
		if CheckIRI(iri) == nil {
			t.Errorf("CheckIRI(%q) took a bad IRI", iri)
		}
	}
	for _, iri := range []string{"urn:example:ctx", "ftp://example.org/ctx", "https:///ctx", "https://example.org/ctx#frag x"} {
		if CheckContext(iri) == nil {
			t.Errorf("CheckContext(%q) took a bad context", iri)
		}
	}
	cases := []struct {
		name  string
		edit  func(*record.Record)
		field string
	}{
		{"relative context", func(r *record.Record) { r.Contexts = []string{"citizenship/v1"} }, "contexts"},
		{"twice", func(r *record.Record) { r.Contexts = []string{"https://schema.org/", "https://schema.org/"} }, "contexts"},
		{"base context", func(r *record.Record) { r.Contexts = []string{VCDMContext} }, "contexts"},
		{"bad term", func(r *record.Record) { r.ClaimMappings[0].IRI = "given name" }, "claim.name.iri"},
		{"no property", func(r *record.Record) { r.ClaimMappings[0].Claim = "ghost" }, "claim.ghost"},
		{"claim twice", func(r *record.Record) { r.ClaimMappings = append(r.ClaimMappings, r.ClaimMappings[0]) }, "claim.name"},
		{"no locale", func(r *record.Record) { r.ClaimMappings[0].Labels[1].Locale = "" }, "claim.name.labels"},
		{"no label", func(r *record.Record) { r.ClaimMappings[0].Labels[0].Label = " " }, "claim.name.labels"},
		{"locale twice", func(r *record.Record) { r.ClaimMappings[0].Labels[1].Locale = "en" }, "claim.name.labels"},
	}
	for _, c := range cases {
		r := mapped()
		c.edit(&r)
		got := CheckMapping(r)
		if len(got) != 1 || got[0].Field != c.field || got[0].Text == "" {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	if got := CheckMapping(record.Record{JSONSchema: "{", ClaimMappings: []record.ClaimMapping{{Claim: "x"}}}); len(got) != 1 {
		t.Fatalf("a broken document: %v", got)
	}
}
