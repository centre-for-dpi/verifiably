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
	if mustAs[[]string](t, ldp["@context"])[0] != VCDMContext {
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
