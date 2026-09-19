// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"testing"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
)

const metadata = `{
  "credential_issuer": "https://issuer.example",
  "display": [{"name": "Ministry of Example", "locale": "en"}],
  "credential_configurations_supported": {
    "pid_sd_jwt": {"format": "dc+sd-jwt", "vct": "https://issuer.example/pid",
      "display": [{"name": "Person ID", "locale": "en"}]},
    "degree_jwt": {"format": "jwt_vc_json",
      "credential_definition": {"type": ["VerifiableCredential", "DegreeCredential"]}},
    "mdl": {"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL"},
    "scoped": {"format": "ldp_vc", "scope": "ScopedCredential"},
    "bare": {"format": "ldp_vc"},
    "no_format": {"vct": "https://issuer.example/x"},
    "broken": 7
  }
}`

func TestReadMetadata(t *testing.T) {
	issuer, display, types, err := catalog.ReadMetadata([]byte(metadata))
	if err != nil {
		t.Fatal(err)
	}
	if issuer != "https://issuer.example" {
		t.Errorf("issuer = %q", issuer)
	}
	if len(display) != 1 || display[0].Name != "Ministry of Example" {
		t.Errorf("display = %v", display)
	}
	if len(types) != 5 {
		t.Fatalf("types = %d: %+v", len(types), types)
	}
	byID := map[string]catalog.CredentialType{}
	for _, item := range types {
		byID[item.ConfigurationID] = item
	}
	if byID["pid_sd_jwt"].Type != "https://issuer.example/pid" {
		t.Errorf("vct = %q", byID["pid_sd_jwt"].Type)
	}
	if byID["degree_jwt"].Type != "DegreeCredential" {
		t.Errorf("W3C type = %q", byID["degree_jwt"].Type)
	}
	if byID["mdl"].Type != "org.iso.18013.5.1.mDL" {
		t.Errorf("doctype = %q", byID["mdl"].Type)
	}
	if byID["scoped"].Type != "ScopedCredential" {
		t.Errorf("scope = %q", byID["scoped"].Type)
	}
	if byID["bare"].Type != "bare" {
		t.Errorf("the configuration id stands in, got %q", byID["bare"].Type)
	}
	if _, ok := byID["no_format"]; ok {
		t.Error("a configuration without a format is not a type")
	}
}

func TestReadMetadataLegacyMember(t *testing.T) {
	_, _, types, err := catalog.ReadMetadata([]byte(`{"credentials_supported":{"a":{"format":"ldp_vc","vct":"A"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(types) != 1 || types[0].Type != "A" {
		t.Errorf("types = %+v", types)
	}
	if _, _, _, err := catalog.ReadMetadata([]byte("{")); err == nil {
		t.Error("broken JSON wants an error")
	}
}

const schemas = `{"schemas": [
  {"id": "pid", "version": 2, "vct": "https://issuer.example/pid", "formats": ["dc+sd-jwt"],
   "display": [{"name": "Person ID"}],
   "json_schema": {"type": "object", "required": ["given_name"], "properties": {
     "given_name": {"type": "string", "title": "Given name"},
     "birth_date": {"type": "string", "format": "date"},
     "address": {"type": "object", "properties": {"street": {"type": "string"}}}
   }}},
  {"id": "extra", "type": "ExtraCredential", "version": 1},
  {"id": "unnamed", "version": 1}
]}`

func TestReadSchemas(t *testing.T) {
	out, err := catalog.ReadSchemas([]byte(schemas))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("schemas = %d", len(out))
	}
	pid := out["https://issuer.example/pid"]
	if pid.SchemaID != "pid" || pid.SchemaVersion != 2 || pid.Format != "dc+sd-jwt" {
		t.Errorf("pid = %+v", pid)
	}
	if len(pid.Fields) != 3 {
		t.Fatalf("fields = %+v", pid.Fields)
	}
	if pid.Fields[0].Path != "address.street" {
		t.Errorf("the reader writes a dotted path, got %q", pid.Fields[0].Path)
	}
	if !pid.Fields[2].Mandatory || !pid.Fields[2].SelectivelyDisclosable {
		t.Errorf("given_name = %+v", pid.Fields[2])
	}
	if pid.Fields[1].Format != "date" {
		t.Errorf("birth_date = %+v", pid.Fields[1])
	}
}

func TestReadSchemasBareArray(t *testing.T) {
	out, err := catalog.ReadSchemas([]byte(`[{"id":"a","type":"A"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Errorf("schemas = %v", out)
	}
	if _, err := catalog.ReadSchemas([]byte("not json")); err == nil {
		t.Error("broken JSON wants an error")
	}
}

func TestReadFields(t *testing.T) {
	if got := catalog.ReadFields([]byte("not json"), ""); got != nil {
		t.Errorf("broken JSON gives no field, got %v", got)
	}
	wrapped := `{"type":"object","properties":{"credentialSubject":{"type":"object","properties":{"name":{"type":"string"}}}}}`
	got := catalog.ReadFields([]byte(wrapped), "jwt_vc_json")
	if len(got) != 1 || got[0].Path != "name" {
		t.Errorf("the reader looks inside credentialSubject, got %+v", got)
	}
	if got[0].SelectivelyDisclosable {
		t.Error("a JWT VC discloses every claim together")
	}
	deep := `{"type":"object","properties":{"a":{"type":"object","properties":{"b":{"type":"object","properties":{"c":{"type":"object","properties":{"d":{"type":"object","properties":{"e":{"type":"object","properties":{"f":{"type":"object","properties":{"g":{"type":"string"}}}}}}}}}}}}}}`
	if got := catalog.ReadFields([]byte(deep), ""); len(got) != 0 {
		t.Errorf("the reader stops at the depth limit, got %+v", got)
	}
}

func TestMerge(t *testing.T) {
	types := []catalog.CredentialType{
		{Type: "A", ConfigurationID: "a", Format: "dc+sd-jwt"},
		{Type: "B", ConfigurationID: "b", Format: "ldp_vc", SchemaID: "kept", Display: []catalog.Display{{Name: "B"}}},
	}
	schemas := map[string]catalog.CredentialType{
		"A": {Type: "A", SchemaID: "a-schema", SchemaVersion: 3, JSONSchema: "{}", Fields: []catalog.Field{{Path: "x"}}, Display: []catalog.Display{{Name: "A"}}},
		"B": {Type: "B", SchemaID: "other", SchemaVersion: 9},
		"C": {Type: "C", SchemaID: "c"},
	}
	out := catalog.Merge(types, schemas)
	if len(out) != 3 {
		t.Fatalf("merged = %+v", out)
	}
	if out[0].SchemaID != "a-schema" || len(out[0].Fields) != 1 || out[0].Display[0].Name != "A" {
		t.Errorf("A = %+v", out[0])
	}
	if out[1].SchemaID != "kept" || out[1].Display[0].Name != "B" {
		t.Errorf("the metadata wins over the schema list, got %+v", out[1])
	}
	if out[2].Type != "C" {
		t.Errorf("a schema without metadata joins the list, got %+v", out[2])
	}
}

func TestTrustNames(t *testing.T) {
	cases := []struct {
		outcome trustv1.TrustLookupResponse_Outcome
		name    string
	}{
		{trustv1.TrustLookupResponse_OUTCOME_TRUSTED, catalog.TrustTrusted},
		{trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED, catalog.TrustUntrusted},
		{trustv1.TrustLookupResponse_OUTCOME_UNKNOWN, catalog.TrustUnknown},
		{trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE, catalog.TrustUnavailable},
		{trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED, catalog.TrustUnspecified},
	}
	for _, c := range cases {
		if got := catalog.TrustName(c.outcome); got != c.name {
			t.Errorf("TrustName(%v) = %q", c.outcome, got)
		}
		if got := catalog.TrustOutcome(c.name); got != c.outcome {
			t.Errorf("TrustOutcome(%q) = %v", c.name, got)
		}
	}
	if catalog.TrustOutcome("nonsense") != trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED {
		t.Error("an unknown name is unspecified")
	}
}

func TestFormatNames(t *testing.T) {
	for _, name := range []string{"vc+sd-jwt", "dc+sd-jwt", "jwt_vc_json", "ldp_vc", "mso_mdoc"} {
		f := catalog.FormatOf(name)
		if f == commonv1.Format_FORMAT_UNSPECIFIED {
			t.Fatalf("FormatOf(%q) is unspecified", name)
		}
		if got := catalog.FormatName(f); got != name {
			t.Errorf("FormatName round trip = %q, want %q", got, name)
		}
	}
	if catalog.FormatOf("bogus") != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Error("an unknown format is unspecified")
	}
	if catalog.FormatName(commonv1.Format_FORMAT_UNSPECIFIED) != "" {
		t.Error("the unspecified format has no name")
	}
}

func TestRecordHelpers(t *testing.T) {
	i := catalog.Issuer{CredentialIssuer: "https://issuer.example", Types: []catalog.CredentialType{{Type: "A"}}}
	if i.Name() != "https://issuer.example" {
		t.Errorf("Name = %q", i.Name())
	}
	i.DisplayName = "Ministry"
	if i.Name() != "Ministry" {
		t.Errorf("Name = %q", i.Name())
	}
	if _, ok := i.Find("A"); !ok {
		t.Error("Find must see type A")
	}
	if _, ok := i.Find("B"); ok {
		t.Error("Find must not see type B")
	}
	i.CrawledAt = time.Unix(1700000000, 0).UTC()
	i.Trust = catalog.TrustTrusted
	m := i.ToProto()
	if m.GetTypeCount() != 1 || m.GetCrawledAt() == nil || m.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED {
		t.Errorf("proto = %+v", m)
	}
	if (catalog.Issuer{}).ToProto().GetCrawledAt() != nil {
		t.Error("an issuer without a crawl time writes no timestamp")
	}
	item := catalog.CredentialType{Type: "A", Format: "ldp_vc", Display: []catalog.Display{{Name: "Alpha"}}}
	if item.Name() != "Alpha" {
		t.Errorf("Name = %q", item.Name())
	}
	if (catalog.CredentialType{Type: "A"}).Name() != "A" {
		t.Error("a type without display uses its type name")
	}
	if p := item.ToProto("https://issuer.example"); len(p.GetDisplay()) != 1 {
		t.Errorf("proto = %+v", p)
	}
	f := catalog.Field{Path: "a", Type: "string", Mandatory: true}
	if p := f.ToProto(); p.GetPath() != "a" || !p.GetMandatory() {
		t.Errorf("field proto = %+v", p)
	}
}

func TestURLFor(t *testing.T) {
	if got := catalog.URLFor("https://issuer.example/", catalog.MetadataPath); got != "https://issuer.example"+catalog.MetadataPath {
		t.Errorf("URLFor = %q", got)
	}
}
