// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
)

// degreeSchema is the JSON Schema of the test configuration.
const degreeSchema = `{"type":"object","properties":{` +
	`"name":{"type":"string","title":"Full name"},"credits":{"type":"integer"}},"required":["name"]}`

// register calls RegisterCredentialConfiguration with one configuration.
func register(svc interface {
	RegisterCredentialConfiguration(context.Context, *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (
		*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error)
}, cfg *backendv1.CredentialConfiguration,
) (string, error) {
	resp, err := svc.RegisterCredentialConfiguration(context.Background(),
		connect.NewRequest(&backendv1.RegisterCredentialConfigurationRequest{Configuration: cfg}))
	if err != nil {
		return "", err
	}
	return resp.Msg.GetId(), nil
}

// stored reads the entry the fake holds for id.
func stored(t *testing.T, f *fake.Server, id string) inji.ConfigurationDTO {
	t.Helper()
	raw, ok := f.Configuration(id)
	if !ok {
		t.Fatalf("the stack holds no entry %s", id)
	}
	var out inji.ConfigurationDTO
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRegisterCreatesConfiguration registers a new JSON-LD and a new
// SD-JWT configuration through the configuration API of the stack. The
// entries carry a template with every claim, the signing key names of
// the stack, and the markers the staging call passes. The issuer
// metadata lists them at once.
func TestRegisterCreatesConfiguration(t *testing.T) {
	svc, f := newService(t, both)
	id, err := register(svc, &backendv1.CredentialConfiguration{
		Id: "Degree_ldp_vc", Format: commonv1.Format_FORMAT_LDP_VC, Type: "UniversityDegree",
		JsonSchema: degreeSchema, Display: `[{"name":"University degree","locale":"en","logo":{"uri":"https://u.example/logo.png"}}]`,
		Contexts: []string{"https://u.example/contexts/degree.jsonld"},
	})
	if err != nil || id != "Degree_ldp_vc" {
		t.Fatalf("register: %q %v", id, err)
	}
	if got := f.Request("/v1/certify/credential-configurations"); len(got) == 0 {
		t.Fatal("the adapter did not call the create endpoint")
	}
	ldp := stored(t, f, "Degree_ldp_vc")
	wantContexts := []string{inji.VCDMContext, "https://u.example/contexts/degree.jsonld", inji.Ed25519Context}
	if !slices.Equal(ldp.ContextURLs, wantContexts) || !slices.Equal(ldp.CredentialTypes, []string{"VerifiableCredential", "UniversityDegree"}) {
		t.Fatalf("contexts %v, types %v", ldp.ContextURLs, ldp.CredentialTypes)
	}
	if ldp.KeyManagerAppID != "CERTIFY_VC_SIGN_ED25519" || ldp.SignatureCryptoSuite != "Ed25519Signature2020" || ldp.Scope != id {
		t.Fatalf("signing %+v", ldp)
	}
	if len(ldp.MetaDataDisplay) != 1 || ldp.MetaDataDisplay[0].Logo == nil || ldp.MetaDataDisplay[0].Logo.URL != "https://u.example/logo.png" {
		t.Fatalf("display %+v", ldp.MetaDataDisplay)
	}
	for _, name := range []string{"name", "credits", inji.StatusIndexClaim, inji.StatusURIClaim, inji.ValidFromClaim} {
		if _, ok := ldp.CredentialSubjectDefinition[name]; !ok {
			t.Errorf("the entry does not declare %s", name)
		}
	}
	if got := ldp.CredentialSubjectDefinition["name"].Display[0].Name; got != "Full name" {
		t.Errorf("claim label %q", got)
	}
	tmpl, err := inji.DecodeTemplate(ldp.VcTemplate)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"name": "${name}"`, `"credits": ${credits}`, `"issuer": "${_issuer}"`, "BitstringStatusListEntry", "#if($statusUri"} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("the template lacks %s:\n%s", want, tmpl)
		}
	}

	if _, rerr := register(svc, &backendv1.CredentialConfiguration{
		Id: "Degree_vc+sd-jwt", Format: commonv1.Format_FORMAT_VC_SD_JWT, Type: "https://u.example/vct/degree",
		JsonSchema: degreeSchema, SdClaims: []string{"name"},
	}); rerr != nil {
		t.Fatalf("register SD-JWT: %v", rerr)
	}
	sd := stored(t, f, "Degree_vc+sd-jwt")
	if sd.SdJwtVct != "https://u.example/vct/degree" || sd.SignatureAlgo != "ES256" || sd.SdClaim != "name" {
		t.Fatalf("SD-JWT entry %+v", sd)
	}
	if _, ok := sd.SdJwtClaims[inji.ValidFromClaim]; ok {
		t.Error("the SD-JWT entry declares a validity marker its template never reads")
	}
	if len(sd.MetaDataDisplay) != 1 || sd.MetaDataDisplay[0].Name != "https://u.example/vct/degree" {
		t.Errorf("an empty display gets the type name: %+v", sd.MetaDataDisplay)
	}

	meta, err := svc.ListCredentialTypes(context.Background(), connect.NewRequest(&backendv1.ListCredentialTypesRequest{
		Page: &commonv1.Pagination{PageSize: 50},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if meta.Msg.GetPage().GetTotalSize() != 4 {
		t.Fatalf("the catalogue holds %d entries, want the two recorded and the two new", meta.Msg.GetPage().GetTotalSize())
	}
}

// TestRegisterUpdatesExisting replaces an entry the stack already holds
// instead of creating a second one.
func TestRegisterUpdatesExisting(t *testing.T) {
	svc, f := newService(t, both)
	cfg := &backendv1.CredentialConfiguration{
		Id: fake.SeededConfiguration, Format: commonv1.Format_FORMAT_LDP_VC, Type: "FarmerCredential",
		JsonSchema: `{"type":"object","properties":{"fullName":{"type":"string"},"farmerID":{"type":"string"},"acres":{"type":"number"}}}`,
		Display:    `[{"name":"Farmer","locale":"en"}]`,
	}
	id, err := register(svc, cfg)
	if err != nil || id != fake.SeededConfiguration {
		t.Fatalf("register: %q %v", id, err)
	}
	if len(f.Request("/v1/certify/credential-configurations")) != 0 {
		t.Fatal("the adapter created a second entry for an id the stack holds")
	}
	got := stored(t, f, fake.SeededConfiguration)
	if _, ok := got.CredentialSubjectDefinition["acres"]; !ok || got.MetaDataDisplay[0].Name != "Farmer" {
		t.Fatalf("the entry was not replaced: %+v", got)
	}
	cfg.Display = `[{"name":"Farmer card","locale":"en"}]`
	if _, err := register(svc, cfg); err != nil {
		t.Fatal(err)
	}
	if got := stored(t, f, fake.SeededConfiguration); got.MetaDataDisplay[0].Name != "Farmer card" {
		t.Fatalf("the second update did not land: %+v", got.MetaDataDisplay)
	}
}

// TestRegisterRejectsWhatTheStackRefuses maps each refusal onto a code
// with a reason.
func TestRegisterRejectsWhatTheStackRefuses(t *testing.T) {
	svc, f := newService(t, both)
	cases := []struct {
		name string
		cfg  *backendv1.CredentialConfiguration
		code connect.Code
	}{
		{"no configuration", nil, connect.CodeInvalidArgument},
		{"no id", &backendv1.CredentialConfiguration{Format: commonv1.Format_FORMAT_LDP_VC, Type: "X", JsonSchema: degreeSchema}, connect.CodeInvalidArgument},
		{"no type", &backendv1.CredentialConfiguration{Id: "x", Format: commonv1.Format_FORMAT_LDP_VC, JsonSchema: degreeSchema}, connect.CodeInvalidArgument},
		{"dc+sd-jwt", &backendv1.CredentialConfiguration{Id: "x", Format: commonv1.Format_FORMAT_DC_SD_JWT, Type: "X", JsonSchema: degreeSchema}, connect.CodeInvalidArgument},
		{"bad schema", &backendv1.CredentialConfiguration{Id: "x", Format: commonv1.Format_FORMAT_LDP_VC, Type: "X", JsonSchema: "{"}, connect.CodeInvalidArgument},
		{"bad claim name", &backendv1.CredentialConfiguration{Id: "x", Format: commonv1.Format_FORMAT_LDP_VC, Type: "X",
			JsonSchema: `{"type":"object","properties":{"first name":{"type":"string"}}}`}, connect.CodeInvalidArgument},
		{"same type as the sample", &backendv1.CredentialConfiguration{Id: "Farmer2", Format: commonv1.Format_FORMAT_LDP_VC,
			Type: "FarmerCredential", JsonSchema: degreeSchema}, codeOK},
	}
	for _, c := range cases {
		_, err := register(svc, c.cfg)
		if c.code == codeOK {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		wantCode(t, err, c.code)
	}
	// A second entry with the same types and contexts fails the
	// duplicate check of the stack.
	_, err := register(svc, &backendv1.CredentialConfiguration{Id: "Farmer3", Format: commonv1.Format_FORMAT_LDP_VC,
		Type: "FarmerCredential", JsonSchema: degreeSchema})
	wantCode(t, err, connect.CodeAlreadyExists)
	if !strings.Contains(err.Error(), "ldp_vc_config_exists") {
		t.Errorf("the reason is lost: %v", err)
	}
	f.SetStatus("/v1/certify/credential-configurations/Degree", 503)
	_, err = register(svc, &backendv1.CredentialConfiguration{Id: "Degree", Format: commonv1.Format_FORMAT_LDP_VC,
		Type: "Degree", JsonSchema: degreeSchema})
	wantCode(t, err, connect.CodeUnavailable)

	verifier, _ := newService(t, roles{verify: true})
	_, err = register(verifier, &backendv1.CredentialConfiguration{Id: "x"})
	wantCode(t, err, connect.CodeUnimplemented)
}

// TestFeatureConfigApiListed lists FEATURE_CREDENTIAL_CONFIG_API when
// the adapter reaches Certify, and never for a verifier only adapter.
func TestFeatureConfigApiListed(t *testing.T) {
	for _, c := range []struct {
		r    roles
		want bool
	}{{both, true}, {roles{certify: true}, true}, {roles{verify: true}, false}} {
		svc, _ := newService(t, c.r)
		caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
		if err != nil {
			t.Fatal(err)
		}
		got := slices.Contains(caps.Msg.GetFeatures(), backendv1.Feature_FEATURE_CREDENTIAL_CONFIG_API)
		if got != c.want {
			t.Errorf("roles %+v: listed %v, want %v", c.r, got, c.want)
		}
	}
}

// codeOK marks a case that must succeed.
const codeOK connect.Code = 0
