// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
)

// mdlSchema is the JSON Schema of the mDL test configuration.
const mdlSchema = `{"type":"object","properties":{"family_name":{"type":"string","title":"Family name"},` +
	`"given_name":{"type":"string"},"document_number":{"type":"string"}},"required":["family_name"]}`

// TestFormatsListed lists the three formats the configuration API of
// Certify 0.14.0 takes, and refuses the JWT VC format with a reason.
func TestFormatsListed(t *testing.T) {
	svc, _ := newService(t, roles{certify: true})
	caps, err := svc.GetCapabilities(context.Background(), connect.NewRequest(&backendv1.GetCapabilitiesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	want := []commonv1.Format{commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_MSO_MDOC}
	if !slices.Equal(caps.Msg.GetFormats(), want) {
		t.Fatalf("formats %v", caps.Msg.GetFormats())
	}
	_, err = register(svc, &backendv1.CredentialConfiguration{
		Id: "Degree_jwt", Format: commonv1.Format_FORMAT_JWT_VC_JSON, Type: "Degree", JsonSchema: degreeSchema,
	})
	wantCode(t, err, connect.CodeInvalidArgument)
	if !strings.Contains(err.Error(), "0.14.0") {
		t.Errorf("the refusal does not name the release: %v", err)
	}
}

// TestIssueMdocConfiguration registers an mDL configuration and issues
// one credential of it through the pre-authorized flow. The credential
// is the base64url IssuerSigned structure Certify returns.
func TestIssueMdocConfiguration(t *testing.T) {
	svc, f := newService(t, both)
	id, err := register(svc, &backendv1.CredentialConfiguration{
		Id: "Mdl_mso_mdoc", Format: commonv1.Format_FORMAT_MSO_MDOC, Type: "org.iso.18013.5.1.mDL",
		JsonSchema: mdlSchema, Display: `[{"name":"Driving licence","locale":"en"}]`,
	})
	if err != nil || id != "Mdl_mso_mdoc" {
		t.Fatalf("register: %q %v", id, err)
	}
	entry := stored(t, f, "Mdl_mso_mdoc")
	if entry.DocType != "org.iso.18013.5.1.mDL" || entry.SignatureCryptoSuite != "ES256" || entry.KeyManagerAppID != "CERTIFY_VC_SIGN_EC_R1" {
		t.Fatalf("entry %+v", entry)
	}
	claims := entry.MsoMdocClaims["org.iso.18013.5.1"]
	if claims == nil || claims["family_name"].Display[0].Name != "Family name" {
		t.Fatalf("mdoc claims %+v", entry.MsoMdocClaims)
	}
	tmpl, err := inji.DecodeTemplate(entry.VcTemplate)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"docType": "org.iso.18013.5.1.mDL"`, `"org.iso.18013.5.1": [`, `"elementIdentifier": "family_name"`,
		`"elementValue": "${family_name}"`, `"validFrom": "${_validFrom}"`} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("the template lacks %s:\n%s", want, tmpl)
		}
	}
	types, err := svc.ListCredentialTypes(context.Background(), connect.NewRequest(&backendv1.ListCredentialTypesRequest{
		Page: &commonv1.Pagination{PageToken: "2"},
	}))
	if err != nil || len(types.Msg.GetConfigurations()) != 1 {
		t.Fatalf("catalogue: %v %v", types, err)
	}
	if c := types.Msg.GetConfigurations()[0]; c.GetFormat() != commonv1.Format_FORMAT_MSO_MDOC || c.GetType() != "org.iso.18013.5.1.mDL" {
		t.Fatalf("the catalogue entry %v", c)
	}
	issued, err := svc.Issue(context.Background(), connect.NewRequest(&backendv1.IssueRequest{Spec: &backendv1.IssueSpec{
		ConfigurationId: "Mdl_mso_mdoc", SubjectData: `{"family_name":"Njeri","given_name":"Wanjiku","document_number":"DL-0042"}`,
	}}))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	cred := issued.Msg.GetCredential()
	raw, err := base64.RawURLEncoding.DecodeString(string(cred.GetPayload()))
	if cred.GetFormat() != commonv1.Format_FORMAT_MSO_MDOC || err != nil || len(raw) == 0 || raw[0] != 0xa2 {
		t.Fatalf("credential %v: %v", cred.GetFormat(), err)
	}
	var sent struct {
		Format  string `json:"format"`
		Doctype string `json:"doctype"`
	}
	if err := f.RequestJSON("/v1/certify/issuance/credential", &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Format != "mso_mdoc" || sent.Doctype != "org.iso.18013.5.1.mDL" {
		t.Fatalf("the credential request %+v", sent)
	}
	var staged struct {
		Claims map[string]any `json:"claims"`
	}
	if err := f.RequestJSON("/v1/certify/pre-authorized-data", &staged); err != nil {
		t.Fatal(err)
	}
	if _, ok := staged.Claims[inji.StatusIndexClaim]; ok {
		t.Error("an mDoc staging call carries a status marker its template never reads")
	}
}

// TestRenderTemplatesFromTheStack names the SVG template of the stack in
// a configuration the adapter registers, and returns the template with
// each configuration whose credential names it.
func TestRenderTemplatesFromTheStack(t *testing.T) {
	svc, _ := newServiceWith(t, both, func(o *serviceOptions) { o.RenderingTemplateID = "farmer-card" })
	if _, err := register(svc, &backendv1.CredentialConfiguration{
		Id: "Degree_ldp_vc", Format: commonv1.Format_FORMAT_LDP_VC, Type: "UniversityDegree",
		JsonSchema: degreeSchema, Display: `[{"name":"University degree","locale":"en"}]`,
	}); err != nil {
		t.Fatal(err)
	}
	meta, err := svc.GetIssuerMetadata(context.Background(), connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range meta.Msg.GetConfigurations() {
		switch c.GetId() {
		case "Degree_ldp_vc":
			found = true
			if len(c.GetRenderTemplates()) != 1 {
				t.Fatalf("render templates %v", c.GetRenderTemplates())
			}
			r := c.GetRenderTemplates()[0]
			if r.GetMediaType() != "image/svg+xml" || !strings.Contains(r.GetContent(), "<svg") ||
				r.GetUrl() != "https://inji-certify.example.org/v1/certify/rendering-template/farmer-card" || r.GetName() != "University degree" {
				t.Fatalf("render template %v", r)
			}
		default:
			if len(c.GetRenderTemplates()) != 0 {
				t.Errorf("%s names no template but carries %v", c.GetId(), c.GetRenderTemplates())
			}
		}
	}
	if !found {
		t.Fatal("the registered configuration is missing")
	}

	// Without the template id the registered template names none.
	plain, f := newService(t, both)
	if _, perr := register(plain, &backendv1.CredentialConfiguration{
		Id: "Degree_ldp_vc", Format: commonv1.Format_FORMAT_LDP_VC, Type: "UniversityDegree", JsonSchema: degreeSchema,
	}); perr != nil {
		t.Fatal(perr)
	}
	tmpl, err := inji.DecodeTemplate(stored(t, f, "Degree_ldp_vc").VcTemplate)
	if err != nil || strings.Contains(tmpl, "renderMethod") {
		t.Fatalf("a template without the id names a render method: %v", err)
	}
}

// TestRenderTemplateMissingOnTheStack leaves the render template out
// when the stack does not serve it, and still answers.
func TestRenderTemplateMissingOnTheStack(t *testing.T) {
	svc, _ := newServiceWith(t, both, func(o *serviceOptions) { o.RenderingTemplateID = "gone" })
	if _, err := register(svc, &backendv1.CredentialConfiguration{
		Id: "Degree_ldp_vc", Format: commonv1.Format_FORMAT_LDP_VC, Type: "UniversityDegree", JsonSchema: degreeSchema,
	}); err != nil {
		t.Fatal(err)
	}
	meta, err := svc.GetIssuerMetadata(context.Background(), connect.NewRequest(&backendv1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range meta.Msg.GetConfigurations() {
		if len(c.GetRenderTemplates()) != 0 {
			t.Fatalf("%s carries a template the stack does not serve", c.GetId())
		}
	}
}
