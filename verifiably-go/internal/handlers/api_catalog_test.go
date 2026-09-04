package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// catalogAdapter is a per-test fake for APICatalog: canned DPGs, schemas and
// OID4VP templates, each with an injectable error.
type catalogAdapter struct {
	backend.Adapter
	issuer, verifier       map[string]vctypes.DPG
	issuerErr, verifierErr error
	schemas                []vctypes.Schema
	schemasErr             error
	tpls                   map[string]vctypes.OID4VPTemplate
	tplsErr                error
}

func (c *catalogAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return c.issuer, c.issuerErr
}
func (c *catalogAdapter) ListVerifierDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return c.verifier, c.verifierErr
}
func (c *catalogAdapter) ListAllSchemas(context.Context) ([]vctypes.Schema, error) {
	return c.schemas, c.schemasErr
}
func (c *catalogAdapter) ListOID4VPTemplates(context.Context) (map[string]vctypes.OID4VPTemplate, error) {
	return c.tpls, c.tplsErr
}

func catalogGET(auth string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/catalog", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return req
}

func TestAPICatalog_Unauthenticated(t *testing.T) {
	h := apiTestH(&catalogAdapter{})
	rr := httptest.NewRecorder()
	h.APICatalog(rr, catalogGET(""))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 must carry WWW-Authenticate")
	}
}

func TestAPICatalog_FullResponse(t *testing.T) {
	ad := &catalogAdapter{
		issuer: map[string]vctypes.DPG{
			"zeta": {Version: "2", Tag: "API", Tagline: "later", Formats: []string{"jwt_vc_json"}, FlowPreAuth: true, FlowAuthCode: true, DirectPDF: true,
				Capabilities: []vctypes.Capability{{Kind: "bulk_source", Key: "csv", Title: "CSV", Body: "rows"}}},
			"alpha": {Version: "1"},
		},
		verifier: map[string]vctypes.DPG{"ver": {Tag: "verifier"}},
		schemas: []vctypes.Schema{
			{ID: "s1", Std: "w3c_vcdm_2"}, {ID: "s2", Std: "sd_jwt_vc (IETF)"}, {ID: "s3", Std: "w3c_vcdm_2"}, {ID: "s4"},
		},
		tpls: map[string]vctypes.OID4VPTemplate{
			"age":  {Title: "Age", Fields: []string{"dob"}, Format: "w3c_vcdm_2", Disclosure: "dob only"},
			"bare": {Title: "Bare"}, // nil Fields must serialize as []
		},
	}
	h := apiTestH(ad)
	rr := httptest.NewRecorder()
	h.APICatalog(rr, catalogGET("Bearer secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	got := decodeJSON(t, rr.Body.Bytes())

	issuers := got["issuer_dpgs"].([]any)
	if len(issuers) != 2 || issuers[0].(map[string]any)["id"] != "alpha" || issuers[1].(map[string]any)["id"] != "zeta" {
		t.Fatalf("issuer_dpgs not sorted by id: %v", issuers)
	}
	zeta := issuers[1].(map[string]any)
	if zeta["version"] != "2" || zeta["tag"] != "API" || zeta["tagline"] != "later" || zeta["supports_pdf"] != true {
		t.Errorf("zeta fields wrong: %v", zeta)
	}
	if flows := zeta["flows"]; !reflect.DeepEqual(flows, []any{"pre_auth", "auth_code"}) {
		t.Errorf("flows = %v, want [pre_auth auth_code]", flows)
	}
	if fm := zeta["formats"]; !reflect.DeepEqual(fm, []any{"jwt_vc_json"}) {
		t.Errorf("formats = %v", fm)
	}
	caps := zeta["capabilities"].([]any)
	if len(caps) != 1 || caps[0].(map[string]any)["key"] != "csv" || caps[0].(map[string]any)["body"] != "rows" {
		t.Errorf("capabilities = %v", caps)
	}
	alpha := issuers[0].(map[string]any)
	if _, has := alpha["flows"]; has {
		t.Errorf("alpha declares no flows; flows must be omitted, got %v", alpha["flows"])
	}
	if _, has := alpha["supports_pdf"]; has {
		t.Errorf("alpha supports_pdf must be omitted when false")
	}
	if v := got["verifier_dpgs"].([]any); len(v) != 1 || v[0].(map[string]any)["id"] != "ver" || v[0].(map[string]any)["tag"] != "verifier" {
		t.Errorf("verifier_dpgs = %v", v)
	}
	if std := got["credential_standards"]; !reflect.DeepEqual(std, []any{"sd_jwt_vc (IETF)", "w3c_vcdm_2"}) {
		t.Errorf("credential_standards = %v, want deduped+sorted", std)
	}
	tpls := got["verification_templates"].(map[string]any)
	age := tpls["age"].(map[string]any)
	if age["title"] != "Age" || age["format"] != "w3c_vcdm_2" || age["disclosure"] != "dob only" || !reflect.DeepEqual(age["fields"], []any{"dob"}) {
		t.Errorf("age template = %v", age)
	}
	if bare := tpls["bare"].(map[string]any); !reflect.DeepEqual(bare["fields"], []any{}) {
		t.Errorf("nil Fields must serialize as [], got %v", bare["fields"])
	}
}

func TestAPICatalog_SubQueryErrorsDegradeToEmpty(t *testing.T) {
	ad := &catalogAdapter{
		issuerErr: errors.New("down"), verifierErr: errors.New("down"),
		schemasErr: errors.New("down"), tplsErr: errors.New("down"),
	}
	h := apiTestH(ad)
	rr := httptest.NewRecorder()
	h.APICatalog(rr, catalogGET("Bearer secret"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even when sub-queries fail", rr.Code)
	}
	got := decodeJSON(t, rr.Body.Bytes())
	if len(got["issuer_dpgs"].([]any)) != 0 || len(got["verifier_dpgs"].([]any)) != 0 {
		t.Errorf("dpgs must be empty on error: %v", got)
	}
	if len(got["credential_standards"].([]any)) != 0 {
		t.Errorf("credential_standards must be empty on error: %v", got["credential_standards"])
	}
	if len(got["verification_templates"].(map[string]any)) != 0 {
		t.Errorf("verification_templates must be empty on error: %v", got["verification_templates"])
	}
}

func TestDpgToAPIInfo_NilFormatsBecomeEmptySlice(t *testing.T) {
	info := dpgToAPIInfo("x", vctypes.DPG{FlowAuthCode: true})
	if info.ID != "x" || info.Formats == nil || len(info.Formats) != 0 {
		t.Errorf("Formats must be non-nil empty: %+v", info)
	}
	if !reflect.DeepEqual(info.Flows, []string{"auth_code"}) {
		t.Errorf("Flows = %v", info.Flows)
	}
	if len(info.Capabilities) != 0 {
		t.Errorf("Capabilities = %v", info.Capabilities)
	}
	if got := sortedDPGInfos(nil); len(got) != 0 {
		t.Errorf("sortedDPGInfos(nil) = %v, want empty", got)
	}
}
