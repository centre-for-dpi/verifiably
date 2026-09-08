package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/vctypes"
)

// schemasAPIAdapter records SaveCustomSchema / DeleteCustomSchema calls.
type schemasAPIAdapter struct {
	testAdapter
	saved     []vctypes.Schema
	saveErr   error
	deleted   []string
	deleteErr error
}

func (a *schemasAPIAdapter) SaveCustomSchema(_ context.Context, s vctypes.Schema) error {
	a.saved = append(a.saved, s)
	return a.saveErr
}
func (a *schemasAPIAdapter) DeleteCustomSchema(_ context.Context, id string) error {
	a.deleted = append(a.deleted, id)
	return a.deleteErr
}

func schemasAPIRawPOST(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/schemas", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	return req
}

func TestAPICreateSchema_Validation(t *testing.T) {
	ad := &schemasAPIAdapter{}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APICreateSchema(rr, httptest.NewRequest(http.MethodPost, "/api/v1/schemas", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: status %d, want 401", rr.Code)
	}

	cases := []struct {
		name, body, wantErr string
	}{
		{"invalid json", `{`, "invalid JSON"},
		{"name required", `{"name":"  ","fields":[{"name":"a"}]}`, "name required"},
		{"fields required", `{"name":"Person"}`, "fields required"},
		{"blank field names", `{"name":"Person","fields":[{"name":"  "}]}`, "at least one non-blank field name"},
	}
	for _, c := range cases {
		rr := httptest.NewRecorder()
		h.APICreateSchema(rr, schemasAPIRawPOST(c.body))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", c.name, rr.Code)
		}
		if got := decodeJSON(t, rr.Body.Bytes())["error"].(string); !strings.Contains(got, c.wantErr) {
			t.Errorf("%s: error %q, want contains %q", c.name, got, c.wantErr)
		}
	}
	if len(ad.saved) != 0 {
		t.Errorf("nothing should be saved on validation failure, got %d", len(ad.saved))
	}
}

func TestAPICreateSchema_DefaultsAndSave(t *testing.T) {
	ad := &schemasAPIAdapter{}
	h := apiTestH(ad)
	rr := httptest.NewRecorder()
	h.APICreateSchema(rr, authPOST(t, "/api/v1/schemas", map[string]any{
		"name": " Person ",
		"fields": []map[string]any{
			{"name": " givenName ", "required": true},
			{"name": "", "datatype": "string"},
			{"name": "dob", "datatype": "date", "format": "YYYY-MM-DD"},
		},
	}))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d, want 201 (body=%s)", rr.Code, rr.Body.String())
	}
	if len(ad.saved) != 1 {
		t.Fatalf("saved %d schemas, want 1", len(ad.saved))
	}
	s := ad.saved[0]
	if !strings.HasPrefix(s.ID, "custom-") || s.Name != "Person" || s.Desc != "—" || s.Std != "w3c_vcdm_2" || !s.Custom {
		t.Errorf("defaults not applied: %+v", s)
	}
	if len(s.DPGs) != 1 || s.DPGs[0] != "dpg1" {
		t.Errorf("issuer DPG should default to the first issuer DPG, got %v", s.DPGs)
	}
	if len(s.AdditionalTypes) != 0 {
		t.Errorf("AdditionalTypes = %v, want empty", s.AdditionalTypes)
	}
	if len(s.FieldsSpec) != 2 || s.FieldsSpec[0].Name != "givenName" || s.FieldsSpec[0].Datatype != "string" || !s.FieldsSpec[0].Required ||
		s.FieldsSpec[1].Datatype != "date" || s.FieldsSpec[1].Format != "YYYY-MM-DD" {
		t.Errorf("FieldsSpec = %+v", s.FieldsSpec)
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if out["id"] != s.ID || out["name"] != "Person" || out["custom"] != true || out["std"] != "w3c_vcdm_2" {
		t.Errorf("response = %v", out)
	}
	if fields := out["fields"].([]any); len(fields) != 2 {
		t.Errorf("response fields = %v", fields)
	}
}

func TestAPICreateSchema_ExplicitValuesAndSaveError(t *testing.T) {
	ad := &schemasAPIAdapter{}
	h := apiTestH(ad)
	rr := httptest.NewRecorder()
	h.APICreateSchema(rr, authPOST(t, "/api/v1/schemas", map[string]any{
		"name": "Diploma", "desc": " A diploma ", "std": "sd_jwt_vc", "issuer_display_name": " Example University ",
		"extra_type": " DiplomaCredential ", "issuer_dpg": "dpg-explicit",
		"fields": []map[string]any{{"name": "degree"}},
	}))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d (body=%s)", rr.Code, rr.Body.String())
	}
	s := ad.saved[0]
	if s.Desc != "A diploma" || s.Std != "sd_jwt_vc (IETF)" || s.IssuerDisplayName != "Example University" ||
		s.DPGs[0] != "dpg-explicit" || len(s.AdditionalTypes) != 1 || s.AdditionalTypes[0] != "DiplomaCredential" {
		t.Errorf("explicit values not honoured: %+v", s)
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if out["desc"] != "A diploma" || out["issuer_display_name"] != "Example University" {
		t.Errorf("response = %v", out)
	}

	ad.saveErr = errors.New("vendor down")
	rr = httptest.NewRecorder()
	h.APICreateSchema(rr, authPOST(t, "/api/v1/schemas", map[string]any{
		"name": "X", "fields": []map[string]any{{"name": "a"}},
	}))
	if rr.Code != http.StatusBadGateway || decodeJSON(t, rr.Body.Bytes())["error"] != "vendor down" {
		t.Errorf("save error: status %d body %s", rr.Code, rr.Body.String())
	}
}

func TestAPIListSchemas(t *testing.T) {
	ad := &schemasAPIAdapter{}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APIListSchemas(rr, httptest.NewRequest(http.MethodGet, "/api/v1/schemas", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: status %d", rr.Code)
	}

	get := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/schemas", nil)
		req.Header.Set("Authorization", "Bearer secret")
		return req
	}
	ad.schemasErr = errors.New("boom")
	rr = httptest.NewRecorder()
	h.APIListSchemas(rr, get())
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "backend unavailable: boom") {
		t.Errorf("backend error: %d %s", rr.Code, rr.Body.String())
	}

	ad.schemasErr = nil
	ad.schemas = []vctypes.Schema{
		{ID: "stock", Name: "Stock", Custom: false},
		{ID: "custom-1", Name: "Mine", Custom: true, Std: "w3c_vcdm_2", FieldsSpec: []vctypes.FieldSpec{{Name: "a", Datatype: "string"}}},
	}
	rr = httptest.NewRecorder()
	h.APIListSchemas(rr, get())
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if out["total"] != float64(1) {
		t.Errorf("total = %v, want 1 (stock schemas filtered out)", out["total"])
	}
	list := out["schemas"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["id"] != "custom-1" {
		t.Errorf("schemas = %v", list)
	}
}

func TestAPIDeleteSchema(t *testing.T) {
	ad := &schemasAPIAdapter{}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APIDeleteSchema(rr, httptest.NewRequest(http.MethodDelete, "/api/v1/schemas/x", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: status %d", rr.Code)
	}

	del := func(id string) *http.Request {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/schemas/"+id, nil)
		req.Header.Set("Authorization", "Bearer secret")
		if id != "" {
			req.SetPathValue("id", id)
		}
		return req
	}
	rr = httptest.NewRecorder()
	h.APIDeleteSchema(rr, del(""))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "id required") {
		t.Errorf("empty id: %d %s", rr.Code, rr.Body.String())
	}

	ad.deleteErr = errors.New("not yours")
	rr = httptest.NewRecorder()
	h.APIDeleteSchema(rr, del("custom-1"))
	if rr.Code != http.StatusBadGateway || decodeJSON(t, rr.Body.Bytes())["error"] != "not yours" {
		t.Errorf("adapter error: %d %s", rr.Code, rr.Body.String())
	}

	ad.deleteErr = nil
	rr = httptest.NewRecorder()
	h.APIDeleteSchema(rr, del("custom-2"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if out["id"] != "custom-2" || out["status"] != "deleted" {
		t.Errorf("response = %v", out)
	}
	if len(ad.deleted) != 2 || ad.deleted[1] != "custom-2" {
		t.Errorf("deleted calls = %v", ad.deleted)
	}
}

func TestSchemaToAPIResult(t *testing.T) {
	got := schemaToAPIResult(vctypes.Schema{ID: "i", Name: "n", Desc: "d", Std: "s", IssuerDisplayName: "x", Custom: true,
		FieldsSpec: []vctypes.FieldSpec{{Name: "f", Datatype: "date", Format: "fmt", Required: true}}})
	if got.ID != "i" || got.Name != "n" || got.Desc != "d" || got.Std != "s" || got.IssuerDisplayName != "x" || !got.Custom {
		t.Errorf("scalar fields: %+v", got)
	}
	if len(got.Fields) != 1 || got.Fields[0] != (apiFieldSpec{Name: "f", Datatype: "date", Format: "fmt", Required: true}) {
		t.Errorf("fields: %+v", got.Fields)
	}
	if empty := schemaToAPIResult(vctypes.Schema{}); empty.Fields != nil {
		t.Errorf("no FieldsSpec should yield nil Fields, got %v", empty.Fields)
	}
}
