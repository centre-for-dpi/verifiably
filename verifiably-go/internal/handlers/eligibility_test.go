package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

func TestEvaluateEligibility(t *testing.T) {
	configs := []backend.CredentialConfig{
		{ID: "PersonCredential", Claims: []string{"given_name", "family_name", "birthdate"}},
		{ID: "Diploma", Claims: []string{"given_name", "degree", "gpa"}},
		{ID: "Membership", Claims: nil}, // no claims → always available
	}
	claims := map[string]string{
		"given_name":  "Ana",
		"family_name": "Pérez",
		"birthdate":   "1990-05-01",
	}

	got := evaluateEligibility(configs, claims)
	want := []eligibilityResult{
		{ID: "PersonCredential", Available: true},
		{ID: "Diploma", Available: false, MissingClaims: []string{"degree", "gpa"}},
		{ID: "Membership", Available: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("evaluateEligibility = %+v, want %+v", got, want)
	}
}

func TestEvaluateEligibility_AliasMatching(t *testing.T) {
	// A credential field "dateOfBirth" must be satisfied by the OIDC `birthdate`
	// claim — same alias matching National ID prefill uses.
	configs := []backend.CredentialConfig{
		{ID: "AgeCredential", Claims: []string{"dateOfBirth", "nacionalidad"}},
	}
	claims := map[string]string{"birthdate": "1990-05-01", "nationality": "GT"}

	got := evaluateEligibility(configs, claims)
	if !got[0].Available {
		t.Errorf("expected available via aliases, got %+v", got[0])
	}
}

func TestEvaluateEligibility_NoClaimsNothingAvailable(t *testing.T) {
	configs := []backend.CredentialConfig{
		{ID: "PersonCredential", Claims: []string{"given_name"}},
	}
	got := evaluateEligibility(configs, nil)
	if got[0].Available || !reflect.DeepEqual(got[0].MissingClaims, []string{"given_name"}) {
		t.Errorf("unauthenticated citizen should be ineligible, got %+v", got[0])
	}
}

func TestAPICheckEligibility_Success(t *testing.T) {
	ad := &testAdapter{schemas: []vctypes.Schema{
		{ID: "PersonCredential", Std: "w3c_vcdm_2",
			FieldsSpec: []vctypes.FieldSpec{{Name: "given_name"}, {Name: "family_name"}}},
	}}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, authPOST(t, "/api/v1/credentials/eligible", map[string]any{
		"claims": map[string]string{"given_name": "Ana", "family_name": "Pérez"},
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Credentials []eligibilityResult `json:"credentials"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Credentials) != 1 || !resp.Credentials[0].Available {
		t.Errorf("credentials = %+v, want PersonCredential available", resp.Credentials)
	}
}

func TestAPICheckEligibility_Unauthorized(t *testing.T) {
	h := apiTestH(&testAdapter{})
	rr := httptest.NewRecorder()
	// No Authorization header → 401.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/eligible", nil)
	h.APICheckEligibility(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAPICheckEligibility_NonIssuingMemberEmpty(t *testing.T) {
	// Adapter returns ErrNotSupported → 200 with an empty credentials list.
	ad := &testAdapter{schemasErr: backend.ErrNotSupported}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, authPOST(t, "/api/v1/credentials/eligible", map[string]any{
		"claims": map[string]string{"given_name": "Ana"},
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Credentials []eligibilityResult `json:"credentials"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Credentials) != 0 {
		t.Errorf("credentials = %+v, want empty", resp.Credentials)
	}
}
