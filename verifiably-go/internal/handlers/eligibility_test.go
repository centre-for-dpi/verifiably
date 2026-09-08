package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/auth"
	"github.com/verifiably/verifiably-go/vctypes"
)

// fakeTokenProvider is an auth.Provider whose only exercised method is
// VerifyToken; the eligibility token path never calls the others. Embedding
// the nil interface keeps the fake to one method.
type fakeTokenProvider struct {
	auth.Provider
	claims map[string]string
	err    error
}

func (fakeTokenProvider) ID() string { return "fake" }

func (f fakeTokenProvider) VerifyToken(context.Context, string) (map[string]string, error) {
	return f.claims, f.err
}

func TestEvaluateEligibility(t *testing.T) {
	configs := []backend.CredentialConfig{
		{ID: "PersonCredential", Claims: []string{"given_name", "family_name", "birthdate"}},
		{ID: "Diploma", Claims: []string{"given_name", "degree", "gpa"}},
		{ID: "Membership", Claims: nil}, // no declared claims → "unknown", not available
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
		{ID: "Membership", Available: false},
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

func TestAPICheckEligibility_VerifiedTokenClaimsUsed(t *testing.T) {
	// The schema needs given_name. The body sends NO claims; only a verified
	// id_token supplies given_name. Eligibility must therefore use the verified
	// token claims, proving the token path is wired.
	ad := &testAdapter{schemas: []vctypes.Schema{
		{ID: "PersonCredential", Std: "w3c_vcdm_2",
			FieldsSpec: []vctypes.FieldSpec{{Name: "given_name"}}},
	}}
	h := apiTestH(ad)
	reg := auth.NewRegistry()
	reg.Register(fakeTokenProvider{claims: map[string]string{"given_name": "Ana"}})
	h.AuthReg = reg

	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, authPOST(t, "/api/v1/credentials/eligible", map[string]any{
		"id_token": "header.payload.sig",
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Credentials []eligibilityResult `json:"credentials"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Credentials) != 1 || !resp.Credentials[0].Available {
		t.Errorf("credentials = %+v, want available via verified token", resp.Credentials)
	}
}

func TestAPICheckEligibility_BadTokenRejected(t *testing.T) {
	h := apiTestH(&testAdapter{})
	reg := auth.NewRegistry()
	reg.Register(fakeTokenProvider{err: errors.New("bad signature")})
	h.AuthReg = reg

	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, authPOST(t, "/api/v1/credentials/eligible", map[string]any{
		"id_token": "x.y.z",
	}))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestAPICheckEligibility_CitizenAccessToken(t *testing.T) {
	// Citizen path: access_token in body, no API key. Should evaluate eligibility
	// against the full (unscoped) catalog using the verified token claims.
	ad := &testAdapter{schemas: []vctypes.Schema{
		{ID: "PersonCredential", Std: "w3c_vcdm_2",
			FieldsSpec: []vctypes.FieldSpec{{Name: "given_name"}}},
	}}
	h := apiTestH(ad)
	reg := auth.NewRegistry()
	reg.Register(fakeTokenProvider{claims: map[string]string{"given_name": "Ana"}})
	h.AuthReg = reg

	b, _ := json.Marshal(map[string]any{"access_token": "header.payload.sig"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/eligible", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	// Deliberately no Authorization header — citizen path.

	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("citizen path: status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
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

func TestAPICheckEligibility_CitizenBadTokenRejected(t *testing.T) {
	h := apiTestH(&testAdapter{})
	reg := auth.NewRegistry()
	reg.Register(fakeTokenProvider{err: errors.New("bad signature")})
	h.AuthReg = reg

	b, _ := json.Marshal(map[string]any{"access_token": "x.y.z"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/eligible", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("citizen bad token: status = %d, want 401", rr.Code)
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

func TestAPICheckEligibility_OptionsAndBadJSON(t *testing.T) {
	h := apiTestH(&testAdapter{})
	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, httptest.NewRequest(http.MethodOptions, "/api/v1/credentials/eligible", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", rr.Code)
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/eligible", strings.NewReader("{not json"))
	h.APICheckEligibility(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid JSON body") {
		t.Fatalf("bad JSON: status = %d body = %s", rr.Code, rr.Body.String())
	}
}

// eligibilityDenyAll is a RateLimiter with zero allowance on both axes.
func eligibilityDenyAll() *RateLimiter {
	return &RateLimiter{byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
}

func TestAPICheckEligibility_CitizenRateLimited(t *testing.T) {
	h := selfIssueH(t, &testAdapter{}, map[string]string{"sub": "x"}, nil)
	h.RateLimiter = eligibilityDenyAll()
	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, selfIssuePOST(t, map[string]string{"access_token": "tok"}))
	if rr.Code != http.StatusTooManyRequests || !strings.Contains(rr.Body.String(), "rate limit exceeded") {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPICheckEligibility_CitizenMetadataErrors(t *testing.T) {
	t.Run("non-issuing member returns empty list", func(t *testing.T) {
		h := selfIssueH(t, &testAdapter{schemasErr: backend.ErrNotSupported}, map[string]string{"sub": "x"}, nil)
		rr := httptest.NewRecorder()
		h.APICheckEligibility(rr, selfIssuePOST(t, map[string]string{"id_token": "tok"}))
		if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != `{"credentials":[]}` {
			t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("upstream failure is 502", func(t *testing.T) {
		h := selfIssueH(t, &testAdapter{schemasErr: errors.New("vendor down")}, map[string]string{"sub": "x"}, nil)
		rr := httptest.NewRecorder()
		h.APICheckEligibility(rr, selfIssuePOST(t, map[string]string{"id_token": "tok"}))
		if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "issuer metadata unavailable: vendor down") {
			t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
		}
	})
}

func TestAPICheckEligibility_OperatorMetadataError502(t *testing.T) {
	h := apiTestH(&testAdapter{schemasErr: errors.New("vendor down")})
	rr := httptest.NewRecorder()
	h.APICheckEligibility(rr, authPOST(t, "/api/v1/credentials/eligible", map[string]any{"claims": map[string]string{"sub": "x"}}))
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "issuer metadata unavailable: vendor down") {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestVerifyCitizenToken_NoProvidersConfigured(t *testing.T) {
	h := &H{}
	_, err := h.verifyCitizenToken(context.Background(), "tok")
	if err == nil || err.Error() != "no identity providers configured" {
		t.Fatalf("err = %v", err)
	}
}
