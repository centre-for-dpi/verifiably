package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/auth"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// selfIssuePOST builds an unauthenticated JSON POST (self-issue has no API key;
// the id_token in the body is the credential).
func selfIssuePOST(t *testing.T, body any) *http.Request {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/self-issue", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func selfIssueH(t *testing.T, ad backend.Adapter, claims map[string]string, verr error) *H {
	t.Helper()
	h := apiTestH(ad)
	reg := auth.NewRegistry()
	reg.Register(fakeTokenProvider{claims: claims, err: verr})
	h.AuthReg = reg
	return h
}

func TestSelfIssueResolveSchema(t *testing.T) {
	schemas := []vctypes.Schema{
		{ID: "BankId", Variants: []vctypes.SchemaVariant{{ID: "BankId_jwt_vc_json"}}},
		{ID: "Diploma"}, // no variants — only resolvable via the suffixed fallback
	}
	cases := []struct {
		name, configID, wantID string
		wantOK                 bool
	}{
		{"bare exact", "BankId", "BankId", true},
		{"registered variant id", "BankId_jwt_vc_json", "BankId_jwt_vc_json", true},
		{"suffixed fallback", "Diploma_jwt_vc_json", "Diploma", true},
		{"unknown", "Nope_jwt_vc_json", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, ok := selfIssueResolveSchema(schemas, c.configID)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if ok && s.ID != c.wantID {
				t.Errorf("schema id = %q, want %q", s.ID, c.wantID)
			}
		})
	}
}

func personSchemaAdapter() *testAdapter {
	return &testAdapter{
		schemas: []vctypes.Schema{{
			ID: "PersonCredential", Name: "Person", Std: "w3c_vcdm_2",
			FieldsSpec: []vctypes.FieldSpec{{Name: "given_name"}, {Name: "family_name"}},
			DPGs:       []string{"dpg1"},
		}},
		issueResult: backend.IssueToWalletResult{
			OfferURI: "openid-credential-offer://example", Flow: "pre_auth", PIN: "4821",
		},
	}
}

func TestAPISelfIssue_Success(t *testing.T) {
	h := selfIssueH(t, personSchemaAdapter(), map[string]string{
		"sub": "citizen-123", "given_name": "Ana", "family_name": "Pérez",
	}, nil)

	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]any{
		"id_token":                    "h.p.s",
		"credential_configuration_id": "PersonCredential",
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp selfIssueResult
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.OfferURI != "openid-credential-offer://example" {
		t.Errorf("offer_uri = %q, want the minted offer", resp.OfferURI)
	}
	if resp.PIN != "4821" || resp.Flow != "pre_auth" {
		t.Errorf("pin/flow = %q/%q, want 4821/pre_auth", resp.PIN, resp.Flow)
	}
}

// TestAPISelfIssue_AccessToken pins that the wallet can send an access_token
// instead of an id_token — this is the preferred path since the wallet reliably
// refreshes the access_token but Keycloak may not return a new id_token in
// refresh responses.
func TestAPISelfIssue_AccessToken(t *testing.T) {
	h := selfIssueH(t, personSchemaAdapter(), map[string]string{
		"sub": "citizen-456", "given_name": "Luis", "family_name": "García",
	}, nil)

	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]any{
		"access_token":                "h.p.s",
		"credential_configuration_id": "PersonCredential",
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("access_token path: status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp selfIssueResult
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.OfferURI == "" {
		t.Error("offer_uri should be present")
	}
}

func TestAPISelfIssue_NoToken(t *testing.T) {
	h := selfIssueH(t, personSchemaAdapter(), map[string]string{"sub": "x"}, nil)
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]any{
		"credential_configuration_id": "PersonCredential",
	}))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAPISelfIssue_BadToken(t *testing.T) {
	h := selfIssueH(t, personSchemaAdapter(), nil, errors.New("bad signature"))
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]any{
		"id_token":                    "x.y.z",
		"credential_configuration_id": "PersonCredential",
	}))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestAPISelfIssue_NoSubClaim(t *testing.T) {
	// Token verifies but carries no `sub` — we can't bind HolderDID, so reject.
	h := selfIssueH(t, personSchemaAdapter(), map[string]string{
		"given_name": "Ana", "family_name": "Pérez",
	}, nil)
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]any{
		"id_token":                    "h.p.s",
		"credential_configuration_id": "PersonCredential",
	}))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestAPISelfIssue_NotEligible(t *testing.T) {
	// sub present but the citizen's claims don't cover family_name → 403 + the gap.
	h := selfIssueH(t, personSchemaAdapter(), map[string]string{
		"sub": "citizen-123", "given_name": "Ana",
	}, nil)
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]any{
		"id_token":                    "h.p.s",
		"credential_configuration_id": "PersonCredential",
	}))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		MissingClaims []string `json:"missing_claims"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.MissingClaims) != 1 || resp.MissingClaims[0] != "family_name" {
		t.Errorf("missing_claims = %v, want [family_name]", resp.MissingClaims)
	}
}

func TestAPISelfIssue_ConfigNotFound(t *testing.T) {
	h := selfIssueH(t, personSchemaAdapter(), map[string]string{"sub": "x"}, nil)
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]any{
		"id_token":                    "h.p.s",
		"credential_configuration_id": "DoesNotExist",
	}))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%s)", rr.Code, rr.Body.String())
	}
}

// selfIssueAdapter extends testAdapter with a configurable issuer-DPG list so
// the "no issuer DPG" branch is reachable.
type selfIssueAdapter struct {
	*testAdapter
	dpgs map[string]vctypes.DPG
}

func (a *selfIssueAdapter) ListIssuerDpgs(context.Context) (map[string]vctypes.DPG, error) {
	return a.dpgs, nil
}

// selfIssueFullList is a status-list backend whose Allocate always fails.
type selfIssueFullList struct {
	statuslist.Backend
}

func (selfIssueFullList) Allocate() (int, error) { return 0, errors.New("list full") }
func (selfIssueFullList) GetListID() string      { return "v1" }

func TestAPISelfIssue_OptionsAndRateLimit(t *testing.T) {
	h := selfIssueH(t, personSchemaAdapter(), map[string]string{"sub": "did:example:1"}, nil)
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, httptest.NewRequest(http.MethodOptions, "/api/v1/credentials/self-issue", nil))
	if rr.Code != http.StatusNoContent || rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("OPTIONS status = %d", rr.Code)
	}

	h.RateLimiter = &RateLimiter{byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
	rr = httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]string{"id_token": "tok", "credential_configuration_id": "PersonCredential"}))
	if rr.Code != http.StatusTooManyRequests || !strings.Contains(rr.Body.String(), "rate limit exceeded") {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPISelfIssue_BadRequests(t *testing.T) {
	h := selfIssueH(t, personSchemaAdapter(), map[string]string{"sub": "did:example:1"}, nil)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/self-issue", strings.NewReader("{oops"))
	h.APISelfIssue(rr, req)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid JSON body") {
		t.Fatalf("bad JSON: status = %d body = %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]string{"id_token": "tok"}))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "credential_configuration_id required") {
		t.Fatalf("missing config: status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPISelfIssue_SchemaListErrors(t *testing.T) {
	body := map[string]string{"id_token": "tok", "credential_configuration_id": "PersonCredential"}
	claims := map[string]string{"sub": "did:example:1"}

	h := selfIssueH(t, &testAdapter{schemasErr: backend.ErrNotSupported}, claims, nil)
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, body))
	if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "this member does not issue credentials") {
		t.Fatalf("not supported: status = %d body = %s", rr.Code, rr.Body.String())
	}

	h = selfIssueH(t, &testAdapter{schemasErr: errors.New("vendor down")}, claims, nil)
	rr = httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, body))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "backend unavailable: vendor down") {
		t.Fatalf("other error: status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func selfIssueEligibleClaims() map[string]string {
	return map[string]string{"sub": "did:example:1", "given_name": "Ada", "family_name": "Lovelace"}
}

func TestAPISelfIssue_NoIssuerDPG(t *testing.T) {
	ad := &selfIssueAdapter{testAdapter: personSchemaAdapter(), dpgs: map[string]vctypes.DPG{}}
	h := selfIssueH(t, ad, selfIssueEligibleClaims(), nil)
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]string{"id_token": "tok", "credential_configuration_id": "PersonCredential"}))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "no issuer DPG available") {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPISelfIssue_StatusListAllocateError(t *testing.T) {
	ad := personSchemaAdapter()
	ad.schemas[0].Std = "w3c_vcdm_2" // → bitstring list
	h := selfIssueH(t, ad, selfIssueEligibleClaims(), nil)
	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: selfIssueFullList{}, Kind: "bitstring"})
	h.StatusLists = set
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]string{"id_token": "tok", "credential_configuration_id": "PersonCredential"}))
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "status list: status list allocate: list full") {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}

func TestAPISelfIssue_IssueError502(t *testing.T) {
	ad := personSchemaAdapter()
	ad.issueErr = errors.New("wallet offer failed")
	h := selfIssueH(t, ad, selfIssueEligibleClaims(), nil)
	rr := httptest.NewRecorder()
	h.APISelfIssue(rr, selfIssuePOST(t, map[string]string{"id_token": "tok", "credential_configuration_id": "PersonCredential"}))
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "wallet offer failed") {
		t.Fatalf("status = %d body = %s", rr.Code, rr.Body.String())
	}
}
