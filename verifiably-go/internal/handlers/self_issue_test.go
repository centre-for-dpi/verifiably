package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/auth"
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
