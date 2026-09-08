package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

// delegAPIAdapter drives the single-issue + verify endpoints: it records
// schema registrations and issue requests and can fail at each step.
type delegAPIAdapter struct {
	testAdapter
	saved       []vctypes.Schema
	saveErr     error
	issued      []backend.IssueRequest
	issueErr    error
	noIssuer    bool
	noVerifier  bool
	fetchResult backend.VerificationResult
	fetchErr    error
	fetchState  string
}

func (a *delegAPIAdapter) SaveCustomSchema(_ context.Context, s vctypes.Schema) error {
	a.saved = append(a.saved, s)
	return a.saveErr
}
func (a *delegAPIAdapter) IssueToWallet(_ context.Context, r backend.IssueRequest) (backend.IssueToWalletResult, error) {
	a.issued = append(a.issued, r)
	if a.issueErr != nil {
		return backend.IssueToWalletResult{}, a.issueErr
	}
	return backend.IssueToWalletResult{OfferURI: "openid-credential-offer://" + r.Schema.ID, Flow: r.Flow}, nil
}
func (a *delegAPIAdapter) ListIssuerDpgs(ctx context.Context) (map[string]vctypes.DPG, error) {
	if a.noIssuer {
		return nil, nil
	}
	return a.testAdapter.ListIssuerDpgs(ctx)
}
func (a *delegAPIAdapter) ListVerifierDpgs(ctx context.Context) (map[string]vctypes.DPG, error) {
	if a.noVerifier {
		return nil, errors.New("no verifiers")
	}
	return a.testAdapter.ListVerifierDpgs(ctx)
}
func (a *delegAPIAdapter) FetchPresentationResult(_ context.Context, state, _ string) (backend.VerificationResult, error) {
	a.fetchState = state
	return a.fetchResult, a.fetchErr
}

func delegAPIRaw(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	return req
}

func TestAPIDelegationIssue_Errors(t *testing.T) {
	ad := &delegAPIAdapter{}
	h := apiTestH(ad)
	const path = "/api/v1/delegation/issue"

	rr := httptest.NewRecorder()
	h.APIDelegationIssue(rr, httptest.NewRequest(http.MethodPost, path, nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: %d", rr.Code)
	}

	// Rate limited: a limiter with a zero per-key budget rejects everything.
	h.RateLimiter = &RateLimiter{keyLimit: 0, ipLimit: 1, byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
	rr = httptest.NewRecorder()
	h.APIDelegationIssue(rr, delegAPIRaw(http.MethodPost, path, `{}`))
	if rr.Code != http.StatusTooManyRequests || rr.Header().Get("Retry-After") != "60" {
		t.Errorf("rate limit: %d retry-after=%q", rr.Code, rr.Header().Get("Retry-After"))
	}
	h.RateLimiter = nil

	cases := []struct {
		name, body string
		status     int
		wantErr    string
		prep       func()
	}{
		{"invalid json", `{`, 400, "invalid JSON", nil},
		{"subjectRef required", `{"subject":{"subjectRef":" "}}`, 400, "subject.subjectRef required", nil},
		{"no issuer dpg", `{"subject":{"subjectRef":"urn:person:1"}}`, 503, "no issuer DPG available", func() { ad.noIssuer = true }},
		{"register fails", `{"subject":{"subjectRef":"urn:person:1"}}`, 502, "register subject schema: catalog down", func() { ad.noIssuer = false; ad.saveErr = errors.New("catalog down") }},
		{"issue fails", `{"subject":{"subjectRef":"urn:person:1"}}`, 502, "issue subject credential: wallet down", func() { ad.saveErr = nil; ad.issueErr = errors.New("wallet down") }},
	}
	for _, c := range cases {
		if c.prep != nil {
			c.prep()
		}
		rr := httptest.NewRecorder()
		h.APIDelegationIssue(rr, delegAPIRaw(http.MethodPost, path, c.body))
		if rr.Code != c.status {
			t.Errorf("%s: status %d, want %d (body=%s)", c.name, rr.Code, c.status, rr.Body.String())
		}
		if got, _ := decodeJSON(t, rr.Body.Bytes())["error"].(string); !strings.Contains(got, c.wantErr) {
			t.Errorf("%s: error %q, want contains %q", c.name, got, c.wantErr)
		}
	}
}

func TestAPIDelegationIssue_Success(t *testing.T) {
	ad := &delegAPIAdapter{}
	h := apiTestH(ad)
	rr := httptest.NewRecorder()
	h.APIDelegationIssue(rr, authPOST(t, "/api/v1/delegation/issue", map[string]any{
		"subject":    map[string]any{"subjectRef": "urn:person:1", "claims": map[string]string{"givenName": "Alice"}},
		"delegation": map[string]any{"delegateId": "did:example:delegate", "role": "Guardian", "allowedAction": []string{"present"}},
	}))
	if rr.Code != http.StatusCreated {
		t.Fatalf("status %d (body=%s)", rr.Code, rr.Body.String())
	}
	if len(ad.saved) != 2 || ad.saved[0].ID != "da-birthcertificate" || ad.saved[1].ID != "da-delegatedaccesscredential" {
		t.Errorf("registered schemas = %+v", ad.saved)
	}
	if len(ad.issued) != 2 || ad.issued[0].IssuerDpg != "dpg1" || ad.issued[0].Flow != "pre_auth" || ad.issued[1].Flow != "pre_auth" {
		t.Fatalf("issued = %+v", ad.issued)
	}
	if !strings.Contains(string(ad.issued[1].CredentialData), `"onBehalfOf":{"id":"urn:person:1"}`) {
		t.Errorf("delegation body must nest onBehalfOf: %s", ad.issued[1].CredentialData)
	}
	out := decodeJSON(t, rr.Body.Bytes())
	subj := out["subject"].(map[string]any)
	deleg := out["delegation"].(map[string]any)
	if subj["type"] != "BirthCertificate" || subj["offerUri"] != "openid-credential-offer://da-birthcertificate" {
		t.Errorf("subject result = %v", subj)
	}
	if deleg["type"] != "DelegatedAccessCredential" || deleg["offerUri"] != "openid-credential-offer://da-delegatedaccesscredential" {
		t.Errorf("delegation result = %v", deleg)
	}
}

func TestDelegationCredSchema(t *testing.T) {
	s := delegationCredSchema("Person", "dpg1", []string{"a", "b"}, "w3c_vcdm_2")
	if s.ID != "da-person" || s.Name != "Person" || s.Desc != "Delegated-access Person" || s.Std != "w3c_vcdm_2" ||
		!s.Custom || len(s.DPGs) != 1 || s.DPGs[0] != "dpg1" || len(s.AdditionalTypes) != 1 || s.AdditionalTypes[0] != "Person" {
		t.Errorf("w3c v2: %+v", s)
	}
	if len(s.FieldsSpec) != 2 || s.FieldsSpec[1] != (vctypes.FieldSpec{Name: "b", Datatype: "string"}) {
		t.Errorf("fields: %+v", s.FieldsSpec)
	}
	if got := delegationCredSchema("Person", "d", nil, "sd_jwt_vc (IETF)").ID; got != "da-person-sdjwt" {
		t.Errorf("sd-jwt id = %q", got)
	}
	if got := delegationCredSchema("Person", "d", nil, "w3c_vcdm_1").ID; got != "da-person-v1" {
		t.Errorf("v1 id = %q", got)
	}
}

func TestDelegationContextURL(t *testing.T) {
	t.Setenv("VERIFIABLY_PUBLIC_URL", "")
	if got := delegationContextURL(); got != "" {
		t.Errorf("unset: %q", got)
	}
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://issuer.example/")
	if got := delegationContextURL(); got != "https://issuer.example/static/contexts/delegated-access-v1.jsonld" {
		t.Errorf("set: %q", got)
	}
}

func TestAPIDelegationVerifyRequest(t *testing.T) {
	ad := &delegAPIAdapter{}
	h := apiTestH(ad)
	const path = "/api/v1/delegation/verify/request"

	rr := httptest.NewRecorder()
	h.APIDelegationVerifyRequest(rr, httptest.NewRequest(http.MethodPost, path, nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: %d", rr.Code)
	}

	ad.noVerifier = true
	rr = httptest.NewRecorder()
	h.APIDelegationVerifyRequest(rr, delegAPIRaw(http.MethodPost, path, ""))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "no verifier DPG available") {
		t.Errorf("no verifier: %d %s", rr.Code, rr.Body.String())
	}
	ad.noVerifier = false

	ad.verifyErr = errors.New("verifier down")
	rr = httptest.NewRecorder()
	h.APIDelegationVerifyRequest(rr, delegAPIRaw(http.MethodPost, path, `{}`))
	if rr.Code != http.StatusBadGateway || decodeJSON(t, rr.Body.Bytes())["error"] != "verifier down" {
		t.Errorf("adapter error: %d %s", rr.Code, rr.Body.String())
	}
	ad.verifyErr = nil

	// Success, defaults (jwt_vc_json): the delegation descriptor asks only for onBehalfOf.
	var captured backend.PresentationRequest
	capturing := &delegVerifyCapture{delegAPIAdapter: ad, got: &captured}
	h.Adapter = capturing
	ad.verifyResult = backend.PresentationRequestResult{RequestURI: "openid4vp://x", State: "st-1"}
	rr = httptest.NewRecorder()
	h.APIDelegationVerifyRequest(rr, delegAPIRaw(http.MethodPost, path, `{"verifierDpg":"ver-explicit"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d (body=%s)", rr.Code, rr.Body.String())
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if out["requestUri"] != "openid4vp://x" || out["state"] != "st-1" {
		t.Errorf("response = %v", out)
	}
	if req := out["requested"].([]any); len(req) != 2 || req[0] != "BirthCertificate" || req[1] != "DelegatedAccessCredential" {
		t.Errorf("requested = %v", req)
	}
	if captured.VerifierDpg != "ver-explicit" || len(captured.Templates) != 2 || strings.Join(captured.Policies, ",") != "signature,expired,not-before" {
		t.Errorf("presentation request = %+v", captured)
	}
	if tpl := captured.Templates[1]; tpl.Format != "w3c_vcdm_2" || strings.Join(tpl.Fields, ",") != "onBehalfOf" || tpl.Disclosure != "full" {
		t.Errorf("delegation template (jwt) = %+v", tpl)
	}

	// SD-JWT wire format: the delegation claim must be disclosed too.
	rr = httptest.NewRecorder()
	h.APIDelegationVerifyRequest(rr, delegAPIRaw(http.MethodPost, path, `{"wireFormat":"vc+sd-jwt","subjectType":"Person","delegationType":"Mandate"}`))
	if rr.Code != http.StatusOK {
		t.Fatalf("sd-jwt status %d", rr.Code)
	}
	if captured.VerifierDpg != "ver1" {
		t.Errorf("default verifier DPG = %q, want ver1", captured.VerifierDpg)
	}
	if tpl := captured.Templates[1]; tpl.Format != "sd_jwt_vc (IETF)" || tpl.Vct != "Mandate" || tpl.Disclosure != "selective" ||
		strings.Join(tpl.Fields, ",") != "onBehalfOf,delegation" {
		t.Errorf("delegation template (sd-jwt) = %+v", tpl)
	}
	if tpl := captured.Templates[0]; tpl.Title != "Person" || tpl.CredentialType != "Person" || strings.Join(tpl.Fields, ",") != "subjectRef" {
		t.Errorf("subject template = %+v", tpl)
	}
}

// delegVerifyCapture records the PresentationRequest handed to the adapter.
type delegVerifyCapture struct {
	*delegAPIAdapter
	got *backend.PresentationRequest
}

func (c *delegVerifyCapture) RequestPresentation(ctx context.Context, r backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	*c.got = r
	return c.delegAPIAdapter.RequestPresentation(ctx, r)
}

func TestAPIDelegationVerifyResult(t *testing.T) {
	ad := &delegAPIAdapter{}
	h := apiTestH(ad)
	get := func(state string) *http.Request {
		req := delegAPIRaw(http.MethodGet, "/api/v1/delegation/verify/result/"+state, "")
		if state != "" {
			req.SetPathValue("state", state)
		}
		return req
	}

	rr := httptest.NewRecorder()
	h.APIDelegationVerifyResult(rr, httptest.NewRequest(http.MethodGet, "/api/v1/delegation/verify/result/x", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.APIDelegationVerifyResult(rr, get(""))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "state required") {
		t.Errorf("empty state: %d %s", rr.Code, rr.Body.String())
	}
	ad.fetchErr = errors.New("unknown state")
	rr = httptest.NewRecorder()
	h.APIDelegationVerifyResult(rr, get("st-1"))
	if rr.Code != http.StatusBadGateway || decodeJSON(t, rr.Body.Bytes())["error"] != "unknown state" || ad.fetchState != "st-1" {
		t.Errorf("fetch error: %d %s state=%q", rr.Code, rr.Body.String(), ad.fetchState)
	}
	ad.fetchErr = nil

	// Pending: no credentials, no delegation block.
	ad.fetchResult = backend.VerificationResult{Pending: true}
	rr = httptest.NewRecorder()
	h.APIDelegationVerifyResult(rr, get("st-2"))
	out := decodeJSON(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || out["pending"] != true || out["credentialCount"] != float64(0) {
		t.Errorf("pending: %d %v", rr.Code, out)
	}
	if _, has := out["delegation"]; has {
		t.Error("pending result must not carry a delegation verdict")
	}

	// A presented pair is evaluated (no status cache → fail-closed deny).
	ad.fetchResult = backend.VerificationResult{Valid: true, Method: "OID4VP", Credentials: delegPair(3),
		HolderBinding:   &backend.HolderBinding{ID: "did:example:delegate", Confirmed: true},
		DisclosedFields: map[string]string{"subjectRef": "urn:person:1"}}
	rr = httptest.NewRecorder()
	h.APIDelegationVerifyResult(rr, get("st-3"))
	out = decodeJSON(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || out["valid"] != false || out["credentialCount"] != float64(2) {
		t.Errorf("pair: %d %v", rr.Code, out)
	}
	if !strings.Contains(out["method"].(string), "OID4VP · delegation:") {
		t.Errorf("method = %v", out["method"])
	}
	deleg, _ := out["delegation"].(map[string]any)
	if deleg == nil || deleg["Evaluated"] != true || deleg["Authorized"] != false {
		t.Errorf("delegation = %v", out["delegation"])
	}
	if disc := out["disclosed"].(map[string]any); disc["subjectRef"] != "urn:person:1" {
		t.Errorf("disclosed = %v", disc)
	}
}
