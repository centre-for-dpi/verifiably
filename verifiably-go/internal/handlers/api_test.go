package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/statuslist"
	"github.com/verifiably/verifiably-go/vctypes"
)

// ─── testAdapter ──────────────────────────────────────────────────────────────

// testAdapter is a minimal backend.Adapter for API handler tests. Methods not
// needed in a given test scenario embed the nil-interface panic path (same
// pattern as fakeAdapter in status_list_e2e_test.go) so any unexpected call
// surfaces immediately with a clear trace instead of silently returning zero.
type testAdapter struct {
	backend.Adapter // nil — panics on unintended method calls

	schemas      []vctypes.Schema
	schemasErr   error
	issueResult  backend.IssueToWalletResult
	issueErr     error
	verifyResult backend.PresentationRequestResult
	verifyErr    error
}

func (m *testAdapter) ListAllSchemas(_ context.Context) ([]vctypes.Schema, error) {
	return m.schemas, m.schemasErr
}
func (m *testAdapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return map[string]vctypes.DPG{"dpg1": {}}, nil
}
func (m *testAdapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	return map[string]vctypes.DPG{"ver1": {}}, nil
}
func (m *testAdapter) IssueToWallet(_ context.Context, _ backend.IssueRequest) (backend.IssueToWalletResult, error) {
	return m.issueResult, m.issueErr
}
func (m *testAdapter) RequestPresentation(_ context.Context, _ backend.PresentationRequest) (backend.PresentationRequestResult, error) {
	return m.verifyResult, m.verifyErr
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// apiTestH builds an H wired with ad and a single API key "test:secret".
// BitstringStore, TokenStore, IssuanceLog are deliberately nil so the issue
// flow skips status-list allocation and audit logging — both are tested in
// status_list_e2e_test.go and issuance_test.go respectively.
func apiTestH(ad backend.Adapter) *H {
	return &H{
		Adapter: ad,
		APIKeys: ParseAPIKeys("test:secret"),
	}
}

// authPOST builds a JSON POST authenticated with the "test:secret" API key.
func authPOST(t *testing.T, path string, body any) *http.Request {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret")
	return req
}

// decodeJSON decodes a JSON response body into map[string]any for assertions.
func decodeJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decodeJSON: %v (body=%s)", err, body)
	}
	return m
}

// ─── APIIssue ─────────────────────────────────────────────────────────────────

func TestAPIIssue_Success(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Passport", DPGs: []string{"dpg1"}}
	ad := &testAdapter{
		schemas:     []vctypes.Schema{schema},
		issueResult: backend.IssueToWalletResult{OfferURI: "openid-credential-offer://x", Flow: "pre_auth"},
	}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APIIssue(rr, authPOST(t, "/api/v1/credentials/issue", map[string]any{
		"schema_id":    "s1",
		"subject_data": map[string]string{"name": "Alice"},
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if out["offer_uri"] != "openid-credential-offer://x" {
		t.Errorf("offer_uri: %v", out["offer_uri"])
	}
	if out["flow"] != "pre_auth" {
		t.Errorf("flow: %v", out["flow"])
	}
}

func TestAPIIssue_SchemaNotFound(t *testing.T) {
	ad := &testAdapter{schemas: []vctypes.Schema{}}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APIIssue(rr, authPOST(t, "/api/v1/credentials/issue", map[string]any{
		"schema_id": "does-not-exist",
	}))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", rr.Code)
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if _, ok := out["error"]; !ok {
		t.Error("response body must contain 'error' field")
	}
}

func TestAPIIssue_AdapterError(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Test", DPGs: []string{"dpg1"}}
	ad := &testAdapter{
		schemas:  []vctypes.Schema{schema},
		issueErr: errors.New("upstream unavailable"),
	}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APIIssue(rr, authPOST(t, "/api/v1/credentials/issue", map[string]any{
		"schema_id":    "s1",
		"subject_data": map[string]string{"name": "Alice"},
	}))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502 (body=%s)", rr.Code, rr.Body.String())
	}
}

func TestAPIIssue_Unauthenticated(t *testing.T) {
	h := apiTestH(&testAdapter{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/issue", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()
	h.APIIssue(rr, req)

	// No API keys configured → 503; wrong/missing token → 401.
	if rr.Code != http.StatusServiceUnavailable && rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d, want 401 or 503", rr.Code)
	}
}

func TestAPIIssue_RateLimited(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Test", DPGs: []string{"dpg1"}}
	ad := &testAdapter{
		schemas:     []vctypes.Schema{schema},
		issueResult: backend.IssueToWalletResult{OfferURI: "openid-credential-offer://x", Flow: "pre_auth"},
	}
	h := apiTestH(ad)
	// Tiny limit so we hit it in one extra request.
	h.RateLimiter = &RateLimiter{
		keyLimit: 1,
		ipLimit:  1000,
		byKey:    make(map[string]*rateEntry),
		byIP:     make(map[string]*rateEntry),
	}

	body := map[string]any{"schema_id": "s1", "subject_data": map[string]string{"name": "X"}}

	// First request: must succeed (consumes the 1 allowed token).
	rr1 := httptest.NewRecorder()
	h.APIIssue(rr1, authPOST(t, "/api/v1/credentials/issue", body))
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", rr1.Code)
	}

	// Second request: must be rejected with 429.
	rr2 := httptest.NewRecorder()
	h.APIIssue(rr2, authPOST(t, "/api/v1/credentials/issue", body))
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", rr2.Code)
	}
	if rr2.Header().Get("Retry-After") == "" {
		t.Error("429 response must include Retry-After header")
	}
}

// ─── APIIssueBulk ─────────────────────────────────────────────────────────────

func TestAPIIssueBulk_RowLimitExceeded(t *testing.T) {
	h := apiTestH(&testAdapter{schemas: []vctypes.Schema{}})

	rows := make([]map[string]string, maxBulkRows+1)
	for i := range rows {
		rows[i] = map[string]string{"name": "X"}
	}
	rr := httptest.NewRecorder()
	h.APIIssueBulk(rr, authPOST(t, "/api/v1/credentials/issue/bulk", map[string]any{
		"schema_id": "s1",
		"rows":      rows,
	}))

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status: got %d, want 413", rr.Code)
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if _, ok := out["error"]; !ok {
		t.Error("413 body must contain 'error' field")
	}
}

func TestAPIIssueBulk_Success(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Test", DPGs: []string{"dpg1"}}
	ad := &testAdapter{
		schemas:     []vctypes.Schema{schema},
		issueResult: backend.IssueToWalletResult{OfferURI: "openid-credential-offer://x", Flow: "pre_auth"},
	}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APIIssueBulk(rr, authPOST(t, "/api/v1/credentials/issue/bulk", map[string]any{
		"schema_id": "s1",
		"rows":      []map[string]string{{"name": "Alice"}, {"name": "Bob"}},
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if out["accepted"] != float64(2) {
		t.Errorf("accepted: %v, want 2", out["accepted"])
	}
	if out["rejected"] != float64(0) {
		t.Errorf("rejected: %v, want 0", out["rejected"])
	}
}

// ─── APIVerifyRequest ─────────────────────────────────────────────────────────

func TestAPIVerifyRequest_Success(t *testing.T) {
	schema := vctypes.Schema{
		ID:         "s1",
		Name:       "Passport",
		DPGs:       []string{"dpg1"},
		FieldsSpec: []vctypes.FieldSpec{{Name: "name", Datatype: "string"}},
	}
	ad := &testAdapter{
		schemas:      []vctypes.Schema{schema},
		verifyResult: backend.PresentationRequestResult{RequestURI: "openid4vp://x", State: "state-1"},
	}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APIVerifyRequest(rr, authPOST(t, "/api/v1/verify/request", map[string]any{
		"schema_id": "s1",
	}))

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	out := decodeJSON(t, rr.Body.Bytes())
	if out["request_uri"] != "openid4vp://x" {
		t.Errorf("request_uri: %v", out["request_uri"])
	}
	if out["state"] != "state-1" {
		t.Errorf("state: %v", out["state"])
	}
}

func TestAPIVerifyRequest_AdapterError(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Test", DPGs: []string{"dpg1"}}
	ad := &testAdapter{
		schemas:   []vctypes.Schema{schema},
		verifyErr: errors.New("verifier unreachable"),
	}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.APIVerifyRequest(rr, authPOST(t, "/api/v1/verify/request", map[string]any{
		"schema_id": "s1",
	}))

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502 (body=%s)", rr.Code, rr.Body.String())
	}
}

// ─── PublishBitstringStatusList ───────────────────────────────────────────────

// TestPublishBitstringStatusList_NoSigningKey verifies that when the adapter
// does not implement signingKeyAdapter the endpoint returns 503 rather than
// panicking or emitting an empty body.
func TestPublishBitstringStatusList_NoSigningKey(t *testing.T) {
	dir := t.TempDir()
	store, err := statuslist.NewStore("bitstring", "v1",
		filepath.Join(dir, "bs.json"),
		"https://issuer.test/status-list/bitstring/v1")
	if err != nil {
		t.Fatal(err)
	}
	// testAdapter does NOT implement IssuerSigningKey — resolveSigningKey must
	// return an error, not panic.
	h := &H{
		Adapter:        &testAdapter{},
		BitstringStore: store,
	}
	req := httptest.NewRequest(http.MethodGet, "/status-list/bitstring/v1", nil)
	req.SetPathValue("id", "v1")
	rr := httptest.NewRecorder()
	h.PublishBitstringStatusList(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want 503 (body=%s)", rr.Code, rr.Body.String())
	}
}
