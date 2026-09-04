package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/issuance"
	"github.com/verifiably/verifiably-go/internal/jobs"
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

	// Optional knobs (zero values keep the historical defaults above).
	issuerDpgs   map[string]vctypes.DPG // nil → {"dpg1": {}}
	verifierDpgs map[string]vctypes.DPG // nil → {"ver1": {}}
	dpgsErr      error                  // returned by both List*Dpgs when set
	fetchResult  backend.VerificationResult
	fetchErr     error
	fetchStates  []string        // states passed to FetchPresentationResult
	issueCalls   int32           // atomic count of IssueToWallet calls
	issueGate    <-chan struct{} // when non-nil, IssueToWallet blocks on one receive per call
	issueFailOn  int32           // when >0, the n-th IssueToWallet call fails with "wallet down"
}

func (m *testAdapter) ListAllSchemas(_ context.Context) ([]vctypes.Schema, error) {
	return m.schemas, m.schemasErr
}
func (m *testAdapter) GetIssuerMetadata(ctx context.Context) (backend.IssuerMetadata, error) {
	if m.schemasErr != nil {
		return backend.IssuerMetadata{}, m.schemasErr
	}
	return backend.IssuerMetadata{CredentialsSupported: backend.CredentialConfigsFromSchemas(m.schemas)}, nil
}
func (m *testAdapter) ListIssuerDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	if m.dpgsErr != nil {
		return nil, m.dpgsErr
	}
	if m.issuerDpgs != nil {
		return m.issuerDpgs, nil
	}
	return map[string]vctypes.DPG{"dpg1": {}}, nil
}
func (m *testAdapter) ListVerifierDpgs(_ context.Context) (map[string]vctypes.DPG, error) {
	if m.dpgsErr != nil {
		return nil, m.dpgsErr
	}
	if m.verifierDpgs != nil {
		return m.verifierDpgs, nil
	}
	return map[string]vctypes.DPG{"ver1": {}}, nil
}
func (m *testAdapter) IssueToWallet(_ context.Context, _ backend.IssueRequest) (backend.IssueToWalletResult, error) {
	n := atomic.AddInt32(&m.issueCalls, 1)
	if m.issueGate != nil {
		<-m.issueGate
	}
	if m.issueFailOn > 0 && n == m.issueFailOn {
		return backend.IssueToWalletResult{}, errors.New("wallet down")
	}
	return m.issueResult, m.issueErr
}
func (m *testAdapter) FetchPresentationResult(_ context.Context, state, _ string) (backend.VerificationResult, error) {
	m.fetchStates = append(m.fetchStates, state)
	return m.fetchResult, m.fetchErr
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

// A hosted list signs with its own self-managed key, so an adapter that
// exposes no issuer key is no longer a reason to fail. This used to 503:
// signing reached into the adapter for walt.id's onboarded key, so every
// deployment without a walt.id issuer (an Inji-only stack) lost revocation
// entirely. Publishing must now succeed and be verifiable.
func TestPublishBitstringStatusList_SelfSignedWithoutAdapterKey(t *testing.T) {
	dir := t.TempDir()
	store, err := statuslist.NewStore("bitstring", "v1",
		filepath.Join(dir, "bs.json"),
		"https://issuer.test/status-list/bitstring/v1")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := statuslist.NewSelfSignedKey(dir, "v1")
	if err != nil {
		t.Fatal(err)
	}
	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: store, Signer: signer, Kind: "bitstring"})
	// testAdapter deliberately exposes no IssuerSigningKey.
	h := &H{Adapter: &testAdapter{}, BitstringStore: store, StatusLists: set}

	req := httptest.NewRequest(http.MethodGet, "/status-list/bitstring/v1", nil)
	req.SetPathValue("id", "v1")
	req.Header.Set("Accept", "application/vc+jwt")
	rr := httptest.NewRecorder()
	h.PublishBitstringStatusList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/vc+jwt" {
		t.Fatalf("content-type: got %q, want application/vc+jwt", ct)
	}
	if parts := strings.Split(rr.Body.String(), "."); len(parts) != 3 {
		t.Fatalf("body must be a compact JWS, got %d parts", len(parts))
	}
}

// An id that names no hosted list must 404 rather than fall through to some
// other DPG's list.
func TestPublishBitstringStatusList_UnknownID(t *testing.T) {
	dir := t.TempDir()
	store, err := statuslist.NewStore("bitstring", "v1",
		filepath.Join(dir, "bs.json"),
		"https://issuer.test/status-list/bitstring/v1")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := statuslist.NewSelfSignedKey(dir, "v1")
	if err != nil {
		t.Fatal(err)
	}
	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: store, Signer: signer, Kind: "bitstring"})
	h := &H{Adapter: &testAdapter{}, BitstringStore: store, StatusLists: set}

	req := httptest.NewRequest(http.MethodGet, "/status-list/bitstring/nope", nil)
	req.SetPathValue("id", "nope")
	rr := httptest.NewRecorder()
	h.PublishBitstringStatusList(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status: got %d, want 404", rr.Code)
	}
}

// ─── coverage campaign (plan §4.4) ────────────────────────────────────────────

// apiFakeStore extends slFakeStore with the Reinstate side the API needs.
type apiFakeStore struct {
	slFakeStore
	reinstateErr error
	reinstated   []int
	allocCalls   int
	allocFailOn  int // when >0, the n-th Allocate fails with "full"
}

func (s *apiFakeStore) Allocate() (int, error) {
	s.allocCalls++
	if s.allocFailOn > 0 && s.allocCalls == s.allocFailOn {
		return 0, errors.New("full")
	}
	return s.slFakeStore.Allocate()
}

func (s *apiFakeStore) Reinstate(index int) error {
	s.reinstated = append(s.reinstated, index)
	return s.reinstateErr
}

// apiStatusSet registers store as the default bitstring list on h.
func apiStatusSet(h *H, store statuslist.Backend) {
	set := NewStatusListSet()
	set.Register(&StatusListEntry{Store: store, Kind: "bitstring"})
	h.StatusLists = set
}

// apiGET builds an authenticated GET with an optional {id}/{state}/{jobID} path value.
func apiGET(path, pathKey, pathVal string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer secret")
	if pathKey != "" {
		req.SetPathValue(pathKey, pathVal)
	}
	return req
}

// apiSeedRecord appends one owned record to log and returns it.
func apiSeedRecord(t *testing.T, log issuance.Backend, id, owner string, binding *issuance.StatusListEntry) issuance.IssuedCredential {
	t.Helper()
	rec, err := log.Append(issuance.IssuedCredential{ID: id, SchemaID: "person", SchemaName: "Person", Std: "w3c_vcdm_2", Format: "ldp_vc",
		IssuerDpg: "dpg1", OwnerKey: owner, HolderHint: "Ada", SubjectFields: map[string]string{"name": "Ada"}, OfferURI: "openid-credential-offer://x", StatusList: binding})
	if err != nil {
		t.Fatalf("append %s: %v", id, err)
	}
	return rec
}

func apiBodyErr(t *testing.T, rr *httptest.ResponseRecorder, wantCode int, wantSub string) {
	t.Helper()
	if rr.Code != wantCode {
		t.Fatalf("status = %d, want %d (body=%s)", rr.Code, wantCode, rr.Body.String())
	}
	if msg, _ := decodeJSON(t, rr.Body.Bytes())["error"].(string); !strings.Contains(msg, wantSub) {
		t.Fatalf("error %q does not contain %q", msg, wantSub)
	}
}

func TestParseAPIKeysAndAuthenticate(t *testing.T) {
	m := ParseAPIKeys(" a:1 , ,nocolon, :novalue, b: , c:3:x ")
	if len(m) != 2 || m["a"] != "1" || m["c"] != "3:x" {
		t.Fatalf("parsed = %v", m)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if name, ok := m.Authenticate(req); ok || name != "" {
		t.Fatal("missing header must not authenticate")
	}
	req.Header.Set("Authorization", "Basic xyz")
	if _, ok := m.Authenticate(req); ok {
		t.Fatal("non-bearer must not authenticate")
	}
	req.Header.Set("Authorization", "Bearer wrong")
	if _, ok := m.Authenticate(req); ok {
		t.Fatal("unknown secret must not authenticate")
	}
	req.Header.Set("Authorization", "Bearer 3:x")
	if name, ok := m.Authenticate(req); !ok || name != "c" {
		t.Fatalf("authenticate = %q,%v", name, ok)
	}
}

func TestRequireAPIAuth(t *testing.T) {
	rr := httptest.NewRecorder()
	if _, ok := (&H{}).requireAPIAuth(rr, httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Fatal("no keys must fail")
	}
	apiBodyErr(t, rr, http.StatusServiceUnavailable, "API not enabled")

	h := apiTestH(&testAdapter{})
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer nope")
	if _, ok := h.requireAPIAuth(rr, req); ok {
		t.Fatal("bad key must fail")
	}
	apiBodyErr(t, rr, http.StatusUnauthorized, "invalid or missing API key")
	if rr.Header().Get("WWW-Authenticate") != `Bearer realm="verifiably"` {
		t.Fatalf("WWW-Authenticate = %q", rr.Header().Get("WWW-Authenticate"))
	}
	rr = httptest.NewRecorder()
	if name, ok := h.requireAPIAuth(rr, apiGET("/", "", "")); !ok || name != "test" {
		t.Fatalf("auth = %q,%v", name, ok)
	}
}

func TestAPIRecordIssuance(t *testing.T) {
	schema := vctypes.Schema{ID: "person-sdjwt", Name: "Person", Std: "sd_jwt_vc (IETF)",
		Variants: []vctypes.SchemaVariant{{ID: "person-ldp", Format: "ldp_vc"}, {ID: "person-sdjwt", Format: "vc+sd-jwt"}}}
	if id := (&H{}).apiRecordIssuance("test", schema, "dpg1", "uri", nil, nil); id != "" {
		t.Fatalf("nil log must return empty id, got %q", id)
	}

	log := issuedLog(t)
	h := &H{IssuanceLog: log}
	binding := &backend.StatusListBinding{Type: "token", ListID: "v1", Index: 7}
	id := h.apiRecordIssuance("test", schema, "dpg1", "openid-credential-offer://x", map[string]string{"id": "  ", "given_name": "Ada"}, binding)
	rec, ok := log.Get(id)
	if id == "" || !ok {
		t.Fatalf("record %q not found", id)
	}
	if rec.OwnerKey != "api:test" || rec.HolderHint != "Ada" || rec.Format != "vc+sd-jwt" || rec.IssuerDpg != "dpg1" ||
		rec.StatusList == nil || rec.StatusList.Index != 7 || rec.StatusList.Type != "token" || rec.OfferURI != "openid-credential-offer://x" {
		t.Fatalf("record = %+v", rec)
	}
	plain := h.apiRecordIssuance("test", vctypes.Schema{ID: "x", Std: "w3c_vcdm_2"}, "dpg1", "", map[string]string{"other": "v"}, nil)
	if rec2, _ := log.Get(plain); rec2.HolderHint != "" || rec2.Format != "w3c_vcdm_2" || rec2.StatusList != nil {
		t.Fatalf("plain record = %+v", rec2)
	}

	failing := newLedgerFakeLog()
	failing.appendErr = errors.New("disk full")
	if id := (&H{IssuanceLog: failing}).apiRecordIssuance("test", schema, "dpg1", "", nil, nil); id != "" {
		t.Fatalf("append error must yield empty id, got %q", id)
	}
}

func TestAPIIssue_ValidationAndBackendBranches(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Passport", Std: "w3c_vcdm_2", DPGs: []string{"dpg1"}}
	raw := func(h *H, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/credentials/issue", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		h.APIIssue(rr, req)
		return rr
	}
	post := func(h *H, body map[string]any) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.APIIssue(rr, authPOST(t, "/api/v1/credentials/issue", body))
		return rr
	}
	t.Run("no api keys", func(t *testing.T) {
		rr := httptest.NewRecorder()
		(&H{}).APIIssue(rr, authPOST(t, "/", map[string]any{}))
		apiBodyErr(t, rr, http.StatusServiceUnavailable, "API not enabled")
	})
	t.Run("invalid json", func(t *testing.T) {
		apiBodyErr(t, raw(apiTestH(&testAdapter{}), "{"), http.StatusBadRequest, "invalid JSON")
	})
	t.Run("schema_id required", func(t *testing.T) {
		apiBodyErr(t, post(apiTestH(&testAdapter{}), map[string]any{}), http.StatusBadRequest, "schema_id required")
	})
	t.Run("backend unavailable", func(t *testing.T) {
		apiBodyErr(t, post(apiTestH(&testAdapter{schemasErr: errors.New("down")}), map[string]any{"schema_id": "s1"}), http.StatusServiceUnavailable, "backend unavailable: down")
	})
	t.Run("no issuer dpg", func(t *testing.T) {
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}, issuerDpgs: map[string]vctypes.DPG{}})
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1"}), http.StatusServiceUnavailable, "no issuer DPG available")
		h = apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}, dpgsErr: errors.New("x")})
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1"}), http.StatusServiceUnavailable, "no issuer DPG available")
	})
	t.Run("validity window rejected", func(t *testing.T) {
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}})
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1", "valid_until": "2030-01-01T00:00:00Z"}), http.StatusBadRequest, "does not declare an expiry")
	})
	t.Run("status list allocate error", func(t *testing.T) {
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}})
		apiStatusSet(h, &apiFakeStore{slFakeStore: slFakeStore{id: "v1", allocErr: errors.New("full")}})
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1"}), http.StatusInternalServerError, "status list: status list allocate: full")
	})
	t.Run("success with binding, explicit dpg and audit record", func(t *testing.T) {
		ad := &testAdapter{schemas: []vctypes.Schema{schema}, issueResult: backend.IssueToWalletResult{OfferURI: "openid-credential-offer://ok", PIN: "1234", Flow: "pre_auth"}}
		h := apiTestH(ad)
		h.IssuanceLog = issuedLog(t)
		apiStatusSet(h, &apiFakeStore{slFakeStore: slFakeStore{id: "v1", allocIndex: 9}})
		rr := post(h, map[string]any{"schema_id": "s1", "issuer_dpg": "dpg-explicit", "subject_data": map[string]string{"name": "Ada"}})
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
		}
		out := decodeJSON(t, rr.Body.Bytes())
		sl, _ := out["status_list"].(map[string]any)
		if sl["type"] != "bitstring" || sl["list_id"] != "v1" || sl["index"] != float64(9) || out["pin"] != "1234" {
			t.Fatalf("out = %v", out)
		}
		rec, ok := h.IssuanceLog.Get(out["credential_id"].(string))
		if !ok || rec.IssuerDpg != "dpg-explicit" || rec.StatusList == nil || rec.StatusList.Index != 9 {
			t.Fatalf("audit record = %+v (found=%v)", rec, ok)
		}
	})
}

func TestAPIIssueBulk_Branches(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Passport", Std: "w3c_vcdm_2", DPGs: []string{"dpg1"}}
	post := func(h *H, body any) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.APIIssueBulk(rr, authPOST(t, "/api/v1/credentials/issue/bulk", body))
		return rr
	}
	rows := []map[string]string{{"name": "Ada"}}
	t.Run("auth", func(t *testing.T) {
		rr := httptest.NewRecorder()
		apiTestH(&testAdapter{}).APIIssueBulk(rr, httptest.NewRequest(http.MethodPost, "/", nil))
		apiBodyErr(t, rr, http.StatusUnauthorized, "API key")
	})
	t.Run("rate limited", func(t *testing.T) {
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}})
		h.RateLimiter = &RateLimiter{keyLimit: 1, ipLimit: 1000, byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
		if rr := post(h, map[string]any{"schema_id": "s1", "rows": rows}); rr.Code != http.StatusOK {
			t.Fatalf("first = %d", rr.Code)
		}
		rr := post(h, map[string]any{"schema_id": "s1", "rows": rows})
		apiBodyErr(t, rr, http.StatusTooManyRequests, "rate limit")
		if rr.Header().Get("Retry-After") != "60" {
			t.Fatal("Retry-After missing")
		}
	})
	t.Run("invalid json", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("["))
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		apiTestH(&testAdapter{}).APIIssueBulk(rr, req)
		apiBodyErr(t, rr, http.StatusBadRequest, "invalid JSON")
	})
	t.Run("schema_id and rows required", func(t *testing.T) {
		h := apiTestH(&testAdapter{})
		apiBodyErr(t, post(h, map[string]any{"rows": rows}), http.StatusBadRequest, "schema_id required")
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1"}), http.StatusBadRequest, "rows must not be empty")
	})
	t.Run("backend unavailable / not found / no dpg", func(t *testing.T) {
		apiBodyErr(t, post(apiTestH(&testAdapter{schemasErr: errors.New("down")}), map[string]any{"schema_id": "s1", "rows": rows}), http.StatusServiceUnavailable, "backend unavailable")
		apiBodyErr(t, post(apiTestH(&testAdapter{}), map[string]any{"schema_id": "s1", "rows": rows}), http.StatusNotFound, "schema not found: s1")
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}, issuerDpgs: map[string]vctypes.DPG{}})
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1", "rows": rows}), http.StatusServiceUnavailable, "no issuer DPG")
	})
	t.Run("per-row failures are reported, not fatal", func(t *testing.T) {
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}, issueErr: errors.New("wallet down")})
		apiStatusSet(h, &apiFakeStore{slFakeStore: slFakeStore{id: "v1", allocErr: errors.New("full")}})
		rr := post(h, map[string]any{"schema_id": "s1", "rows": rows})
		out := decodeJSON(t, rr.Body.Bytes())
		r0 := out["rows"].([]any)[0].(map[string]any)
		if rr.Code != http.StatusOK || out["rejected"] != float64(1) || r0["status"] != "failed" || !strings.Contains(r0["error"].(string), "full") {
			t.Fatalf("alloc failure out = %v", out)
		}
		h = apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}, issueErr: errors.New("wallet down")})
		rr = post(h, map[string]any{"schema_id": "s1", "rows": rows})
		out = decodeJSON(t, rr.Body.Bytes())
		r0 = out["rows"].([]any)[0].(map[string]any)
		if out["rejected"] != float64(1) || r0["error"] != "wallet down" || r0["row"] != float64(1) {
			t.Fatalf("issue failure out = %v", out)
		}
	})
	t.Run("success records each row", func(t *testing.T) {
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}, issueResult: backend.IssueToWalletResult{OfferURI: "o", PIN: "p"}})
		h.IssuanceLog = issuedLog(t)
		rr := post(h, map[string]any{"schema_id": "s1", "rows": []map[string]string{{"name": "Ada"}, {"name": "Bob"}}})
		out := decodeJSON(t, rr.Body.Bytes())
		if out["accepted"] != float64(2) || len(h.IssuanceLog.List(issuance.Filter{OwnerKey: "api:test"})) != 2 {
			t.Fatalf("out = %v", out)
		}
		r1 := out["rows"].([]any)[1].(map[string]any)
		if r1["status"] != "issued" || r1["credential_id"] == "" || r1["pin"] != "p" {
			t.Fatalf("row = %v", r1)
		}
	})
}

func TestAPIListAndGetCredential(t *testing.T) {
	h := apiTestH(&testAdapter{})
	rr := httptest.NewRecorder()
	h.APIListCredentials(rr, apiGET("/api/v1/credentials", "", ""))
	apiBodyErr(t, rr, http.StatusServiceUnavailable, "issuance log not configured")
	rr = httptest.NewRecorder()
	h.APIGetCredential(rr, apiGET("/api/v1/credentials/x", "id", "x"))
	apiBodyErr(t, rr, http.StatusServiceUnavailable, "issuance log not configured")
	rr = httptest.NewRecorder()
	h.APIListCredentials(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	apiBodyErr(t, rr, http.StatusUnauthorized, "API key")
	rr = httptest.NewRecorder()
	h.APIGetCredential(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	apiBodyErr(t, rr, http.StatusUnauthorized, "API key")

	log := issuedLog(t)
	h.IssuanceLog = log
	apiSeedRecord(t, log, "vc-mine", "api:test", nil)
	apiSeedRecord(t, log, "vc-revoked", "api:test", &issuance.StatusListEntry{Type: "bitstring", ListID: "v1", Index: 2})
	apiSeedRecord(t, log, "vc-theirs", "api:other", nil)
	if _, err := log.MarkRevoked("vc-revoked", "api:test"); err != nil {
		t.Fatal(err)
	}

	rr = httptest.NewRecorder()
	h.APIListCredentials(rr, apiGET("/api/v1/credentials?q=Ada&state=&std=w3c_vcdm_2&format=ldp_vc", "", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rr.Code, rr.Body.String())
	}
	out := decodeJSON(t, rr.Body.Bytes())
	items := out["items"].([]any)
	if len(items) != 2 || out["total"] != float64(3) || out["revoked"] != float64(1) || out["active"] != float64(2) {
		t.Fatalf("list out = %v", out)
	}
	for _, it := range items {
		if it.(map[string]any)["id"] == "vc-theirs" {
			t.Fatal("foreign record leaked into the owner-scoped list")
		}
	}

	get := func(id string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.APIGetCredential(rr, apiGET("/api/v1/credentials/"+id, "id", id))
		return rr
	}
	apiBodyErr(t, get("missing"), http.StatusNotFound, "credential not found")
	apiBodyErr(t, get("vc-theirs"), http.StatusNotFound, "credential not found")
	rr = get("vc-mine")
	out = decodeJSON(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || out["status"] != "active" || out["holder_hint"] != "Ada" || out["subject_fields"].(map[string]any)["name"] != "Ada" || out["revoked_at"] != nil {
		t.Fatalf("get active = %v", out)
	}
	out = decodeJSON(t, get("vc-revoked").Body.Bytes())
	if out["status"] != "revoked" || out["revoked_at"] == nil || out["status_list"].(map[string]any)["index"] != float64(2) {
		t.Fatalf("get revoked = %v", out)
	}
}

func TestAPIRevokeAndReinstate(t *testing.T) {
	binding := &issuance.StatusListEntry{Type: "bitstring", ListID: "v1", Index: 4}
	call := func(h *H, fn func(http.ResponseWriter, *http.Request), id string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := authPOST(t, "/api/v1/credentials/"+id+"/x", nil)
		req.SetPathValue("id", id)
		fn(rr, req)
		return rr
	}
	for name, pick := range map[string]func(h *H) func(http.ResponseWriter, *http.Request){
		"revoke":    func(h *H) func(http.ResponseWriter, *http.Request) { return h.APIRevoke },
		"reinstate": func(h *H) func(http.ResponseWriter, *http.Request) { return h.APIReinstate },
	} {
		t.Run(name, func(t *testing.T) {
			h := apiTestH(&testAdapter{})
			rr := httptest.NewRecorder()
			pick(h)(rr, httptest.NewRequest(http.MethodPost, "/", nil))
			apiBodyErr(t, rr, http.StatusUnauthorized, "API key")
			apiBodyErr(t, call(h, pick(h), "x"), http.StatusServiceUnavailable, "issuance log not configured")

			log := issuedLog(t)
			h.IssuanceLog = log
			apiSeedRecord(t, log, "vc-theirs", "api:other", binding)
			apiSeedRecord(t, log, "vc-plain", "api:test", nil)
			apiSeedRecord(t, log, "vc-bound", "api:test", binding)
			apiBodyErr(t, call(h, pick(h), "missing"), http.StatusNotFound, "credential not found")
			apiBodyErr(t, call(h, pick(h), "vc-theirs"), http.StatusNotFound, "credential not found")
			apiBodyErr(t, call(h, pick(h), "vc-plain"), http.StatusUnprocessableEntity, "no status list binding")
			apiBodyErr(t, call(h, pick(h), "vc-bound"), http.StatusServiceUnavailable, "status list store not configured")

			store := &apiFakeStore{slFakeStore: slFakeStore{id: "v1", revokeErr: errors.New("io")}, reinstateErr: errors.New("io")}
			apiStatusSet(h, store)
			apiBodyErr(t, call(h, pick(h), "vc-bound"), http.StatusInternalServerError, name+": io")
			store.revokeErr, store.reinstateErr = nil, nil

			fake := newLedgerFakeLog()
			fake.items["vc-bound"] = issuance.IssuedCredential{ID: "vc-bound", OwnerKey: "api:test", StatusList: binding}
			fake.markErr = errors.New("chain")
			h.IssuanceLog = fake
			apiBodyErr(t, call(h, pick(h), "vc-bound"), http.StatusInternalServerError, map[string]string{"revoke": "mark revoked: chain", "reinstate": "mark reinstate: chain"}[name])
			h.IssuanceLog = log

			rr = call(h, pick(h), "vc-bound")
			out := decodeJSON(t, rr.Body.Bytes())
			if rr.Code != http.StatusOK || out["id"] != "vc-bound" {
				t.Fatalf("%s = %d %v", name, rr.Code, out)
			}
			rec, _ := log.Get("vc-bound")
			if name == "revoke" {
				if out["status"] != "revoked" || out["revoked_at"] == nil || rec.RevokedAt == nil || len(store.revoked) != 3 || store.revoked[2] != 4 {
					t.Fatalf("revoke out=%v rec=%+v store=%+v", out, rec, store.revoked)
				}
			} else {
				if out["status"] != "active" || out["revoked_at"] != nil || rec.RevokedAt != nil || len(store.reinstated) != 3 || store.reinstated[2] != 4 {
					t.Fatalf("reinstate out=%v rec=%+v store=%+v", out, rec, store.reinstated)
				}
			}
		})
	}
	if s := (&H{}).reinstateStoreForBinding("", ""); s != nil {
		t.Fatal("empty kind must resolve no store")
	}
}

func TestAPIVerifyRequest_Branches(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Passport", Std: "sd_jwt_vc (IETF)", FieldsSpec: []vctypes.FieldSpec{{Name: "name"}}}
	post := func(h *H, body any) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.APIVerifyRequest(rr, authPOST(t, "/api/v1/verify/request", body))
		return rr
	}
	rr := httptest.NewRecorder()
	apiTestH(&testAdapter{}).APIVerifyRequest(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	apiBodyErr(t, rr, http.StatusUnauthorized, "API key")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("nope"))
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	apiTestH(&testAdapter{}).APIVerifyRequest(rr, req)
	apiBodyErr(t, rr, http.StatusBadRequest, "invalid JSON")
	apiBodyErr(t, post(apiTestH(&testAdapter{}), map[string]any{}), http.StatusBadRequest, "schema_id or template required")
	apiBodyErr(t, post(apiTestH(&testAdapter{verifierDpgs: map[string]vctypes.DPG{}}), map[string]any{"schema_id": "s1"}), http.StatusServiceUnavailable, "no verifier DPG")
	apiBodyErr(t, post(apiTestH(&testAdapter{schemasErr: errors.New("down")}), map[string]any{"schema_id": "s1"}), http.StatusServiceUnavailable, "backend unavailable")
	apiBodyErr(t, post(apiTestH(&testAdapter{}), map[string]any{"schema_id": "s1"}), http.StatusNotFound, "schema not found: s1")

	ad := &testAdapter{schemas: []vctypes.Schema{schema}, verifyResult: backend.PresentationRequestResult{RequestURI: "openid4vp://x", State: "st"}}
	rr = post(apiTestH(ad), map[string]any{"schema_id": "s1", "verifier_dpg": "v-explicit", "fields": []string{"name"}})
	if rr.Code != http.StatusOK || decodeJSON(t, rr.Body.Bytes())["state"] != "st" {
		t.Fatalf("explicit fields = %d %s", rr.Code, rr.Body.String())
	}
	tplAd := &testAdapter{verifyResult: backend.PresentationRequestResult{RequestURI: "openid4vp://t", State: "tpl"}}
	rr = post(apiTestH(tplAd), map[string]any{"template": map[string]any{"title": "Custom", "fields": []string{"a"}}})
	if rr.Code != http.StatusOK || decodeJSON(t, rr.Body.Bytes())["request_uri"] != "openid4vp://t" {
		t.Fatalf("template path = %d %s", rr.Code, rr.Body.String())
	}
}

func TestAPIVerifyResult(t *testing.T) {
	get := func(h *H, state string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/verify/result/"+state, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer secret")
		}
		req.SetPathValue("state", state)
		rr := httptest.NewRecorder()
		h.APIVerifyResult(rr, req)
		return rr
	}
	apiBodyErr(t, get(apiTestH(&testAdapter{}), "s", false), http.StatusUnauthorized, "API key")
	apiBodyErr(t, get(apiTestH(&testAdapter{}), "", true), http.StatusBadRequest, "state required")
	apiBodyErr(t, get(apiTestH(&testAdapter{fetchErr: errors.New("gone")}), "s", true), http.StatusBadGateway, "gone")

	cases := []struct {
		res    backend.VerificationResult
		status string
	}{
		{backend.VerificationResult{Pending: true}, "pending"},
		{backend.VerificationResult{Valid: true, Method: "OID4VP", Format: "sd_jwt_vc (IETF)", Issuer: "did:example:issuer", DisclosedFields: map[string]string{"name": "Ada"}}, "verified"},
		{backend.VerificationResult{Valid: false}, "failed"},
	}
	for _, c := range cases {
		ad := &testAdapter{fetchResult: c.res}
		rr := get(apiTestH(ad), "state-1", true)
		out := decodeJSON(t, rr.Body.Bytes())
		if rr.Code != http.StatusOK || out["status"] != c.status || out["valid"] != c.res.Valid || out["pending"] != c.res.Pending {
			t.Fatalf("%s: %d %v", c.status, rr.Code, out)
		}
		if len(ad.fetchStates) != 1 || ad.fetchStates[0] != "state-1" {
			t.Fatalf("fetch states = %v", ad.fetchStates)
		}
		if c.status == "verified" && (out["issuer"] != "did:example:issuer" || out["disclosed"].(map[string]any)["name"] != "Ada" || out["checked_at"] == nil) {
			t.Fatalf("verified payload = %v", out)
		}
	}
}

// apiQueue builds an in-memory jobs.Queue with the given worker count that is
// shut down when the test ends.
func apiQueue(t *testing.T, workers int) (*jobs.Queue, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return jobs.NewQueue(ctx, nil, workers), cancel
}

// apiWaitJob drains sub until the job reaches a terminal status.
func apiWaitJob(t *testing.T, sub <-chan jobs.Progress) jobs.Progress {
	t.Helper()
	for p := range sub {
		if p.Status == jobs.StatusDone || p.Status == jobs.StatusError {
			return p
		}
	}
	t.Fatal("subscription closed before the job finished")
	return jobs.Progress{}
}

func TestAPIIssueBulkAsync(t *testing.T) {
	schema := vctypes.Schema{ID: "s1", Name: "Passport", Std: "w3c_vcdm_2", DPGs: []string{"dpg1"}}
	rows := []map[string]string{{"name": "Ada"}, {"name": "Bob"}}
	post := func(h *H, body any) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.APIIssueBulkAsync(rr, authPOST(t, "/api/v1/credentials/issue/bulk/async", body))
		return rr
	}
	t.Run("auth and queue guards", func(t *testing.T) {
		h := apiTestH(&testAdapter{})
		rr := httptest.NewRecorder()
		h.APIIssueBulkAsync(rr, httptest.NewRequest(http.MethodPost, "/", nil))
		apiBodyErr(t, rr, http.StatusUnauthorized, "API key")
		apiBodyErr(t, post(h, map[string]any{}), http.StatusServiceUnavailable, "async bulk queue not configured")
	})
	t.Run("validation", func(t *testing.T) {
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}, issuerDpgs: map[string]vctypes.DPG{}})
		h.BulkJobQueue, _ = apiQueue(t, 0)
		h.RateLimiter = &RateLimiter{keyLimit: 0, ipLimit: 0, byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
		rr := post(h, map[string]any{"schema_id": "s1", "rows": rows})
		apiBodyErr(t, rr, http.StatusTooManyRequests, "rate limit")
		if rr.Header().Get("Retry-After") != "60" {
			t.Fatal("Retry-After missing")
		}
		h.RateLimiter = nil
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{"))
		req.Header.Set("Authorization", "Bearer secret")
		rr = httptest.NewRecorder()
		h.APIIssueBulkAsync(rr, req)
		apiBodyErr(t, rr, http.StatusBadRequest, "invalid JSON")
		apiBodyErr(t, post(h, map[string]any{"rows": rows}), http.StatusBadRequest, "schema_id required")
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1"}), http.StatusBadRequest, "rows must not be empty")
		big := make([]map[string]string, maxBulkRows+1)
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1", "rows": big}), http.StatusRequestEntityTooLarge, "rows exceeds limit")
		apiBodyErr(t, post(h, map[string]any{"schema_id": "zz", "rows": rows}), http.StatusNotFound, "schema not found: zz")
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1", "rows": rows}), http.StatusServiceUnavailable, "no issuer DPG")
		h2 := apiTestH(&testAdapter{schemasErr: errors.New("down")})
		h2.BulkJobQueue = h.BulkJobQueue
		apiBodyErr(t, post(h2, map[string]any{"schema_id": "s1", "rows": rows}), http.StatusServiceUnavailable, "backend unavailable")
	})
	t.Run("queue full", func(t *testing.T) {
		h := apiTestH(&testAdapter{schemas: []vctypes.Schema{schema}})
		q, _ := apiQueue(t, 0) // no workers: 256 pending slots then Submit fails
		for i := 0; i < 256; i++ {
			if _, err := q.Submit(context.Background(), jobs.Rows{{}}, func(context.Context, map[string]string) error { return nil }); err != nil {
				t.Fatalf("prefill %d: %v", i, err)
			}
		}
		h.BulkJobQueue = q
		apiBodyErr(t, post(h, map[string]any{"schema_id": "s1", "rows": rows}), http.StatusInternalServerError, "submit job: jobs: queue full")
	})
	t.Run("accepted and processed", func(t *testing.T) {
		ad := &testAdapter{schemas: []vctypes.Schema{schema}, issueResult: backend.IssueToWalletResult{OfferURI: "o"}}
		h := apiTestH(ad)
		h.IssuanceLog = issuedLog(t)
		store := &apiFakeStore{slFakeStore: slFakeStore{id: "v1"}}
		apiStatusSet(h, store)
		h.BulkJobQueue, _ = apiQueue(t, 0)
		rr := post(h, map[string]any{"schema_id": "s1", "rows": rows})
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d %s", rr.Code, rr.Body.String())
		}
		out := decodeJSON(t, rr.Body.Bytes())
		jobID, _ := out["job_id"].(string)
		if jobID == "" || out["total"] != float64(2) || out["status_url"] != "/api/v1/bulk/"+jobID || out["events_url"] != "/api/v1/bulk/"+jobID+"/events" {
			t.Fatalf("out = %v", out)
		}
		job, found := h.BulkJobQueue.Status(context.Background(), jobID)
		if !found || job.Status != jobs.StatusPending {
			t.Fatalf("job = %+v", job)
		}

		// Now run the work function through a queue that has a worker: row 1
		// issues, row 2 fails at allocation (never reaches the adapter), row 3
		// fails at the wallet. issueGate makes each adapter call a sync point.
		q, _ := apiQueue(t, 1)
		h.BulkJobQueue = q
		gate := make(chan struct{})
		ad.issueGate = gate
		ad.issueFailOn = 2
		store.allocFailOn = 2
		rows3 := []map[string]string{{"name": "Ada"}, {"name": "Bob"}, {"name": "Cy"}}
		rr = post(h, map[string]any{"schema_id": "s1", "rows": rows3})
		jobID = decodeJSON(t, rr.Body.Bytes())["job_id"].(string)
		sub := q.Subscribe(context.Background(), jobID)
		gate <- struct{}{} // row 1
		gate <- struct{}{} // row 3
		p := apiWaitJob(t, sub)
		if p.Status != jobs.StatusDone || p.Done != 3 || p.Errors != 2 {
			t.Fatalf("progress = %+v", p)
		}
		if got := h.IssuanceLog.List(issuance.Filter{OwnerKey: "api:test"}); len(got) != 1 || got[0].SubjectFields["name"] != "Ada" || got[0].StatusList == nil {
			t.Fatalf("audit records = %+v", got)
		}
		if atomic.LoadInt32(&ad.issueCalls) != 2 || store.allocCalls != 3 {
			t.Fatalf("issue calls = %d, alloc calls = %d", ad.issueCalls, store.allocCalls)
		}
	})
}

func TestAPIBulkJobStatus(t *testing.T) {
	get := func(h *H, jobID string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/bulk/"+jobID, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer secret")
		}
		req.SetPathValue("jobID", jobID)
		rr := httptest.NewRecorder()
		h.APIBulkJobStatus(rr, req)
		return rr
	}
	h := apiTestH(&testAdapter{})
	apiBodyErr(t, get(h, "j", false), http.StatusUnauthorized, "API key")
	apiBodyErr(t, get(h, "j", true), http.StatusServiceUnavailable, "async bulk queue not configured")
	q, _ := apiQueue(t, 0)
	h.BulkJobQueue = q
	apiBodyErr(t, get(h, "", true), http.StatusBadRequest, "jobID required")
	apiBodyErr(t, get(h, "nope", true), http.StatusNotFound, "job not found: nope")
	id, err := q.Submit(context.Background(), jobs.Rows{{}, {}}, func(context.Context, map[string]string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	rr := get(h, id, true)
	out := decodeJSON(t, rr.Body.Bytes())
	if rr.Code != http.StatusOK || out["job_id"] != id || out["status"] != jobs.StatusPending || out["total"] != float64(2) || out["done"] != float64(0) || out["created_at"] == nil {
		t.Fatalf("status = %d %v", rr.Code, out)
	}
}

// apiNoFlush hides the recorder's Flush so the handler sees a non-streaming writer.
type apiNoFlush struct{ http.ResponseWriter }

// apiSSEWriter records the stream and counts flushes.
type apiSSEWriter struct {
	*httptest.ResponseRecorder
	flushes int
}

func (w *apiSSEWriter) Flush() {
	w.flushes++
	w.ResponseRecorder.Flush()
}

// apiCtxProbe closes probed the first time Done is called. The events handler
// hands the request context to Queue.Subscribe, whose cleanup goroutine calls
// Done only after the subscriber channel is registered — so probed is a
// deterministic "handler has subscribed" signal, no sleeps or polling.
type apiCtxProbe struct {
	context.Context
	once   sync.Once
	probed chan struct{}
}

func (c *apiCtxProbe) Done() <-chan struct{} {
	c.once.Do(func() { close(c.probed) })
	return c.Context.Done()
}

func apiSSEEvents(body string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "data: ") {
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m); err == nil {
				out = append(out, m)
			}
		}
	}
	return out
}

func TestAPIBulkJobEvents(t *testing.T) {
	newReq := func(ctx context.Context, jobID string, auth bool) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/bulk/"+jobID+"/events", nil).WithContext(ctx)
		if auth {
			req.Header.Set("Authorization", "Bearer secret")
		}
		req.SetPathValue("jobID", jobID)
		return req
	}
	bg := context.Background()
	h := apiTestH(&testAdapter{})
	rr := httptest.NewRecorder()
	h.APIBulkJobEvents(rr, newReq(bg, "j", false))
	apiBodyErr(t, rr, http.StatusUnauthorized, "API key")
	rr = httptest.NewRecorder()
	h.APIBulkJobEvents(rr, newReq(bg, "j", true))
	apiBodyErr(t, rr, http.StatusServiceUnavailable, "async bulk queue not configured")

	t.Run("guards and terminal snapshot", func(t *testing.T) {
		q, cancelQ := apiQueue(t, 1)
		h.BulkJobQueue = q
		rr := httptest.NewRecorder()
		h.APIBulkJobEvents(rr, newReq(bg, "", true))
		apiBodyErr(t, rr, http.StatusBadRequest, "jobID required")
		rr = httptest.NewRecorder()
		h.APIBulkJobEvents(rr, newReq(bg, "nope", true))
		apiBodyErr(t, rr, http.StatusNotFound, "job not found: nope")

		// Finished job: one terminal event, stream closes immediately.
		gate := make(chan struct{})
		work := func(context.Context, map[string]string) error { <-gate; return nil }
		id, err := q.Submit(bg, jobs.Rows{{}}, work)
		if err != nil {
			t.Fatal(err)
		}
		sub := q.Subscribe(bg, id)
		close(gate)
		if p := apiWaitJob(t, sub); p.Status != jobs.StatusDone {
			t.Fatalf("progress = %+v", p)
		}
		rr = httptest.NewRecorder()
		h.APIBulkJobEvents(apiNoFlush{rr}, newReq(bg, id, true))
		apiBodyErr(t, rr, http.StatusInternalServerError, "streaming not supported")
		rr = httptest.NewRecorder()
		h.APIBulkJobEvents(rr, newReq(bg, id, true))
		ev := apiSSEEvents(rr.Body.String())
		if rr.Header().Get("Content-Type") != "text/event-stream" || len(ev) != 1 || ev[0]["status"] != jobs.StatusDone || ev[0]["done"] != float64(1) || ev[0]["job_id"] != id {
			t.Fatalf("terminal stream: ct=%q events=%v", rr.Header().Get("Content-Type"), ev)
		}

		// Errored job (queue shut down mid-run) is also terminal.
		gate2 := make(chan struct{})
		id2, err := q.Submit(bg, jobs.Rows{{}, {}}, func(context.Context, map[string]string) error { <-gate2; return nil })
		if err != nil {
			t.Fatal(err)
		}
		sub2 := q.Subscribe(bg, id2)
		cancelQ()
		close(gate2)
		if p := apiWaitJob(t, sub2); p.Status != jobs.StatusError {
			t.Fatalf("progress = %+v", p)
		}
		rr = httptest.NewRecorder()
		h.APIBulkJobEvents(rr, newReq(bg, id2, true))
		if ev := apiSSEEvents(rr.Body.String()); len(ev) != 1 || ev[0]["status"] != jobs.StatusError {
			t.Fatalf("error stream events = %v", ev)
		}
	})

	t.Run("live stream until done", func(t *testing.T) {
		q, _ := apiQueue(t, 1)
		h.BulkJobQueue = q
		const total = 3
		gate := make(chan struct{})
		entered := make(chan struct{}, 1)
		work := func(context.Context, map[string]string) error {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-gate
			return nil
		}
		id, err := q.Submit(bg, make(jobs.Rows, total), work)
		if err != nil {
			t.Fatal(err)
		}
		<-entered // worker is inside row 0: the job is "running", not terminal
		probe := &apiCtxProbe{Context: bg, probed: make(chan struct{})}
		w := &apiSSEWriter{ResponseRecorder: httptest.NewRecorder()}
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.APIBulkJobEvents(w, newReq(probe, id, true))
		}()
		<-probe.probed // Subscribe registered its channel: every later broadcast is delivered
		close(gate)    // all rows run through to the terminal event
		<-done
		ev := apiSSEEvents(w.Body.String())
		if len(ev) != total+1 || ev[len(ev)-1]["status"] != jobs.StatusDone || ev[len(ev)-1]["done"] != float64(total) || w.flushes != total+1 {
			t.Fatalf("events = %v (flushes=%d)", ev, w.flushes)
		}
		for i, e := range ev {
			if e["job_id"] != id || e["done"] != float64(min(i+1, total)) {
				t.Fatalf("event %d = %v", i, e)
			}
		}
	})

	t.Run("client disconnect closes the stream", func(t *testing.T) {
		q, _ := apiQueue(t, 0) // never runs: job stays pending
		h.BulkJobQueue = q
		id, err := q.Submit(bg, jobs.Rows{{}}, func(context.Context, map[string]string) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(bg)
		cancel()
		rr := httptest.NewRecorder()
		h.APIBulkJobEvents(rr, newReq(ctx, id, true))
		if rr.Code != http.StatusOK || len(apiSSEEvents(rr.Body.String())) != 0 || rr.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("disconnect: code=%d body=%q", rr.Code, rr.Body.String())
		}
	})
}
