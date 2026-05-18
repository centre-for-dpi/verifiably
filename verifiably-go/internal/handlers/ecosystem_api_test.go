package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/trust"
	"github.com/verifiably/verifiably-go/internal/verification"
)

// ── mock APIKeyStore ──────────────────────────────────────────────────────────

type mockAPIKeyStore struct {
	keys map[string]string // token → did
}

func newMockAPIKeyStore(pairs ...string) *mockAPIKeyStore {
	m := &mockAPIKeyStore{keys: make(map[string]string)}
	for i := 0; i+1 < len(pairs); i += 2 {
		m.keys[pairs[i]] = pairs[i+1]
	}
	return m
}

func (s *mockAPIKeyStore) Issue(_ context.Context, did string) (string, error) {
	return "token-for-" + did, nil
}
func (s *mockAPIKeyStore) Validate(_ context.Context, key string) (string, error) {
	did, ok := s.keys[key]
	if !ok {
		return "", trust.ErrInvalidAPIKey
	}
	return did, nil
}
func (s *mockAPIKeyStore) Revoke(_ context.Context, _ string) error { return nil }
func (s *mockAPIKeyStore) HasKey(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// ── mock verification.Log ─────────────────────────────────────────────────────

type mockVerificationLog struct {
	events []verification.Event
	err    error
}

func (l *mockVerificationLog) Append(_ context.Context, e verification.Event) error {
	l.events = append(l.events, e)
	return nil
}
func (l *mockVerificationLog) QueryByIssuer(_ context.Context, issuerDID string, _ time.Duration) ([]verification.Event, error) {
	if l.err != nil {
		return nil, l.err
	}
	var out []verification.Event
	for _, e := range l.events {
		if e.IssuerDID == issuerDID {
			out = append(out, e)
		}
	}
	return out, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func ecosystemH(store trust.APIKeyStore, log verification.Log) *H {
	return &H{
		IssuerAPIKeyStore: store,
		VerificationLog:   log,
	}
}

func bearerRequest(t *testing.T, did, token string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/ecosystem/issuers/"+did+"/stats", nil)
	req.SetPathValue("did", did)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestGetEcosystemIssuerStats_NoAPIKeyStore(t *testing.T) {
	h := ecosystemH(nil, &mockVerificationLog{})
	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "token"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestGetEcosystemIssuerStats_NoVerificationLog(t *testing.T) {
	h := ecosystemH(newMockAPIKeyStore("tok", "did:web:a.gov"), nil)
	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "tok"))
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rr.Code)
	}
}

func TestGetEcosystemIssuerStats_MissingAuthHeader(t *testing.T) {
	h := ecosystemH(newMockAPIKeyStore(), &mockVerificationLog{})
	req := httptest.NewRequest(http.MethodGet, "/api/ecosystem/issuers/did:web:a.gov/stats", nil)
	req.SetPathValue("did", "did:web:a.gov")
	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header on 401")
	}
}

func TestGetEcosystemIssuerStats_InvalidKey(t *testing.T) {
	h := ecosystemH(newMockAPIKeyStore(), &mockVerificationLog{})
	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "bad-token"))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestGetEcosystemIssuerStats_WrongDID(t *testing.T) {
	// Key belongs to did:web:a.gov but path says did:web:b.gov.
	h := ecosystemH(
		newMockAPIKeyStore("tok-a", "did:web:a.gov"),
		&mockVerificationLog{},
	)
	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:b.gov", "tok-a"))
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rr.Code)
	}
}

func TestGetEcosystemIssuerStats_EmptyLog(t *testing.T) {
	h := ecosystemH(
		newMockAPIKeyStore("tok", "did:web:a.gov"),
		&mockVerificationLog{},
	)
	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "tok"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out["issuer_did"] != "did:web:a.gov" {
		t.Errorf("issuer_did = %v", out["issuer_did"])
	}
	verified := out["verified"].(map[string]any)
	if verified["total"] != float64(0) {
		t.Errorf("verified.total = %v, want 0", verified["total"])
	}
}

func TestGetEcosystemIssuerStats_Aggregation(t *testing.T) {
	log := &mockVerificationLog{
		events: []verification.Event{
			{IssuerDID: "did:web:a.gov", SchemaName: "DNI", Status: "valid", VerifiedAt: time.Now()},
			{IssuerDID: "did:web:a.gov", SchemaName: "DNI", Status: "valid", VerifiedAt: time.Now()},
			{IssuerDID: "did:web:a.gov", SchemaName: "DNI", Status: "invalid", VerifiedAt: time.Now()},
			{IssuerDID: "did:web:a.gov", SchemaName: "Passport", Status: "valid", VerifiedAt: time.Now()},
		},
	}
	h := ecosystemH(newMockAPIKeyStore("tok", "did:web:a.gov"), log)

	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "tok"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	verified := out["verified"].(map[string]any)
	if verified["total"] != float64(4) {
		t.Errorf("total = %v, want 4", verified["total"])
	}
	if verified["valid"] != float64(3) {
		t.Errorf("valid = %v, want 3", verified["valid"])
	}
	if verified["invalid"] != float64(1) {
		t.Errorf("invalid = %v, want 1", verified["invalid"])
	}

	bySchema := verified["by_schema"].([]any)
	if len(bySchema) != 2 {
		t.Fatalf("by_schema: expected 2 entries, got %d", len(bySchema))
	}
	// First entry should be DNI (total 3) due to insertion-sort desc.
	first := bySchema[0].(map[string]any)
	if first["schema"] != "DNI" {
		t.Errorf("by_schema[0].schema = %v, want DNI (highest total)", first["schema"])
	}
	if first["total"] != float64(3) {
		t.Errorf("by_schema[0].total = %v, want 3", first["total"])
	}
}

func TestGetEcosystemIssuerStats_PeriodDaysField(t *testing.T) {
	h := ecosystemH(
		newMockAPIKeyStore("tok", "did:web:a.gov"),
		&mockVerificationLog{},
	)
	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "tok"))

	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["period_days"] != float64(30) {
		t.Errorf("period_days = %v, want 30", out["period_days"])
	}
}

func TestGetEcosystemIssuerStats_SchemaFallbackToID(t *testing.T) {
	// When SchemaName is empty, SchemaID should be used as label.
	log := &mockVerificationLog{
		events: []verification.Event{
			{IssuerDID: "did:web:a.gov", SchemaID: "s-123", Status: "valid", VerifiedAt: time.Now()},
		},
	}
	h := ecosystemH(newMockAPIKeyStore("tok", "did:web:a.gov"), log)

	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "tok"))

	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	bySchema := out["verified"].(map[string]any)["by_schema"].([]any)
	first := bySchema[0].(map[string]any)
	if first["schema"] != "s-123" {
		t.Errorf("schema label = %v, want s-123 (fallback to SchemaID)", first["schema"])
	}
}

func TestGetEcosystemIssuerStats_SchemaFallbackToUnknown(t *testing.T) {
	// When both SchemaName and SchemaID are empty, "unknown" should be used.
	log := &mockVerificationLog{
		events: []verification.Event{
			{IssuerDID: "did:web:a.gov", Status: "valid", VerifiedAt: time.Now()},
		},
	}
	h := ecosystemH(newMockAPIKeyStore("tok", "did:web:a.gov"), log)

	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "tok"))

	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	bySchema := out["verified"].(map[string]any)["by_schema"].([]any)
	first := bySchema[0].(map[string]any)
	if first["schema"] != "unknown" {
		t.Errorf("schema label = %v, want unknown", first["schema"])
	}
}

func TestGetEcosystemIssuerStats_QueryError(t *testing.T) {
	log := &mockVerificationLog{err: errors.New("db timeout")}
	h := ecosystemH(newMockAPIKeyStore("tok", "did:web:a.gov"), log)

	rr := httptest.NewRecorder()
	h.GetEcosystemIssuerStats(rr, bearerRequest(t, "did:web:a.gov", "tok"))
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}
