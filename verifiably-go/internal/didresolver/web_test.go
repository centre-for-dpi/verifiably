package didresolver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ── didWebToURL ───────────────────────────────────────────────────────────────

func TestDIDWebToURL_WellKnown(t *testing.T) {
	got := didWebToURL("did:web:example.com")
	want := "https://example.com/.well-known/did.json"
	if got != want {
		t.Errorf("didWebToURL = %q, want %q", got, want)
	}
}

func TestDIDWebToURL_PathComponent(t *testing.T) {
	got := didWebToURL("did:web:example.com:path:to")
	want := "https://example.com/path/to/did.json"
	if got != want {
		t.Errorf("didWebToURL = %q, want %q", got, want)
	}
}

func TestDIDWebToURL_SinglePathSegment(t *testing.T) {
	got := didWebToURL("did:web:example.com:users")
	want := "https://example.com/users/did.json"
	if got != want {
		t.Errorf("didWebToURL = %q, want %q", got, want)
	}
}

// ── mock transport ────────────────────────────────────────────────────────────

type mockTransport struct {
	body      string
	status    int
	callCount int
	err       error
}

func (t *mockTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	t.callCount++
	if t.err != nil {
		return nil, t.err
	}
	return &http.Response{
		StatusCode: t.status,
		Body:       io.NopCloser(strings.NewReader(t.body)),
		Header:     make(http.Header),
	}, nil
}

func resolverWith(body string, status int) (*WebResolver, *mockTransport) {
	tr := &mockTransport{body: body, status: status}
	r := NewWebResolver()
	r.client = &http.Client{Transport: tr}
	r.cacheTTL = 0 // zero TTL = no caching unless test explicitly opts in
	return r, tr
}

var sampleDIDDoc = `{
  "id": "did:web:example.com",
  "verificationMethod": [{
    "id": "did:web:example.com#key-1",
    "type": "JsonWebKey2020",
    "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"abc","y":"def"}
  }]
}`

// ── WebResolver.Resolve ───────────────────────────────────────────────────────

func TestResolve_Success(t *testing.T) {
	r, _ := resolverWith(sampleDIDDoc, http.StatusOK)

	doc, err := r.Resolve(context.Background(), "did:web:example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if doc.ID != "did:web:example.com" {
		t.Errorf("doc.ID = %q", doc.ID)
	}
	if len(doc.VerificationMethods) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(doc.VerificationMethods))
	}
	if doc.VerificationMethods[0].Type != "JsonWebKey2020" {
		t.Errorf("VM Type = %q", doc.VerificationMethods[0].Type)
	}
	if doc.VerificationMethods[0].PublicKeyJWK["kty"] != "EC" {
		t.Errorf("PublicKeyJWK.kty = %v", doc.VerificationMethods[0].PublicKeyJWK["kty"])
	}
}

func TestResolve_NotFound(t *testing.T) {
	r, _ := resolverWith("", http.StatusNotFound)
	_, err := r.Resolve(context.Background(), "did:web:example.com")
	if err == nil {
		t.Fatal("Resolve on 404 should return error")
	}
}

func TestResolve_UnsupportedMethod(t *testing.T) {
	r := NewWebResolver()
	_, err := r.Resolve(context.Background(), "did:key:abc123")
	if err == nil {
		t.Fatal("Resolve should error on non-did:web DID")
	}
}

func TestResolve_NetworkError(t *testing.T) {
	tr := &mockTransport{err: errors.New("connection refused")}
	r := NewWebResolver()
	r.client = &http.Client{Transport: tr}
	r.cacheTTL = 0

	_, err := r.Resolve(context.Background(), "did:web:example.com")
	if err == nil {
		t.Fatal("Resolve should propagate network error")
	}
}

func TestResolve_InvalidJSON(t *testing.T) {
	r, _ := resolverWith("not json at all", http.StatusOK)
	_, err := r.Resolve(context.Background(), "did:web:example.com")
	if err == nil {
		t.Fatal("Resolve should error on invalid JSON body")
	}
}

func TestResolve_CacheHit(t *testing.T) {
	tr := &mockTransport{body: sampleDIDDoc, status: http.StatusOK}
	r := NewWebResolver()
	r.client = &http.Client{Transport: tr}
	// Use default cacheTTL (10 min) so second call hits cache.

	_, _ = r.Resolve(context.Background(), "did:web:example.com")
	_, _ = r.Resolve(context.Background(), "did:web:example.com")

	if tr.callCount != 1 {
		t.Errorf("expected 1 HTTP call with cache enabled, got %d", tr.callCount)
	}
}

func TestResolve_CacheMissZeroTTL(t *testing.T) {
	r, tr := resolverWith(sampleDIDDoc, http.StatusOK)
	// cacheTTL is 0 (set by resolverWith) → every call is a cache miss.
	_, _ = r.Resolve(context.Background(), "did:web:example.com")
	_, _ = r.Resolve(context.Background(), "did:web:example.com")

	if tr.callCount != 2 {
		t.Errorf("expected 2 HTTP calls with zero TTL, got %d", tr.callCount)
	}
}

func TestResolve_CacheSeparateByDID(t *testing.T) {
	tr := &mockTransport{body: sampleDIDDoc, status: http.StatusOK}
	r := NewWebResolver()
	r.client = &http.Client{Transport: tr}

	_, _ = r.Resolve(context.Background(), "did:web:a.example.com")
	_, _ = r.Resolve(context.Background(), "did:web:b.example.com")

	if tr.callCount != 2 {
		t.Errorf("different DIDs should each make their own HTTP call, got %d", tr.callCount)
	}
}

func TestResolve_EmptyVerificationMethods(t *testing.T) {
	r, _ := resolverWith(`{"id":"did:web:empty.com"}`, http.StatusOK)
	doc, err := r.Resolve(context.Background(), "did:web:empty.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(doc.VerificationMethods) != 0 {
		t.Errorf("expected 0 VMs for DID doc with no verificationMethod field")
	}
}
