package credentialcache

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/trust"
)

// fakeRegistry is a minimal trust.Registry returning a fixed issuer list.
type fakeRegistry struct{ issuers []trust.TrustedIssuer }

func (f fakeRegistry) TrustedIssuers(context.Context) ([]trust.TrustedIssuer, error) {
	return f.issuers, nil
}
func (f fakeRegistry) IsTrusted(context.Context, string, string) error { return nil }
func (f fakeRegistry) Add(context.Context, trust.TrustedIssuer) error  { return nil }
func (f fakeRegistry) Remove(context.Context, string) error            { return nil }

// memberServer stands in for a federation member's well-known endpoint.
func memberServer(t *testing.T, meta backend.IssuerMetadata, status int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(meta)
	})
	return httptest.NewServer(mux)
}

func TestFetchIssuer_MapsMetadataToCatalogEntry(t *testing.T) {
	srv := memberServer(t, backend.IssuerMetadata{
		CredentialIssuer: srvURL("ignored-by-hub"),
		CredentialsSupported: []backend.CredentialConfig{
			{ID: "PersonCredential", Format: "jwt_vc_json", Display: "Person"},
		},
	}, http.StatusOK)
	defer srv.Close()

	a := NewAggregator(time.Minute)
	entry, ok := a.fetchIssuer(context.Background(), trust.TrustedIssuer{
		DID:             "did:example:member-a",
		DisplayName:     "Registro Civil",
		ServiceEndpoint: srv.URL + "/", // trailing slash must be trimmed
	})
	if !ok {
		t.Fatal("fetchIssuer ok=false, want true")
	}
	if entry.DID != "did:example:member-a" {
		t.Errorf("DID = %q", entry.DID)
	}
	if entry.Name != "Registro Civil" {
		t.Errorf("Name = %q (should come from the hub's registry, not the member)", entry.Name)
	}
	if entry.ServiceEndpoint != srv.URL {
		t.Errorf("ServiceEndpoint = %q, want %q (trimmed)", entry.ServiceEndpoint, srv.URL)
	}
	if len(entry.Credentials) != 1 || entry.Credentials[0].ID != "PersonCredential" {
		t.Errorf("Credentials = %+v", entry.Credentials)
	}
}

func TestFetchIssuer_Non200IsNotOK(t *testing.T) {
	// A verifier-only member answers 404 → treated as "no catalog", not an error.
	srv := memberServer(t, backend.IssuerMetadata{}, http.StatusNotFound)
	defer srv.Close()

	a := NewAggregator(time.Minute)
	_, ok := a.fetchIssuer(context.Background(), trust.TrustedIssuer{
		DID: "did:example:verifier", ServiceEndpoint: srv.URL,
	})
	if ok {
		t.Error("fetchIssuer ok=true on 404, want false")
	}
}

func TestRefresh_PopulatesCatalogAndSkipsEndpointless(t *testing.T) {
	srv := memberServer(t, backend.IssuerMetadata{
		CredentialsSupported: []backend.CredentialConfig{{ID: "C1", Format: "vc+sd-jwt"}},
	}, http.StatusOK)
	defer srv.Close()

	reg := fakeRegistry{issuers: []trust.TrustedIssuer{
		{DID: "did:a", DisplayName: "A", ServiceEndpoint: srv.URL},
		{DID: "did:no-endpoint", DisplayName: "B"}, // skipped: no ServiceEndpoint
	}}
	a := NewAggregator(time.Minute)
	a.refresh(context.Background(), reg)

	cat := a.Catalog()
	if len(cat) != 1 {
		t.Fatalf("catalog len = %d, want 1 (endpointless member skipped)", len(cat))
	}
	if cat[0].DID != "did:a" || len(cat[0].Credentials) != 1 {
		t.Errorf("catalog[0] = %+v", cat[0])
	}
}

func TestRefresh_KeepsStaleEntryWhenMemberGoesDown(t *testing.T) {
	a := NewAggregator(time.Minute)
	// Seed a cached entry, then refresh against an unreachable endpoint.
	a.byIssuer["did:a"] = issuerEntry{entry: backend.IssuerCatalogEntry{
		DID: "did:a", Credentials: []backend.CredentialConfig{{ID: "cached"}},
	}}
	reg := fakeRegistry{issuers: []trust.TrustedIssuer{
		{DID: "did:a", ServiceEndpoint: "http://127.0.0.1:1"}, // connection refused
	}}
	a.refresh(context.Background(), reg)

	cat := a.Catalog()
	if len(cat) != 1 || cat[0].Credentials[0].ID != "cached" {
		t.Errorf("stale entry not retained on fetch failure: %+v", cat)
	}
}

// srvURL is a tiny helper so the test reads clearly; the value is irrelevant
// because the hub overrides issuer-reported URLs with its own member info.
func srvURL(s string) string { return "https://" + s }
