package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/vctypes"
)

func TestServeIssuerMetadata_Success(t *testing.T) {
	ad := &testAdapter{schemas: []vctypes.Schema{
		{ID: "PersonCredential", Name: "Person", Std: "w3c_vcdm_2",
			FieldsSpec: []vctypes.FieldSpec{{Name: "given_name"}}},
	}}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.ServeIssuerMetadata(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var meta backend.IssuerMetadata
	if err := json.Unmarshal(rr.Body.Bytes(), &meta); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if meta.CredentialIssuer == "" {
		t.Error("credential_issuer should be filled from the request base")
	}
	if meta.CredentialEndpoint == "" {
		t.Error("credential_endpoint should be defaulted")
	}
	if len(meta.CredentialsSupported) != 1 || meta.CredentialsSupported[0].ID != "PersonCredential" {
		t.Errorf("credentials_supported = %+v", meta.CredentialsSupported)
	}
}

func TestServeIssuerMetadata_NotSupported404(t *testing.T) {
	// A verifier-only adapter returns ErrNotSupported → handler answers 404.
	ad := &testAdapter{schemasErr: backend.ErrNotSupported}
	h := apiTestH(ad)

	rr := httptest.NewRecorder()
	h.ServeIssuerMetadata(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-credential-issuer", nil))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body=%s)", rr.Code, rr.Body.String())
	}
}

// fakeCatalog implements credentialcache.Cache for handler tests.
type fakeCatalog struct{ entries []backend.IssuerCatalogEntry }

func (f fakeCatalog) Catalog() []backend.IssuerCatalogEntry { return f.entries }

func TestServeCredentialCatalog_Success(t *testing.T) {
	h := apiTestH(&testAdapter{})
	h.CredentialCache = fakeCatalog{entries: []backend.IssuerCatalogEntry{
		{DID: "did:a", Name: "Registro Civil", ServiceEndpoint: "https://a.gt",
			Credentials: []backend.CredentialConfig{
				{ID: "PersonCredential", Format: "jwt_vc_json", Claims: []string{"national_id", "given_name"}},
			}},
	}}

	rr := httptest.NewRecorder()
	h.ServeCredentialCatalog(rr, httptest.NewRequest(http.MethodGet, "/api/v1/discovery/credentials", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Issuers []backend.IssuerCatalogEntry `json:"issuers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if len(resp.Issuers) != 1 || resp.Issuers[0].DID != "did:a" {
		t.Errorf("issuers = %+v", resp.Issuers)
	}
	if len(resp.Issuers[0].Credentials) != 1 {
		t.Errorf("credentials = %+v", resp.Issuers[0].Credentials)
	}
}

func TestServeCredentialCatalog_NilCacheEmptyArray(t *testing.T) {
	h := apiTestH(&testAdapter{}) // CredentialCache left nil
	rr := httptest.NewRecorder()
	h.ServeCredentialCatalog(rr, httptest.NewRequest(http.MethodGet, "/api/v1/discovery/credentials", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	// Must serialize as {"issuers":[]}, never {"issuers":null}.
	if got := rr.Body.String(); got != "{\"issuers\":[]}\n" {
		t.Errorf("body = %q, want empty issuers array", got)
	}
}

// TestServeCredentialCatalog_StandaloneIssuer pins that a non-hub deployment
// (CredentialCache nil) still serves its own credential catalog so the wallet's
// "Descubrir" tab works without a federation hub.
func TestServeCredentialCatalog_StandaloneIssuer(t *testing.T) {
	ad := &testAdapter{schemas: []vctypes.Schema{
		{ID: "PersonCredential", Name: "Person", Std: "sd_jwt_vc",
			FieldsSpec: []vctypes.FieldSpec{{Name: "national_id"}, {Name: "given_name"}, {Name: "family_name"}}},
	}}
	h := apiTestH(ad) // CredentialCache left nil → standalone mode

	rr := httptest.NewRecorder()
	h.ServeCredentialCatalog(rr, httptest.NewRequest(http.MethodGet, "/api/v1/discovery/credentials", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Issuers []backend.IssuerCatalogEntry `json:"issuers"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, rr.Body.String())
	}
	if len(resp.Issuers) != 1 {
		t.Fatalf("issuers len = %d, want 1 (standalone should return self)", len(resp.Issuers))
	}
	entry := resp.Issuers[0]
	if entry.ServiceEndpoint == "" {
		t.Error("service_endpoint should be set to the request base URL")
	}
	if len(entry.Credentials) != 1 || entry.Credentials[0].ID != "PersonCredential" {
		t.Errorf("credentials = %+v, want PersonCredential", entry.Credentials)
	}
}

func TestServeCredentialCatalog_FiltersNonCitizenCredentials(t *testing.T) {
	// Catalog has two credentials: one with nationalId (should pass), one
	// without (should be filtered out). The issuer entry itself stays because
	// it still has one eligible credential.
	h := apiTestH(&testAdapter{})
	h.CredentialCache = fakeCatalog{entries: []backend.IssuerCatalogEntry{
		{DID: "did:a", Name: "RNPN", ServiceEndpoint: "https://a.gt",
			Credentials: []backend.CredentialConfig{
				{ID: "RuralId", Claims: []string{"NationalId", "FullName"}},
				{ID: "Diploma", Claims: []string{"given_name", "degree"}},
			}},
	}}

	rr := httptest.NewRecorder()
	h.ServeCredentialCatalog(rr, httptest.NewRequest(http.MethodGet, "/api/v1/discovery/credentials", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp struct {
		Issuers []backend.IssuerCatalogEntry `json:"issuers"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Issuers) != 1 {
		t.Fatalf("issuers = %d, want 1", len(resp.Issuers))
	}
	creds := resp.Issuers[0].Credentials
	if len(creds) != 1 || creds[0].ID != "RuralId" {
		t.Errorf("credentials = %+v, want only RuralId", creds)
	}
}

func TestServeCredentialCatalog_ExcludesIssuerWithNoEligibleCredentials(t *testing.T) {
	// All credentials in this issuer lack a nationalId claim → issuer excluded.
	h := apiTestH(&testAdapter{})
	h.CredentialCache = fakeCatalog{entries: []backend.IssuerCatalogEntry{
		{DID: "did:b", Name: "University", ServiceEndpoint: "https://b.gt",
			Credentials: []backend.CredentialConfig{
				{ID: "Diploma", Claims: []string{"given_name", "degree"}},
			}},
	}}

	rr := httptest.NewRecorder()
	h.ServeCredentialCatalog(rr, httptest.NewRequest(http.MethodGet, "/api/v1/discovery/credentials", nil))

	var resp struct {
		Issuers []backend.IssuerCatalogEntry `json:"issuers"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Issuers) != 0 {
		t.Errorf("issuers = %+v, want empty (no citizen-binding credentials)", resp.Issuers)
	}
}

func TestServeCredentialCatalog_AliasedNationalIDClaims(t *testing.T) {
	// "cedula" and "documentnumber" are aliases for nationalid — they must pass.
	h := apiTestH(&testAdapter{})
	h.CredentialCache = fakeCatalog{entries: []backend.IssuerCatalogEntry{
		{DID: "did:c", Credentials: []backend.CredentialConfig{
			{ID: "CedulaCredential", Claims: []string{"cedula", "nombre"}},
			{ID: "DocCredential", Claims: []string{"documentnumber", "given_name"}},
		}},
	}}

	rr := httptest.NewRecorder()
	h.ServeCredentialCatalog(rr, httptest.NewRequest(http.MethodGet, "/api/v1/discovery/credentials", nil))

	var resp struct {
		Issuers []backend.IssuerCatalogEntry `json:"issuers"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Issuers) != 1 || len(resp.Issuers[0].Credentials) != 2 {
		t.Errorf("issuers = %+v, want 1 issuer with 2 credentials (cedula + documentnumber aliases)", resp.Issuers)
	}
}

func TestServeCredentialCatalog_FiltersPartiallyGatedCredentials(t *testing.T) {
	// A credential with [national_id, degree] must be filtered: "degree" is not
	// coverable from any national-ID OIDC token, so the "Obtener" button would
	// always lead to a 403 from self-issue. Only NatIdOnly (fully coverable) survives.
	h := apiTestH(&testAdapter{})
	h.CredentialCache = fakeCatalog{entries: []backend.IssuerCatalogEntry{
		{DID: "did:a", Credentials: []backend.CredentialConfig{
			{ID: "NatIdOnly", Claims: []string{"national_id", "given_name"}},
			{ID: "Diploma", Claims: []string{"national_id", "degree"}},
		}},
	}}

	rr := httptest.NewRecorder()
	h.ServeCredentialCatalog(rr, httptest.NewRequest(http.MethodGet, "/api/v1/discovery/credentials", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp struct {
		Issuers []backend.IssuerCatalogEntry `json:"issuers"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Issuers) != 1 {
		t.Fatalf("issuers = %d, want 1", len(resp.Issuers))
	}
	creds := resp.Issuers[0].Credentials
	if len(creds) != 1 || creds[0].ID != "NatIdOnly" {
		t.Errorf("credentials = %+v, want only NatIdOnly (Diploma filtered: degree not identity-coverable)", creds)
	}
}

func TestServeIssuerMetadata_OptionsCORS(t *testing.T) {
	h := apiTestH(&testAdapter{})
	rr := httptest.NewRecorder()
	h.ServeIssuerMetadata(rr, httptest.NewRequest(http.MethodOptions, "/.well-known/openid-credential-issuer", nil))

	if rr.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS origin header missing on preflight")
	}
}
