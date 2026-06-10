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
