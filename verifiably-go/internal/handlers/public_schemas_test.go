package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/verifiably/verifiably-go/internal/schemacache"
	"github.com/verifiably/verifiably-go/vctypes"
)

func TestServePublicSchemas_OptionsPreflight(t *testing.T) {
	h := &H{Adapter: &testAdapter{}}
	rec := httptest.NewRecorder()
	h.ServePublicSchemas(rec, httptest.NewRequest(http.MethodOptions, "/api/schemas", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS header missing")
	}
}

func TestServePublicSchemas_CustomOnlyWithSourceAttribution(t *testing.T) {
	t.Setenv("VERIFIABLY_ISSUER_DID", "did:web:issuer.example")
	t.Setenv("VERIFIABLY_PUBLIC_URL", "https://issuer.example/")
	h := &H{Adapter: &testAdapter{schemas: []vctypes.Schema{
		{ID: "Person", Custom: true},
		{ID: "Stock", Custom: false},
	}}}
	rec := httptest.NewRecorder()
	h.ServePublicSchemas(rec, httptest.NewRequest(http.MethodGet, "/api/schemas", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d ct = %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	var out []vctypes.Schema
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "Person" {
		t.Fatalf("out = %+v, want only the custom schema", out)
	}
	if out[0].SourceIssuerDID != "did:web:issuer.example" || out[0].SourceDeployment != "https://issuer.example" {
		t.Errorf("source attribution = %q / %q", out[0].SourceIssuerDID, out[0].SourceDeployment)
	}
}

func TestServePublicSchemas_NoCustomSchemasIsEmptyArray(t *testing.T) {
	h := &H{Adapter: &testAdapter{}}
	rec := httptest.NewRecorder()
	h.ServePublicSchemas(rec, httptest.NewRequest(http.MethodGet, "/api/schemas", nil))
	if body := rec.Body.String(); body != "[]\n" {
		t.Errorf("body = %q, want empty JSON array", body)
	}
}

func TestServeHubSchemas(t *testing.T) {
	t.Run("options preflight", func(t *testing.T) {
		rec := httptest.NewRecorder()
		(&H{}).ServeHubSchemas(rec, httptest.NewRequest(http.MethodOptions, "/schemas", nil))
		if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Methods") != "GET, OPTIONS" {
			t.Fatalf("status = %d headers = %v", rec.Code, rec.Header())
		}
	})
	t.Run("nil cache serves empty array", func(t *testing.T) {
		rec := httptest.NewRecorder()
		(&H{}).ServeHubSchemas(rec, httptest.NewRequest(http.MethodGet, "/schemas", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "[]\n" {
			t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
		}
	})
	t.Run("empty cache serves empty array", func(t *testing.T) {
		h := &H{SchemaCache: schemacache.NewAggregator(time.Minute, nil)}
		rec := httptest.NewRecorder()
		h.ServeHubSchemas(rec, httptest.NewRequest(http.MethodGet, "/schemas", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "[]\n" {
			t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
		}
	})
}
