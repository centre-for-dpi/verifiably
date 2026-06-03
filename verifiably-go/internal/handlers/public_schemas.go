package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/verifiably/verifiably-go/vctypes"
)

// ServePublicSchemas handles GET /api/schemas (Issuer + Schemas role).
// Returns a JSON array of the adapter's custom schemas, with SourceIssuerDID
// and SourceDeployment filled from environment variables so the Hub's
// schema aggregator can attribute each schema to its correct issuer.
//
// CORS is enabled so the Hub can fetch cross-origin from issuer deployments.
func (h *H) ServePublicSchemas(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	issuerDID := os.Getenv("VERIFIABLY_ISSUER_DID")
	deployment := strings.TrimRight(os.Getenv("VERIFIABLY_PUBLIC_URL"), "/")

	all, _ := h.Adapter.ListAllSchemas(r.Context())
	out := make([]vctypes.Schema, 0)
	for _, s := range all {
		if !s.Custom {
			continue
		}
		s.SourceIssuerDID = issuerDID
		s.SourceDeployment = deployment
		out = append(out, s)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ServeHubSchemas handles GET /schemas (Hub role).
// Returns a JSON array of schemas aggregated from all trusted federation
// members that have a ServiceEndpoint and expose GET /api/schemas.
// Results come from the in-memory cache (TTL 5 min) so this endpoint
// never blocks on upstream HTTP.
func (h *H) ServeHubSchemas(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var schemas []vctypes.Schema
	if h.SchemaCache != nil {
		schemas = h.SchemaCache.Schemas()
	}
	if schemas == nil {
		schemas = []vctypes.Schema{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(schemas)
}

// setCORSHeaders sets permissive CORS headers for public schema endpoints.
// These endpoints are read-only, unauthenticated, and intentionally public.
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")
}
