package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/verifiably/verifiably-go/backend"
)

// ServeIssuerMetadata handles GET /.well-known/openid-credential-issuer.
//
// It returns this member's OpenID4VCI Credential Issuer Metadata: the
// credential configurations it can issue, aggregated across its issuer DPGs.
// A wallet (or the hub catalog aggregator) fetches it to discover what this
// member offers without an operator in the loop — the holder-initiated half of
// the delivery model (docs/credential-delivery.md).
//
// Public + CORS, like the other federation discovery endpoints. The adapter
// reports only the credential list; the absolute issuer/credential endpoint
// URLs are filled here from the request's public base so they match however the
// member is actually reached.
func (h *H) ServeIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	meta, err := h.Adapter.GetIssuerMetadata(r.Context())
	if err != nil {
		// A DPG that doesn't issue (verifier-only / stub) returns
		// ErrNotSupported — surface that as 404 so a wallet treats this member
		// as non-issuing rather than as a server fault. Any other error is a
		// genuine upstream failure.
		if errors.Is(err, backend.ErrNotSupported) {
			http.Error(w, "this member does not issue credentials", http.StatusNotFound)
			return
		}
		http.Error(w, "issuer metadata unavailable: "+err.Error(), http.StatusBadGateway)
		return
	}

	base := publicBase(r)
	meta.CredentialIssuer = base
	if meta.CredentialEndpoint == "" {
		meta.CredentialEndpoint = base + "/credential"
	}
	if meta.CredentialsSupported == nil {
		meta.CredentialsSupported = []backend.CredentialConfig{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}
