package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/verifiably/verifiably-go/backend"
)

// issuerMetaTTL bounds how long the public issuer-metadata response is memoized.
// Short enough that a newly-saved schema appears quickly; long enough that a
// burst of wallet discovery requests doesn't fan out to a per-vendor schema
// fetch each time.
const issuerMetaTTL = 60 * time.Second

// cachedIssuerMetadata returns this member's OpenID4VCI metadata, memoized for
// issuerMetaTTL. Only the public (unowned) view is cached — callers that need
// an owner-scoped view must call h.Adapter.GetIssuerMetadata directly. Errors
// are not cached (they're cheap and may be transient).
func (h *H) cachedIssuerMetadata(ctx context.Context) (backend.IssuerMetadata, error) {
	h.issuerMetaMu.Lock()
	if h.issuerMetaOK && time.Since(h.issuerMetaAt) < issuerMetaTTL {
		v := h.issuerMetaVal
		h.issuerMetaMu.Unlock()
		return v, nil
	}
	h.issuerMetaMu.Unlock()

	meta, err := h.Adapter.GetIssuerMetadata(ctx)
	if err != nil {
		return backend.IssuerMetadata{}, err
	}
	h.issuerMetaMu.Lock()
	h.issuerMetaVal = meta
	h.issuerMetaAt = time.Now()
	h.issuerMetaOK = true
	h.issuerMetaMu.Unlock()
	return meta, nil
}

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

	meta, err := h.cachedIssuerMetadata(r.Context())
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

// ServeCredentialCatalog handles GET /api/v1/discovery/credentials (Hub).
//
// It returns the federated credential catalog: one entry per trusted member,
// each carrying the member's attribution and the credentials it advertises at
// its /.well-known/openid-credential-issuer endpoint. This is what cdpi-wallet
// calls once to populate its "Descubrir" screen. Served from the in-memory
// cache (TTL refresh) so it never blocks on upstream members. Public + CORS,
// like the other federation discovery endpoints.
func (h *H) ServeCredentialCatalog(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	issuers := []backend.IssuerCatalogEntry{}
	if h.CredentialCache != nil {
		if c := h.CredentialCache.Catalog(); c != nil {
			issuers = c
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"issuers": issuers})
}
