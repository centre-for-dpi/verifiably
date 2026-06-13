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

// ServeCredentialCatalog handles GET /api/v1/discovery/credentials.
//
// In hub mode (CredentialCache set): returns the pre-fetched federated catalog
// — one entry per trusted member, populated by the background aggregator.
//
// In standalone issuer mode (CredentialCache nil): returns a single-entry
// catalog for this member itself, derived from its own
// /.well-known/openid-credential-issuer. This allows a wallet to use the same
// endpoint for discovery regardless of whether the deployment is a federation
// hub or a single issuer.
//
// Only credentials that carry a national-ID-equivalent claim are included:
// these are the only ones a citizen can self-issue from their verified identity.
// Credentials requiring issuer-gated data (e.g. a diploma's "degree") are
// omitted here; the operator API path serves those separately.
//
// Public + CORS, like the other federation discovery endpoints.
func (h *H) ServeCredentialCatalog(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var issuers []backend.IssuerCatalogEntry
	if h.CredentialCache != nil {
		if c := h.CredentialCache.Catalog(); c != nil {
			issuers = c
		}
	} else {
		// Standalone issuer: serve only this member's own catalog.
		meta, err := h.cachedIssuerMetadata(r.Context())
		if err == nil && len(meta.CredentialsSupported) > 0 {
			issuers = []backend.IssuerCatalogEntry{{
				ServiceEndpoint: publicBase(r),
				Credentials:     meta.CredentialsSupported,
			}}
		}
	}
	if issuers == nil {
		issuers = []backend.IssuerCatalogEntry{}
	}

	issuers = filterCitizenBindingCredentials(issuers)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"issuers": issuers})
}

// filterCitizenBindingCredentials removes credentials that do not carry a
// national-ID-equivalent claim, and removes issuers that have no remaining
// credentials after filtering. This keeps the citizen discovery catalog honest:
// every credential shown can actually be self-issued from a verified national
// identity, so the wallet never shows an "Obtener" button that will always fail.
func filterCitizenBindingCredentials(issuers []backend.IssuerCatalogEntry) []backend.IssuerCatalogEntry {
	// Mock token with nationalid so resolveClaim can do alias-aware matching.
	mockToken := map[string]string{"nationalid": "1"}
	out := make([]backend.IssuerCatalogEntry, 0, len(issuers))
	for _, iss := range issuers {
		var creds []backend.CredentialConfig
		for _, c := range iss.Credentials {
			if credentialHasNationalIDClaim(c, mockToken) {
				creds = append(creds, c)
			}
		}
		if len(creds) > 0 {
			iss.Credentials = creds
			out = append(out, iss)
		}
	}
	return out
}

// credentialHasNationalIDClaim reports whether any of the credential's declared
// claim names resolves to a national-ID-equivalent value when matched against a
// token that carries nationalid. Uses resolveClaim so the alias table in
// identity_prefill.go (cedula, dni, documentnumber, …) is the single source of
// truth — this check and the eligibility check never drift.
func credentialHasNationalIDClaim(c backend.CredentialConfig, mockToken map[string]string) bool {
	for _, name := range c.Claims {
		if _, ok := resolveClaim(name, mockToken); ok {
			return true
		}
	}
	return false
}
