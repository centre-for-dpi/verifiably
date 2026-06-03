package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// signingKeyAdapter is the optional capability the walt.id adapter exposes
// for status-list signing. Other adapters (mock, inji-certify, inji-web)
// don't implement it; the handler falls back to a clear error in that case
// rather than panicking.
type signingKeyAdapter interface {
	IssuerSigningKey(ctx context.Context) (raw []byte, did string, err error)
}

// resolveSigningKey lazily fetches and parses the walt.id issuer JWK.
// The key is cached after a successful fetch (it doesn't rotate in normal
// operation). If the fetch fails (walt.id unreachable at boot), the error
// is NOT cached — the next request retries so the feature recovers once
// walt.id comes up, without needing a container restart.
func (h *H) resolveSigningKey(ctx context.Context) (*statuslist.SigningKey, error) {
	h.signingKeyMu.RLock()
	key := h.signingKey
	h.signingKeyMu.RUnlock()
	if key != nil {
		return key, nil
	}

	// Key not yet cached — try to fetch it. Only one goroutine at a time
	// to avoid hammering walt.id with concurrent onboard calls.
	h.signingKeyMu.Lock()
	defer h.signingKeyMu.Unlock()
	if h.signingKey != nil {
		return h.signingKey, nil // another goroutine beat us
	}

	sa, ok := h.Adapter.(signingKeyAdapter)
	if !ok {
		return nil, fmt.Errorf("status-list: adapter %T doesn't expose IssuerSigningKey", h.Adapter)
	}
	raw, did, err := sa.IssuerSigningKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("status-list: fetch issuer key: %w", err)
	}
	parsed, err := statuslist.ParseWaltidIssuerKey(raw, did)
	if err != nil {
		return nil, fmt.Errorf("status-list: parse issuer key: %w", err)
	}
	h.signingKey = parsed
	return h.signingKey, nil
}

// PublishBitstringStatusList serves GET /status-list/bitstring/{id}. The
// id segment must match the configured BitstringStore.ListID — we only
// host one list at a time today, but pinning the ID in the URL lets us
// add second-list support later without changing the route shape.
func (h *H) PublishBitstringStatusList(w http.ResponseWriter, r *http.Request) {
	if h.BitstringStore == nil {
		http.Error(w, "bitstring status list not configured", http.StatusNotFound)
		return
	}
	id := r.PathValue("id")
	if id == "" || id != h.BitstringStore.GetListID() {
		http.Error(w, "unknown status list id", http.StatusNotFound)
		return
	}
	key, err := h.resolveSigningKey(r.Context())
	if err != nil {
		log.Printf("status-list/bitstring: signing key unavailable: %v", err)
		http.Error(w, "status list signing key unavailable", http.StatusServiceUnavailable)
		return
	}
	jwt, err := h.BitstringStore.PublishBitstringJWT(key)
	if err != nil {
		log.Printf("status-list/bitstring: publish failed: %v", err)
		http.Error(w, "status list unavailable", http.StatusInternalServerError)
		return
	}
	// Per VCDM 2.0 + IANA media-type registry, JOSE-secured VCs use the
	// `application/vc+jwt` media type. Verifiers that key off the
	// Content-Type can dispatch to the JWT-VC parser without sniffing.
	w.Header().Set("Content-Type", "application/vc+jwt")
	// Status lists change rarely — let intermediaries cache for 60s. A
	// freshly-revoked credential's status visibility lags by at most one
	// minute, well inside what verifiers expect.
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write([]byte(jwt))
}

// PublishTokenStatusList serves GET /status-list/token/{id} for SD-JWT
// VCs. Same shape as PublishBitstringStatusList but emits the IETF Token
// Status List JWT (status_list claim) with media type
// application/statuslist+jwt (draft-ietf-oauth-status-list §6).
func (h *H) PublishTokenStatusList(w http.ResponseWriter, r *http.Request) {
	if h.TokenStore == nil {
		http.Error(w, "token status list not configured", http.StatusNotFound)
		return
	}
	id := r.PathValue("id")
	if id == "" || id != h.TokenStore.GetListID() {
		http.Error(w, "unknown status list id", http.StatusNotFound)
		return
	}
	key, err := h.resolveSigningKey(r.Context())
	if err != nil {
		log.Printf("status-list/token: signing key unavailable: %v", err)
		http.Error(w, "status list signing key unavailable", http.StatusServiceUnavailable)
		return
	}
	jwt, err := h.TokenStore.PublishTokenStatusList(key)
	if err != nil {
		log.Printf("status-list/token: publish failed: %v", err)
		http.Error(w, "status list unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_, _ = w.Write([]byte(jwt))
}
