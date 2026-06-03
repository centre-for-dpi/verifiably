package didresolver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebResolver resolves did:web DIDs by fetching the DID Document over HTTPS.
// Results are cached for cacheTTL to avoid repeated HTTP calls on each
// credential verification — the DID Document of a stable issuer almost
// never changes, so a 10-minute TTL is safe and eliminates the per-request
// round-trip cost.
type WebResolver struct {
	client   *http.Client
	cacheTTL time.Duration
	mu       sync.Mutex
	cache    map[string]cachedEntry
}

type cachedEntry struct {
	doc       DIDDocument
	fetchedAt time.Time
}

// NewWebResolver returns a WebResolver with sensible defaults:
// 10-second HTTP timeout and 10-minute document cache.
func NewWebResolver() *WebResolver {
	return &WebResolver{
		client:   &http.Client{Timeout: 10 * time.Second},
		cacheTTL: 10 * time.Minute,
		cache:    make(map[string]cachedEntry),
	}
}

// Resolve implements Resolver for did:web.
// Parsing follows the W3C DID-Web spec:
//
//	did:web:example.com            → https://example.com/.well-known/did.json
//	did:web:example.com:path:to    → https://example.com/path/to/did.json
func (r *WebResolver) Resolve(ctx context.Context, did string) (DIDDocument, error) {
	if !strings.HasPrefix(did, "did:web:") {
		return DIDDocument{}, fmt.Errorf("didresolver: unsupported DID method in %q (only did:web supported)", did)
	}

	r.mu.Lock()
	if entry, ok := r.cache[did]; ok && time.Since(entry.fetchedAt) < r.cacheTTL {
		doc := entry.doc
		r.mu.Unlock()
		return doc, nil
	}
	r.mu.Unlock()

	docURL := didWebToURL(did)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return DIDDocument{}, fmt.Errorf("didresolver: build request for %s: %w", docURL, err)
	}
	req.Header.Set("Accept", "application/json, application/did+json")

	resp, err := r.client.Do(req)
	if err != nil {
		return DIDDocument{}, fmt.Errorf("didresolver: fetch %s: %w", docURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return DIDDocument{}, fmt.Errorf("didresolver: %s returned HTTP %d", docURL, resp.StatusCode)
	}

	var raw struct {
		ID                 string `json:"id"`
		VerificationMethod []struct {
			ID           string         `json:"id"`
			Type         string         `json:"type"`
			PublicKeyJwk map[string]any `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return DIDDocument{}, fmt.Errorf("didresolver: decode DID document from %s: %w", docURL, err)
	}

	doc := DIDDocument{ID: raw.ID}
	for _, vm := range raw.VerificationMethod {
		doc.VerificationMethods = append(doc.VerificationMethods, VerificationMethod{
			ID:           vm.ID,
			Type:         vm.Type,
			PublicKeyJWK: vm.PublicKeyJwk,
		})
	}

	r.mu.Lock()
	r.cache[did] = cachedEntry{doc: doc, fetchedAt: time.Now()}
	r.mu.Unlock()

	return doc, nil
}

// didWebToURL converts a did:web identifier to its DID Document URL.
// Colons after the domain component are treated as path separators per spec.
func didWebToURL(did string) string {
	rest := strings.TrimPrefix(did, "did:web:")
	parts := strings.SplitN(rest, ":", 2)
	domain := parts[0]
	if len(parts) == 1 {
		return "https://" + domain + "/.well-known/did.json"
	}
	path := strings.ReplaceAll(parts[1], ":", "/")
	return "https://" + domain + "/" + path + "/did.json"
}
