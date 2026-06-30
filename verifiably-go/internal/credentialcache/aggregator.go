// Package credentialcache aggregates the OpenID4VCI credential catalogs of all
// trusted issuers in the federation. The Hub uses it to power the wallet's
// "Descubrir" screen without fetching every member's
// /.well-known/openid-credential-issuer on each request.
//
// It mirrors schemacache: each member's catalog is cached in memory for a
// configurable TTL, a background goroutine (Start) refreshes it every TTL, and
// reads return instantly from the hot layer. When a member is unreachable the
// most recent cached catalog is retained so the discovery screen stays up.
package credentialcache

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/verifiably/verifiably-go/backend"
	"github.com/verifiably/verifiably-go/internal/trust"
)

// Cache is the read side the discovery handler depends on. *Aggregator
// implements it; tests substitute a fake. Mirrors statuslistcache.Cache.
type Cache interface {
	// Catalog returns the merged per-issuer credential catalog.
	Catalog() []backend.IssuerCatalogEntry
}

type issuerEntry struct {
	entry    backend.IssuerCatalogEntry
	cachedAt time.Time
}

// Aggregator federates credential catalogs from all trusted issuers with a
// ServiceEndpoint. Safe for concurrent use.
type Aggregator struct {
	mu       sync.RWMutex
	byIssuer map[string]issuerEntry // key = issuerDID
	ttl      time.Duration
	client   *http.Client
}

// NewAggregator creates an Aggregator with the given TTL.
func NewAggregator(ttl time.Duration) *Aggregator {
	return &Aggregator{
		byIssuer: make(map[string]issuerEntry),
		ttl:      ttl,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// Start spawns a background goroutine that refreshes the catalog from the trust
// registry. It polls immediately on startup and then every ttl. Stops when ctx
// is cancelled. A member registered after startup appears on the next poll.
func (a *Aggregator) Start(ctx context.Context, reg trust.Registry) {
	go func() {
		a.refresh(ctx, reg)
		ticker := time.NewTicker(a.ttl)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.refresh(ctx, reg)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Catalog returns the merged per-issuer catalog from all cached issuers. An
// issuer not yet fetched (e.g. before Start's first poll) simply won't appear.
func (a *Aggregator) Catalog() []backend.IssuerCatalogEntry {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]backend.IssuerCatalogEntry, 0, len(a.byIssuer))
	for _, e := range a.byIssuer {
		out = append(out, e.entry)
	}
	return out
}

func (a *Aggregator) refresh(ctx context.Context, reg trust.Registry) {
	issuers, err := reg.TrustedIssuers(ctx)
	if err != nil {
		log.Printf("credentialcache: TrustedIssuers: %v", err)
		return
	}
	for _, issuer := range issuers {
		if issuer.ServiceEndpoint == "" {
			continue
		}
		entry, ok := a.fetchIssuer(ctx, issuer)
		if !ok {
			// Fetch failed — keep the existing cache entry so discovery stays up.
			continue
		}
		a.mu.Lock()
		a.byIssuer[issuer.DID] = issuerEntry{entry: entry, cachedAt: time.Now()}
		a.mu.Unlock()
	}
}

// fetchIssuer GETs {ServiceEndpoint}/.well-known/openid-credential-issuer and
// maps it onto a catalog entry attributed with the hub's own member info.
// Returns ok=false on any error so callers preserve the existing cache entry.
// A member that doesn't issue answers 404, which is treated as "no catalog"
// (ok=false) rather than an error — it just won't appear in the catalog.
func (a *Aggregator) fetchIssuer(ctx context.Context, issuer trust.TrustedIssuer) (backend.IssuerCatalogEntry, bool) {
	base := strings.TrimRight(issuer.ServiceEndpoint, "/")
	url := base + "/.well-known/openid-credential-issuer"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("credentialcache: build request for %s: %v", issuer.DID, err)
		return backend.IssuerCatalogEntry{}, false
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("credentialcache: fetch %s: %v", url, err)
		return backend.IssuerCatalogEntry{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("credentialcache: %s returned %d", url, resp.StatusCode)
		return backend.IssuerCatalogEntry{}, false
	}

	// Cap at 1 MiB to protect against runaway responses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		log.Printf("credentialcache: read body from %s: %v", url, err)
		return backend.IssuerCatalogEntry{}, false
	}

	var meta backend.IssuerMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		log.Printf("credentialcache: decode from %s: %v", url, err)
		return backend.IssuerCatalogEntry{}, false
	}

	return backend.IssuerCatalogEntry{
		DID:             issuer.DID,
		Name:            issuer.DisplayName,
		ServiceEndpoint: base,
		Credentials:     meta.CredentialsSupported,
	}, true
}
