// Package schemacache aggregates credential schemas from all trusted issuers
// in the federation. The Hub uses it to power the public /verify schema picker
// without hitting every issuer's /api/schemas endpoint on every page load.
//
// Each issuer's schema list is cached in memory for a configurable TTL. A
// background goroutine (started via Start) refreshes the cache every TTL,
// so reads always return instantly from the hot layer. When an issuer is
// unreachable the most recent cached list is retained — the citizen-facing
// portal continues to show that issuer's schemas even if their deployment
// is temporarily down.
package schemacache

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/verifiably/verifiably-go/internal/trust"
	"github.com/verifiably/verifiably-go/vctypes"
)

type issuerEntry struct {
	schemas  []vctypes.Schema
	cachedAt time.Time
}

// Aggregator federates schemas from all trusted issuers with a ServiceEndpoint.
// Safe for concurrent use.
type Aggregator struct {
	mu        sync.RWMutex
	byIssuer  map[string]issuerEntry // key = issuerDID
	memberIDs map[string]string      // issuerDID → Registry adapter key (member.ID)
	ttl       time.Duration
	client    *http.Client
}

// NewAggregator creates an Aggregator with the given TTL.
// memberIDs maps each issuer DID to its Registry adapter key (the member.ID
// from federation.json). This lets PublicVerifyRequest route OID4VP requests
// to the correct verifier adapter for each schema.
func NewAggregator(ttl time.Duration, memberIDs map[string]string) *Aggregator {
	return &Aggregator{
		byIssuer:  make(map[string]issuerEntry),
		memberIDs: memberIDs,
		ttl:       ttl,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

// Start spawns a background goroutine that refreshes schema caches from the
// trust registry. It polls immediately on startup and then every ttl.
// Stops when ctx is cancelled.
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

// RegisterMember adds or updates the DID→adapterKey mapping at runtime.
// Called when a federation member is registered via the admin UI so the
// next schema refresh stamps the correct SourceDeployment without a restart.
func (a *Aggregator) RegisterMember(did, adapterKey string) {
	a.mu.Lock()
	a.memberIDs[did] = adapterKey
	a.mu.Unlock()
}

// Schemas returns the merged list of schemas from all cached issuers.
// If an issuer hasn't been fetched yet (e.g. called before Start's first
// poll), it simply won't appear in the results.
func (a *Aggregator) Schemas() []vctypes.Schema {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var out []vctypes.Schema
	for _, e := range a.byIssuer {
		out = append(out, e.schemas...)
	}
	return out
}

func (a *Aggregator) refresh(ctx context.Context, reg trust.Registry) {
	issuers, err := reg.TrustedIssuers(ctx)
	if err != nil {
		log.Printf("schemacache: TrustedIssuers: %v", err)
		return
	}
	for _, issuer := range issuers {
		if issuer.ServiceEndpoint == "" {
			continue
		}
		schemas := a.fetchIssuer(ctx, issuer)
		if schemas == nil {
			// Fetch failed — keep existing cache entry so the portal stays up.
			continue
		}
		a.mu.Lock()
		a.byIssuer[issuer.DID] = issuerEntry{schemas: schemas, cachedAt: time.Now()}
		a.mu.Unlock()
	}
}

// fetchIssuer GETs {ServiceEndpoint}/api/schemas and returns the decoded schemas.
// Returns nil on any error so callers preserve the existing cache entry.
func (a *Aggregator) fetchIssuer(ctx context.Context, issuer trust.TrustedIssuer) []vctypes.Schema {
	url := strings.TrimRight(issuer.ServiceEndpoint, "/") + "/api/schemas"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("schemacache: build request for %s: %v", issuer.DID, err)
		return nil
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("schemacache: fetch %s: %v", url, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("schemacache: %s returned %d", url, resp.StatusCode)
		return nil
	}

	// Cap at 1 MiB to protect against runaway responses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		log.Printf("schemacache: read body from %s: %v", url, err)
		return nil
	}

	var schemas []vctypes.Schema
	if err := json.Unmarshal(body, &schemas); err != nil {
		log.Printf("schemacache: decode from %s: %v", url, err)
		return nil
	}

	// Hub overrides SourceIssuerDID and SourceDeployment — the issuer's
	// self-reported values may not match what the Hub knows about this member.
	a.mu.RLock()
	memberID := a.memberIDs[issuer.DID]
	a.mu.RUnlock()
	for i := range schemas {
		schemas[i].SourceIssuerDID = issuer.DID
		schemas[i].SourceDeployment = memberID
	}
	return schemas
}
