// Package statuslistcache provides a persistent cache for issuer status lists.
// On each fetch it tries the live endpoint first (3 s timeout); on failure it
// returns the last-known copy. The Source field in Result tells callers whether
// the data came from a live request or the cache.
package statuslistcache

import (
	"context"
	"time"
)

// Cache is the interface for fetching status list content with caching.
type Cache interface {
	// Fetch retrieves the status list at listURL for the given issuerDID.
	// It tries a live fetch first; on failure it returns a cached copy.
	// Result.Source is "live", "cached", or "unknown".
	Fetch(ctx context.Context, issuerDID, listURL string) (Result, error)
}

// Result is the output of a status list fetch.
type Result struct {
	RawJWT    string    // raw JWT as served by the endpoint (may be empty for "unknown")
	Source    string    // "live" | "cached" | "unknown"
	CachedAt  time.Time // when this entry was last fetched from the live endpoint
	ExpiresAt time.Time // when the cached copy should be considered stale
}
