// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/oidc"
)

// DefaultCacheTTL is how long a discovery document or a JWKS stays valid.
const DefaultCacheTTL = 10 * time.Minute

// maxBody caps the size of a provider response.
const maxBody = 1 << 20

// Metadata is a provider metadata document plus the RP initiated logout
// endpoint that core/oidc does not carry.
type Metadata struct {
	oidc.Discovery
	// EndSessionEndpoint is the RP initiated logout endpoint, when any.
	EndSessionEndpoint string `json:"end_session_endpoint,omitempty"`
}

// ParseMetadata decodes a metadata document.
func ParseMetadata(raw []byte) (Metadata, error) {
	d, err := oidc.ParseDiscovery(raw)
	if err != nil {
		return Metadata{}, err
	}
	var extra struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	// raw parsed once above, so it parses again.
	_ = json.Unmarshal(raw, &extra)
	return Metadata{Discovery: d, EndSessionEndpoint: extra.EndSessionEndpoint}, nil
}

// Rebase moves the server side endpoints to authority and keeps the
// authorization and end session endpoints for the browser.
func (m Metadata) Rebase(authority string) Metadata {
	if authority == "" {
		return m
	}
	m.TokenEndpoint = oidc.SwapAuthority(m.TokenEndpoint, authority)
	m.UserinfoEndpoint = oidc.SwapAuthority(m.UserinfoEndpoint, authority)
	m.JWKSURI = oidc.SwapAuthority(m.JWKSURI, authority)
	return m
}

type entry[T any] struct {
	value   T
	expires time.Time
}

// Cache fetches and keeps provider metadata and key sets.
type Cache struct {
	client *http.Client
	ttl    time.Duration
	now    func() time.Time

	mu   sync.Mutex
	meta map[string]entry[Metadata]
	keys map[string]entry[jose.JWKS]
}

// NewCache returns a cache that uses client for fetches. A nil client
// selects http.DefaultClient with a 10 second timeout.
func NewCache(client *http.Client, ttl time.Duration) *Cache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Cache{
		client: client,
		ttl:    ttl,
		now:    time.Now,
		meta:   map[string]entry[Metadata]{},
		keys:   map[string]entry[jose.JWKS]{},
	}
}

// Metadata returns the metadata at discoveryURL, from the cache when fresh.
func (c *Cache) Metadata(ctx context.Context, discoveryURL string) (Metadata, error) {
	c.mu.Lock()
	e, ok := c.meta[discoveryURL]
	c.mu.Unlock()
	if ok && c.now().Before(e.expires) {
		return e.value, nil
	}
	raw, err := c.get(ctx, discoveryURL)
	if err != nil {
		return Metadata{}, err
	}
	m, err := ParseMetadata(raw)
	if err != nil {
		return Metadata{}, err
	}
	c.mu.Lock()
	c.meta[discoveryURL] = entry[Metadata]{value: m, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return m, nil
}

// JWKS returns the key set at jwksURI. When force is true the cache
// fetches again, which handles key rotation at the provider.
func (c *Cache) JWKS(ctx context.Context, jwksURI string, force bool) (jose.JWKS, error) {
	c.mu.Lock()
	e, ok := c.keys[jwksURI]
	c.mu.Unlock()
	if ok && !force && c.now().Before(e.expires) {
		return e.value, nil
	}
	raw, err := c.get(ctx, jwksURI)
	if err != nil {
		return jose.JWKS{}, err
	}
	set, err := jose.ParseJWKS(raw)
	if err != nil {
		return jose.JWKS{}, err
	}
	c.mu.Lock()
	c.keys[jwksURI] = entry[jose.JWKS]{value: set, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
	return set, nil
}

func (c *Cache) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, wrap(ErrUpstream, "build request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, wrap(ErrUpstream, "%v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, wrap(ErrUpstream, "read %s: %v", u, err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s returned %d", ErrUpstream, u, res.StatusCode)
	}
	return body, nil
}
