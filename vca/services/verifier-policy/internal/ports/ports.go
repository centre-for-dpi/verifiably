// SPDX-License-Identifier: Apache-2.0

// Package ports builds the side effects that the pure checks of
// core/policy need: a size limited HTTP fetcher, a small cache in front
// of it (ADR-024 decision 3), an issuer key resolver over core/did and
// JWKS, and a trust list lookup over the trust registry service
// (ADR-024 decision 4).
//
// Every port is a function value, so a test injects a fake.
package ports

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
)

// JWKSPath is the path of the key set of an issuer that is a URL.
const JWKSPath = "/.well-known/jwks.json"

// ErrTooLarge reports a document over the size cap.
var ErrTooLarge = errors.New("ports: the document is too large")

// HTTPFetcher returns a fetcher that does one GET with a size cap.
// It accepts http and https URLs only.
func HTTPFetcher(client *http.Client, maxBytes int64) policy.Fetcher {
	if client == nil {
		client = http.DefaultClient
	}
	return func(ctx context.Context, url string) ([]byte, error) {
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			return nil, fmt.Errorf("ports: %q is not an http URL", url)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		// Nothing can act on a close fault of a response body.
		defer func() { ignored := resp.Body.Close(); _ = ignored }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("ports: %s returned %d", url, resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
		if err != nil {
			return nil, fmt.Errorf("ports: %w", err)
		}
		if int64(len(body)) > maxBytes {
			return nil, ErrTooLarge
		}
		return body, nil
	}
}

// entry is one cached document.
type entry struct {
	body    []byte
	expires time.Time
}

// Cache holds fetched documents for a time. It drops the oldest entry
// when it is full.
type Cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries map[string]entry
	order   []string
}

// NewCache builds a cache. A nil now uses time.Now.
func NewCache(ttl time.Duration, max int, now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{ttl: ttl, max: max, now: now, entries: map[string]entry{}}
}

// Wrap returns a fetcher that answers from the cache when it can.
func (c *Cache) Wrap(next policy.Fetcher) policy.Fetcher {
	return func(ctx context.Context, url string) ([]byte, error) {
		if body, ok := c.get(url); ok {
			return body, nil
		}
		body, err := next(ctx, url)
		if err != nil {
			return nil, err
		}
		c.put(url, body)
		return body, nil
	}
}

func (c *Cache) get(url string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[url]
	if !ok || c.now().After(e.expires) {
		return nil, false
	}
	return e.body, true
}

func (c *Cache) put(url string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.entries[url]; !seen {
		c.order = append(c.order, url)
	}
	c.entries[url] = entry{body: body, expires: c.now().Add(c.ttl)}
	for len(c.order) > c.max {
		delete(c.entries, c.order[0])
		c.order = c.order[1:]
	}
}

// docCache adapts a Cache to the core/did cache interface.
type docCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	now  func() time.Time
	docs map[string]didEntry
}

type didEntry struct {
	doc     did.Document
	expires time.Time
}

// NewDIDCache builds a cache of DID documents.
func NewDIDCache(ttl time.Duration, now func() time.Time) did.Cache {
	if now == nil {
		now = time.Now
	}
	return &docCache{ttl: ttl, now: now, docs: map[string]didEntry{}}
}

func (d *docCache) Get(id string) (did.Document, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.docs[id]
	if !ok || d.now().After(e.expires) {
		return did.Document{}, false
	}
	return e.doc, true
}

func (d *docCache) Put(id string, doc did.Document) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.docs[id] = didEntry{doc: doc, expires: d.now().Add(d.ttl)}
}

// Keys returns a resolver that reads the keys of an issuer. A DID
// resolves through core/did, which covers did:web, did:key, and did:jwk.
// An http issuer resolves through its JWKS endpoint.
func Keys(resolver did.Resolver, fetch policy.Fetcher) policy.KeyResolver {
	return func(ctx context.Context, issuer, _ string) (jose.JWKS, error) {
		switch {
		case strings.HasPrefix(issuer, "did:"):
			doc, err := resolver.Resolve(ctx, issuer)
			if err != nil {
				return jose.JWKS{}, fmt.Errorf("ports: resolve %s: %w", issuer, err)
			}
			return keysOf(doc)
		case strings.HasPrefix(issuer, "http://"), strings.HasPrefix(issuer, "https://"):
			raw, err := fetch(ctx, strings.TrimRight(issuer, "/")+JWKSPath)
			if err != nil {
				return jose.JWKS{}, err
			}
			return jose.ParseJWKS(raw)
		}
		return jose.JWKS{}, fmt.Errorf("ports: the issuer %q is not a DID or a URL", issuer)
	}
}

// keysOf turns the verification methods of a document into a key set.
func keysOf(doc did.Document) (jose.JWKS, error) {
	var set jose.JWKS
	for _, vm := range doc.VerificationMethod {
		pub, err := did.PublicKey(vm)
		if err != nil {
			continue
		}
		k, err := jose.PublicJWK(pub, vm.ID)
		if err != nil {
			continue
		}
		set.Keys = append(set.Keys, k)
	}
	if len(set.Keys) == 0 {
		return set, fmt.Errorf("ports: %s publishes no usable key", doc.ID)
	}
	return set, nil
}

// Trust returns a lookup that asks the trust registry service.
func Trust(client trustv1connect.TrustServiceClient) policy.TrustLookup {
	return func(ctx context.Context, issuer, credentialType string) (policy.Trust, error) {
		if client == nil {
			return policy.Trust{}, errors.New("ports: no trust registry is configured")
		}
		resp, err := client.TrustLookup(ctx, connect.NewRequest(&trustv1.TrustLookupRequest{
			Identifier:     &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: issuer}},
			Role:           commonv1.Role_ROLE_ISSUER,
			CredentialType: credentialType,
		}))
		if err != nil {
			return policy.Trust{}, fmt.Errorf("ports: trust lookup: %w", err)
		}
		msg := resp.Msg
		out := policy.Trust{
			DisplayName: msg.GetEntry().GetDisplayName(),
			ListURL:     msg.GetProvenance().GetListUrl(),
			Reason:      msg.GetReason(),
		}
		switch msg.GetOutcome() {
		case trustv1.TrustLookupResponse_OUTCOME_TRUSTED:
			out.Trusted = true
		case trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE:
			return out, errors.New("ports: the trust lists are not available")
		case trustv1.TrustLookupResponse_OUTCOME_UNSPECIFIED,
			trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED,
			trustv1.TrustLookupResponse_OUTCOME_UNKNOWN:
			if out.Reason == "" {
				out.Reason = "no enabled trust list names the issuer"
			}
		}
		return out, nil
	}
}
