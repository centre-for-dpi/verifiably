// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/services/internal/trustsnap"
)

// Usage records the cached material one evaluation read. It is safe for
// concurrent use.
type Usage struct {
	mu     sync.Mutex
	used   bool
	oldest time.Duration
	stale  bool
}

// usageKey is the context key of the Usage of an evaluation.
type usageKey struct{}

// Track returns a context that records the cached material the ports
// read, and the record.
func Track(ctx context.Context) (context.Context, *Usage) {
	u := &Usage{}
	return context.WithValue(ctx, usageKey{}, u), u
}

// Age returns the age of the oldest cached material read, and whether
// the evaluation read any.
func (u *Usage) Age() (time.Duration, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.oldest, u.used
}

// Stale reports whether a read copy was older than its refresh interval
// and the policy marks such results.
func (u *Usage) Stale() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.stale
}

// add records one read copy.
func (u *Usage) add(age time.Duration, stale bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.used = true
	if age > u.oldest {
		u.oldest = age
	}
	u.stale = u.stale || stale
}

// usageOf returns the Usage of ctx, or nil.
func usageOf(ctx context.Context) *Usage {
	if u, ok := ctx.Value(usageKey{}).(*Usage); ok {
		return u
	}
	return nil
}

// material returns the copy of a source for an evaluation whose online
// read failed with cause. It returns cause when the policy does not
// allow checks with no network or no copy exists. A copy older than the
// window gives policy.ErrStale, except a status list when the policy
// leaves stale status lists to the fail mode.
func (c *Cache) material(ctx context.Context, kind Kind, key string, cause error) (Source, error) {
	p := c.Policy(ctx)
	if !p.AllowOffline {
		return Source{}, cause
	}
	s, ok := c.load(ctx, kind, key)
	if !ok || !s.Good() {
		return Source{}, cause
	}
	age := c.now().Sub(s.SyncedAt)
	if age > p.Window {
		if kind == KindStatus && !p.RefuseStaleStatus {
			return Source{}, cause
		}
		return Source{}, fmt.Errorf("cache: %s was read %s ago: %w", key, age.Round(time.Minute), policy.ErrStale)
	}
	if u := usageOf(ctx); u != nil {
		u.add(age, p.MarkStale && age > p.Refresh(kind))
	}
	return s, nil
}

// Trust wraps an online trust lookup. When it fails, the lookup answers
// from the stored snapshot.
func (c *Cache) Trust(online policy.TrustLookup) policy.TrustLookup {
	return func(ctx context.Context, issuer, credentialType string) (policy.Trust, error) {
		t, err := online(ctx, issuer, credentialType)
		if err == nil {
			return t, nil
		}
		s, err := c.material(ctx, KindTrust, c.opts.TrustURL, err)
		if err != nil {
			return policy.Trust{}, err
		}
		claims, err := decodeClaims(s.Body)
		if err != nil {
			return policy.Trust{}, fmt.Errorf("cache: the stored snapshot: %w", err)
		}
		a := claims.Lookup(issuer, credentialType, c.now())
		return policy.Trust{
			Trusted: a.Outcome == trustsnap.Trusted, DisplayName: a.Name, ListURL: a.ListURL,
			Reason: a.Reason, Registry: a.RegistryName,
		}, nil
	}
}

// Keys wraps an online key resolver. An issuer it resolves joins the
// schedule. When it fails, the resolver answers from the stored keys.
func (c *Cache) Keys(online policy.KeyResolver) policy.KeyResolver {
	return func(ctx context.Context, issuer, kid string) (jose.JWKS, error) {
		set, err := online(ctx, issuer, kid)
		if err == nil {
			if networkIssuer(issuer) {
				c.remember(ctx, KindKeys, issuer, issuer)
			}
			return set, nil
		}
		s, err := c.material(ctx, KindKeys, issuer, err)
		if err != nil {
			return jose.JWKS{}, err
		}
		var stored jose.JWKS
		if err := json.Unmarshal(s.Body, &stored); err != nil {
			return jose.JWKS{}, fmt.Errorf("cache: the stored keys of %s: %w", issuer, err)
		}
		return stored, nil
	}
}

// Status wraps an online status list fetcher. A list it reads joins the
// schedule. When it fails, the fetcher answers from the stored list.
func (c *Cache) Status(online policy.Fetcher) policy.Fetcher {
	return func(ctx context.Context, url string) ([]byte, error) {
		raw, err := online(ctx, url)
		if err == nil {
			c.remember(ctx, KindStatus, url, "")
			return raw, nil
		}
		s, err := c.material(ctx, KindStatus, url, err)
		if err != nil {
			return nil, err
		}
		return s.Body, nil
	}
}
