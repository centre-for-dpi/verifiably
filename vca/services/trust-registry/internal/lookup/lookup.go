// SPDX-License-Identifier: Apache-2.0

// Package lookup answers TrustLookup from a cached, signature checked
// copy of the published lists (ADR-011 decision 7). The cache never
// reads the store. It reads the published files, checks their
// signatures with the JWKS, and keeps the entries with provenance.
// When the copy is older than the maximum age, the policy decides:
// fail-open answers from the stale copy, fail-closed answers unavailable.
package lookup

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// Policy names what the cache does with a stale copy.
type Policy string

// Policies.
const (
	FailOpen   Policy = "fail-open"
	FailClosed Policy = "fail-closed"
)

// Outcome extends the entry outcomes with unavailable.
type Outcome string

// Outcomes.
const (
	Trusted     Outcome = Outcome(entry.Trusted)
	Untrusted   Outcome = Outcome(entry.Untrusted)
	Unknown     Outcome = Outcome(entry.Unknown)
	Unavailable Outcome = "unavailable"
)

// ParsePolicy reads a policy name. Empty means fail-closed.
func ParsePolicy(s string) (Policy, error) {
	switch Policy(s) {
	case "", FailClosed:
		return FailClosed, nil
	case FailOpen:
		return FailOpen, nil
	}
	return "", fmt.Errorf("lookup: unknown policy %q, use fail-open or fail-closed", s)
}

// Options configure the cache.
type Options struct {
	Policy Policy
	// MaxAge is how long a checked copy stays fresh. Zero means one hour.
	MaxAge time.Duration
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Provenance says which list gave an answer.
type Provenance struct {
	Method    string
	ListURL   string
	KeyID     string
	CheckedAt time.Time
	// Stale is true when the copy is older than the maximum age.
	Stale bool
}

// Result is the answer of Lookup.
type Result struct {
	Outcome Outcome
	Entry   *entry.Entry
	Reason  string
	Provenance
}

// copy is one signature checked list.
type copy struct {
	publish.Verified
	checkedAt time.Time
}

// Cache holds one checked copy per method.
type Cache struct {
	mu         sync.RWMutex
	publishers []publish.Publisher
	jwks       func() jose.JWKS
	opts       Options
	copies     map[string]copy
}

// New builds an empty cache. jwks returns the keys that sign the lists.
func New(publishers []publish.Publisher, jwks func() jose.JWKS, opts Options) *Cache {
	if opts.MaxAge <= 0 {
		opts.MaxAge = time.Hour
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Policy == "" {
		opts.Policy = FailClosed
	}
	return &Cache{publishers: publishers, jwks: jwks, opts: opts, copies: map[string]copy{}}
}

// Refresh checks every published method in the snapshot and replaces
// the copies. A method that fails the check keeps its old copy, and
// Refresh returns the error after it has checked the other methods.
func (c *Cache) Refresh(snap *publish.Snapshot) error {
	now := c.opts.Now()
	set := c.jwks()
	var errs []error
	for _, p := range c.publishers {
		pub, ok := snap.Publication(p.Method())
		if !ok {
			continue
		}
		v, err := p.Verify(pub.Files, set, now)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		c.mu.Lock()
		c.copies[p.Method()] = copy{Verified: v, checkedAt: now}
		c.mu.Unlock()
	}
	return errors.Join(errs...)
}

// Methods returns the methods with a checked copy, in publisher order.
func (c *Cache) Methods() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []string
	for _, p := range c.publishers {
		if _, ok := c.copies[p.Method()]; ok {
			out = append(out, p.Method())
		}
	}
	return out
}

// Lookup answers for one entity and role at time at.
// A trusted answer from any method wins. Otherwise an untrusted answer
// wins over unknown. A stale copy under fail-closed makes the answer
// unavailable.
func (c *Cache) Lookup(id string, role entry.Role, credentialType string, at time.Time) Result {
	now := c.opts.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	best := Result{Outcome: Unavailable, Reason: "No signed list is available."}
	for _, p := range c.publishers {
		cp, ok := c.copies[p.Method()]
		if !ok {
			continue
		}
		prov := Provenance{Method: p.Method(), ListURL: cp.ListURL, KeyID: cp.KeyID, CheckedAt: cp.checkedAt}
		prov.Stale = now.Sub(cp.checkedAt) > c.opts.MaxAge || now.After(cp.ExpiresAt)
		if prov.Stale && c.opts.Policy == FailClosed {
			return Result{Outcome: Unavailable, Reason: "The cached list is stale and the policy is fail-closed.", Provenance: prov}
		}
		r := entry.Evaluate(cp.Entries, id, role, credentialType, at)
		res := Result{Outcome: Outcome(r.Outcome), Entry: r.Entry, Reason: r.Reason, Provenance: prov}
		if res.Outcome == Trusted {
			return res
		}
		if best.Outcome == Unavailable || rank(res.Outcome) > rank(best.Outcome) {
			best = res
		}
	}
	return best
}

func rank(o Outcome) int {
	switch o {
	case Untrusted:
		return 2
	case Unknown:
		return 1
	}
	return 0
}
