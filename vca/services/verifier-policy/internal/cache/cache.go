// SPDX-License-Identifier: Apache-2.0

// Package cache keeps signature checked copies of the trust material of
// the verifier policy service (ADR-041): the signed trust snapshot of the
// trust registry, the registry keys (the key set of the registry, the
// DID documents and key sets of the listed issuers, and the X.509 anchor
// chains of the external registries), and the status lists.
//
// A sync reads each source and checks its signature or its anchor before
// it stores the copy. A copy that fails the check is refused and the last
// good copy stays. A schedule reads each kind on its own interval.
//
// The ports of an evaluation ask the network first. When a source does
// not answer and the policy allows checks with no network, a port answers
// from the copy inside the offline window and records the age of the
// material. A copy older than the window fails the check that needs it.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// Kind names one kind of cached material.
type Kind string

// The three kinds, in sync order.
const (
	KindTrust  Kind = "trust_list"
	KindKeys   Kind = "registry_keys"
	KindStatus Kind = "status_list"
)

// Kinds returns every kind in sync order: the trust list names the
// issuers, the keys check the status lists.
func Kinds() []Kind { return []Kind{KindTrust, KindKeys, KindStatus} }

// Bounds of the policy (ADR-041 decisions 2 and 3).
const (
	// MaxWindow is the longest offline window.
	MaxWindow = 7 * 24 * time.Hour
	// MinRefresh is the shortest refresh interval.
	MinRefresh = time.Minute
)

// Policy says how often each kind is read and when a check may use a
// copy with no network.
type Policy struct {
	TrustRefresh  time.Duration `json:"trust_refresh"`
	KeysRefresh   time.Duration `json:"keys_refresh"`
	StatusRefresh time.Duration `json:"status_refresh"`
	// AllowOffline lets a check read a copy when a source does not answer.
	AllowOffline bool `json:"allow_offline"`
	// Window is how long after its last good read a copy stays usable.
	Window time.Duration `json:"window"`
	// MarkStale marks a result that read a copy older than its refresh
	// interval.
	MarkStale bool `json:"mark_stale"`
	// RefuseStaleStatus fails the status check on a status list copy
	// older than the window, in every fail mode.
	RefuseStaleStatus bool `json:"refuse_stale_status"`
}

// DefaultPolicy is the policy of ADR-041 decision 2, with checks that
// need the network.
func DefaultPolicy() Policy {
	return Policy{
		TrustRefresh: 6 * time.Hour, KeysRefresh: 24 * time.Hour, StatusRefresh: time.Hour,
		Window: 24 * time.Hour, MarkStale: true, RefuseStaleStatus: true,
	}
}

// Refresh returns the refresh interval of a kind.
func (p Policy) Refresh(k Kind) time.Duration {
	switch k {
	case KindTrust:
		return p.TrustRefresh
	case KindKeys:
		return p.KeysRefresh
	case KindStatus:
		return p.StatusRefresh
	}
	return p.StatusRefresh
}

// ErrPolicy reports a policy out of its bounds.
var ErrPolicy = errors.New("cache: the policy is not valid")

// Check reports every value out of its bounds.
func (p Policy) Check() error {
	var problems []string
	for _, k := range Kinds() {
		if p.Refresh(k) < MinRefresh {
			problems = append(problems, fmt.Sprintf("the refresh of %s must be at least %s", k, MinRefresh))
		}
	}
	if p.Window <= 0 || p.Window > MaxWindow {
		problems = append(problems, "the offline window must be more than zero and at most 7 days")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrPolicy, strings.Join(problems, "; "))
	}
	return nil
}

// withDefaults fills each zero duration from d.
func (p Policy) withDefaults(d Policy) Policy {
	for _, pair := range []struct{ v, d *time.Duration }{
		{&p.TrustRefresh, &d.TrustRefresh}, {&p.KeysRefresh, &d.KeysRefresh},
		{&p.StatusRefresh, &d.StatusRefresh}, {&p.Window, &d.Window},
	} {
		if *pair.v == 0 {
			*pair.v = *pair.d
		}
	}
	return p
}

// Source is the stored state of one source and its last good copy.
type Source struct {
	Kind Kind   `json:"kind"`
	Key  string `json:"key"`
	// Body is the last good copy: the snapshot JWS, a key set as JSON,
	// PEM certificates, or a status list document.
	Body []byte `json:"body,omitempty"`
	// SyncedAt is the time of the last good read.
	SyncedAt time.Time `json:"synced_at,omitzero"`
	// ReadAt is the time of the last read, good or failed.
	ReadAt time.Time `json:"read_at,omitzero"`
	// LastError is the reason of the last failed read or refusal.
	LastError string `json:"last_error,omitempty"`
	// SignedBy is the key id or the certificate subject that signed the
	// copy, the DID of a DID document, or NotChecked.
	SignedBy string `json:"signed_by,omitempty"`
	// Items counts the entries, keys, or certificates of the copy.
	Items int `json:"items"`
	// Issuer is the issuer the keys or the status list belong to.
	Issuer string `json:"issuer,omitempty"`
	// RegistryID and RegistryName name the external registry the source
	// comes from. Empty means the trust registry of the deployment.
	RegistryID   string `json:"registry_id,omitempty"`
	RegistryName string `json:"registry_name,omitempty"`
}

// Good reports whether the source holds a good copy.
func (s Source) Good() bool { return !s.SyncedAt.IsZero() }

// NotChecked is the SignedBy of a status list document with no JWS.
const NotChecked = "not checked"

// Options configure a cache.
type Options struct {
	// KV keeps the copies and the policy. Nil keeps them in memory.
	KV store.KeyValue
	// TrustURL is the base URL of the trust registry. Its key set sits
	// at TrustURL plus JWKSPath.
	TrustURL string
	// Snapshot returns the signed snapshot of the trust registry. Nil
	// means the deployment has no trust registry.
	Snapshot func(context.Context) (string, error)
	// Fetch reads key sets, DID documents, and status lists.
	Fetch policy.Fetcher
	// Defaults is the policy until SetPolicy stores one.
	Defaults Policy
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the failed reads. Nil means slog.Default.
	Log *slog.Logger
}

// JWKSPath is the path of the key set of the trust registry.
const JWKSPath = "/.well-known/jwks.json"

// policyKey is the store key of the policy.
const policyKey = "cache-policy"

// sourcePrefix starts the store key of every source.
const sourcePrefix = "cache/"

// Cache keeps the copies. It holds no package state.
type Cache struct {
	opts Options
	// syncing serialises the reads.
	syncing sync.Mutex
	// mu guards runs.
	mu   sync.Mutex
	runs map[Kind]time.Time
}

// New builds a cache.
func New(opts Options) (*Cache, error) {
	if opts.Fetch == nil {
		return nil, errors.New("cache: a fetcher is required")
	}
	if opts.KV == nil {
		opts.KV = store.Memory()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	opts.Defaults = opts.Defaults.withDefaults(DefaultPolicy())
	if err := opts.Defaults.Check(); err != nil {
		return nil, err
	}
	opts.TrustURL = strings.TrimRight(opts.TrustURL, "/")
	return &Cache{opts: opts, runs: map[Kind]time.Time{}}, nil
}

func (c *Cache) now() time.Time { return c.opts.Now() }

// jwksURL returns the URL of the key set of the trust registry.
func (c *Cache) jwksURL() string { return c.opts.TrustURL + JWKSPath }

// Policy returns the stored policy, or the defaults.
func (c *Cache) Policy(ctx context.Context) Policy {
	raw, err := c.opts.KV.Get(ctx, policyKey)
	if err != nil {
		return c.opts.Defaults
	}
	var p Policy
	if json.Unmarshal(raw, &p) != nil {
		return c.opts.Defaults
	}
	return p.withDefaults(c.opts.Defaults)
}

// SetPolicy stores p. A zero duration takes the default.
func (c *Cache) SetPolicy(ctx context.Context, p Policy) (Policy, error) {
	p = p.withDefaults(c.opts.Defaults)
	if err := p.Check(); err != nil {
		return Policy{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return Policy{}, fmt.Errorf("cache: encode the policy: %w", err)
	}
	if err := c.opts.KV.Put(ctx, policyKey, raw); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// storeKey returns the store key of a source.
func storeKey(kind Kind, key string) string {
	sum := sha256.Sum256([]byte(key))
	return sourcePrefix + string(kind) + "/" + hex.EncodeToString(sum[:12])
}

// load returns one source.
func (c *Cache) load(ctx context.Context, kind Kind, key string) (Source, bool) {
	raw, err := c.opts.KV.Get(ctx, storeKey(kind, key))
	if err != nil {
		return Source{}, false
	}
	var s Source
	if json.Unmarshal(raw, &s) != nil {
		return Source{}, false
	}
	return s, true
}

// save stores one source.
func (c *Cache) save(ctx context.Context, s Source) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("cache: encode %s: %w", s.Key, err)
	}
	return c.opts.KV.Put(ctx, storeKey(s.Kind, s.Key), raw)
}

// sources returns the sources of one kind, by key.
func (c *Cache) sources(ctx context.Context, kind Kind) ([]Source, error) {
	keys, err := c.opts.KV.List(ctx, sourcePrefix+string(kind)+"/")
	if err != nil {
		return nil, err
	}
	out := make([]Source, 0, len(keys))
	for _, k := range keys {
		raw, gerr := c.opts.KV.Get(ctx, k)
		if gerr != nil {
			return nil, gerr
		}
		var s Source
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// remember adds a source the schedule reads from now on. A known source
// stays as it is.
func (c *Cache) remember(ctx context.Context, kind Kind, key, issuer string) {
	if _, ok := c.load(ctx, kind, key); ok {
		return
	}
	if err := c.save(ctx, Source{Kind: kind, Key: key, Issuer: issuer}); err != nil {
		c.opts.Log.Warn("cache: remember a source", "kind", kind, "source", key, "error", err)
	}
}

// KindState sums up the sources of one kind.
type KindState struct {
	Kind Kind
	// SyncedAt is the time of the oldest good copy. Zero means none.
	SyncedAt time.Time
	// NextSync is the time the schedule reads the kind next.
	NextSync time.Time
	Sources  int
	Items    int
	Issuers  int
	Failed   int
}

// State is the policy, the state of each kind, and every source.
type State struct {
	Policy  Policy
	Kinds   []KindState
	Sources []Source
}

// State returns the state of the cache.
func (c *Cache) State(ctx context.Context) (State, error) {
	out := State{Policy: c.Policy(ctx)}
	for _, k := range Kinds() {
		list, err := c.sources(ctx, k)
		if err != nil {
			return State{}, err
		}
		ks := KindState{Kind: k, NextSync: c.nextSync(k, out.Policy)}
		issuers := map[string]bool{}
		for _, s := range list {
			if s.LastError != "" {
				ks.Failed++
			}
			if !s.Good() {
				continue
			}
			ks.Sources++
			ks.Items += s.Items
			if ks.SyncedAt.IsZero() || s.SyncedAt.Before(ks.SyncedAt) {
				ks.SyncedAt = s.SyncedAt
			}
			if s.Issuer != "" {
				issuers[s.Issuer] = true
			}
		}
		ks.Issuers = len(issuers)
		if k == KindTrust {
			ks.Issuers = c.trustIssuers(ctx)
		}
		out.Kinds = append(out.Kinds, ks)
		out.Sources = append(out.Sources, list...)
	}
	return out, nil
}

// nextSync returns the time the schedule reads kind next.
func (c *Cache) nextSync(k Kind, p Policy) time.Time {
	c.mu.Lock()
	last, ok := c.runs[k]
	c.mu.Unlock()
	if !ok {
		return c.now()
	}
	return last.Add(p.Refresh(k))
}
