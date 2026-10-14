// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/oidc"
)

// Persister saves and loads one named JSON document. A service supplies
// a file or database backed Persister. Load leaves v unchanged and
// returns nil when the document does not exist.
type Persister interface {
	Load(name string, v any) error
	Save(name string, v any) error
}

// MemoryPersister keeps documents in process memory.
type MemoryPersister struct {
	mu   sync.Mutex
	docs map[string][]byte
}

// NewMemoryPersister returns an empty persister.
func NewMemoryPersister() *MemoryPersister {
	return &MemoryPersister{docs: map[string][]byte{}}
}

// Load implements Persister.
func (m *MemoryPersister) Load(name string, v any) error {
	m.mu.Lock()
	raw, ok := m.docs[name]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// Save implements Persister.
func (m *MemoryPersister) Save(name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.docs[name] = raw
	m.mu.Unlock()
	return nil
}

// providersDoc is the persisted document name.
const providersDoc = "providers"

// Registry holds the registered providers (ADR-012 decision 5). Every
// change is written through the Persister.
type Registry struct {
	store Persister
	now   func() time.Time
	mu    sync.RWMutex
	m     map[string]Provider
}

// NewRegistry loads the providers from store.
func NewRegistry(store Persister, now func() time.Time) (*Registry, error) {
	if store == nil {
		store = NewMemoryPersister()
	}
	if now == nil {
		now = time.Now
	}
	var list []Provider
	if err := store.Load(providersDoc, &list); err != nil {
		return nil, err
	}
	r := &Registry{store: store, now: now, m: map[string]Provider{}}
	for _, p := range list {
		r.m[p.ID] = p
	}
	return r, nil
}

// Get returns one provider.
func (r *Registry) Get(id string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.m[id]
	if !ok {
		return Provider{}, wrap(ErrProviderNotFound, "%q", id)
	}
	return p, nil
}

// List returns every provider sorted by id.
func (r *Registry) List() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, 0, len(r.m))
	for _, p := range r.m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Enabled returns the providers that accept logins, sorted by id.
func (r *Registry) Enabled() []Provider {
	var out []Provider
	for _, p := range r.List() {
		if p.Enabled {
			out = append(out, p)
		}
	}
	return out
}

// Put creates or replaces a provider. An empty id gets a random id.
func (r *Registry) Put(p Provider) (Provider, error) {
	if p.ID == "" {
		p.ID = randomID()
	}
	if err := p.Validate(); err != nil {
		return Provider{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.m[p.ID]; ok && !old.CreatedAt.IsZero() {
		p.CreatedAt = old.CreatedAt
	} else if p.CreatedAt.IsZero() {
		p.CreatedAt = r.now().UTC()
	}
	prev, had := r.m[p.ID]
	r.m[p.ID] = p
	if err := r.save(); err != nil {
		if had {
			r.m[p.ID] = prev
		} else {
			delete(r.m, p.ID)
		}
		return Provider{}, err
	}
	return p, nil
}

// Seed stores the seeded provider when the registry has no record with
// its id, so a stored record, edited through the admin RPCs, survives a
// restart (ADR-035 decision 2). A stored record that still names the one
// realm of an earlier setup at the same Keycloak moves to the realm of
// the seed, as setup moves the .env of the pair (ADR-035 decision 1),
// and keeps its other edits.
func (r *Registry) Seed(p Provider) error {
	stored, err := r.Get(p.ID)
	if err != nil {
		_, err := r.Put(p)
		return err
	}
	if !namesLegacyRealm(stored.DiscoveryURL, p.DiscoveryURL) {
		return nil
	}
	stored.DiscoveryURL = p.DiscoveryURL
	stored.Realm = p.Realm
	stored.ConsoleURL = p.ConsoleURL
	_, err = r.Put(stored)
	return err
}

// legacyRealm is the one realm of every role that an earlier setup
// wrote, before one realm per role (ADR-035 decision 1).
const legacyRealm = "vca"

// namesLegacyRealm reports whether stored is the discovery URL of the
// legacy realm at the Keycloak that seeded names.
func namesLegacyRealm(stored, seeded string) bool {
	realm, ok := KeycloakRealmOf(stored)
	if !ok || realm != legacyRealm {
		return false
	}
	if _, ok := KeycloakRealmOf(seeded); !ok {
		return false
	}
	return oidc.Authority(stored) == oidc.Authority(seeded)
}

// seededDoc names the document that lists the ids SeedOnce wrote.
const seededDoc = "providers-seeded"

// SeedOnce stores a seeded provider the first time only. The registry
// remembers each id it seeded, so an admin who removes the record keeps
// it removed after a restart (ADR-052 decision 2). A record that exists
// already counts as seeded. It reports whether it wrote the record.
func (r *Registry) SeedOnce(p Provider) (bool, error) {
	var seeded []string
	if err := r.store.Load(seededDoc, &seeded); err != nil {
		return false, err
	}
	if slices.Contains(seeded, p.ID) {
		return false, nil
	}
	_, err := r.Get(p.ID)
	wrote := err != nil
	if wrote {
		if _, err := r.Put(p); err != nil {
			return false, err
		}
	}
	if err := r.store.Save(seededDoc, append(seeded, p.ID)); err != nil {
		return false, err
	}
	return wrote, nil
}

// OnlyDefault clears the default flag of every provider but id, so one
// record takes the logins that pick the default.
func (r *Registry) OnlyDefault(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := map[string]Provider{}
	for other, p := range r.m {
		if other != id && p.IsDefault {
			prev[other] = p
			p.IsDefault = false
			r.m[other] = p
		}
	}
	if len(prev) == 0 {
		return nil
	}
	if err := r.save(); err != nil {
		maps.Copy(r.m, prev)
		return err
	}
	return nil
}

// Delete removes a provider.
func (r *Registry) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.m[id]
	if !ok {
		return wrap(ErrProviderNotFound, "%q", id)
	}
	delete(r.m, id)
	if err := r.save(); err != nil {
		r.m[id] = p
		return err
	}
	return nil
}

func (r *Registry) save() error {
	list := make([]Provider, 0, len(r.m))
	for _, p := range r.m {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return r.store.Save(providersDoc, list)
}
