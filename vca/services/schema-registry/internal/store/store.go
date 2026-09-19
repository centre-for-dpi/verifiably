// SPDX-License-Identifier: Apache-2.0

// Package store keeps schema versions. A version never changes after the
// store writes it, except for its state (ADR-013 decision 2). The store
// saves the whole document after each change.
//
// The store saves the state through the shared store package (ADR-004
// decision 3).
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
)

// ErrNotFound reports a missing schema or version.
var ErrNotFound = errors.New("store: no such schema version")

// document is the saved form of the state.
type document struct {
	Revision uint64                     `json:"revision"`
	Schemas  map[string][]record.Record `json:"schemas"`
}

// Options configure a store.
type Options struct {
	// NewID makes a schema id from the type. Nil means a slug plus random hex.
	NewID func(typ string) string
}

// Store holds the versions behind a mutex and saves after each change.
type Store struct {
	mu      sync.RWMutex
	backend sharedstore.Document
	doc     document
	newID   func(string) string
}

// Open reads the saved state from the document.
func Open(b sharedstore.Document, opts Options) (*Store, error) {
	data, found, err := b.Load()
	if err != nil {
		return nil, err
	}
	doc := document{Schemas: map[string][]record.Record{}}
	if found {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("store: parse state: %w", err)
		}
		if doc.Schemas == nil {
			doc.Schemas = map[string][]record.Record{}
		}
	}
	if opts.NewID == nil {
		opts.NewID = RandomID
	}
	return &Store{backend: b, doc: doc, newID: opts.NewID}, nil
}

// RandomID returns a slug of typ followed by eight random hex digits.
func RandomID(typ string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(typ) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case !strings.HasSuffix(b.String(), "-") && b.Len() > 0:
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	if slug == "" {
		slug = "schema"
	}
	var raw [4]byte
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(raw[:]); err != nil {
		panic(err)
	}
	return slug + "-" + hex.EncodeToString(raw[:])
}

// Revision returns the count of changes since the store was empty.
func (s *Store) Revision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.doc.Revision
}

// Create stores r as version 1 of a new schema in the draft state.
func (s *Store) Create(r record.Record, now time.Time) (record.Record, error) {
	if err := r.Validate(); err != nil {
		return record.Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.newID(r.Type)
	// RandomID always returns a valid id. A second draw repeats only on a
	// collision of eight random bytes.
	for !record.ValidID(id) || s.doc.Schemas[id] != nil {
		id = RandomID(r.Type)
	}
	r = fresh(r, id, 1, now)
	if err := s.write(id, []record.Record{r}); err != nil {
		return record.Record{}, err
	}
	return r, nil
}

// AddVersion stores r as the next draft version of the schema id.
func (s *Store) AddVersion(id string, r record.Record, now time.Time) (record.Record, error) {
	if err := r.Validate(); err != nil {
		return record.Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := s.doc.Schemas[id]
	if len(versions) == 0 {
		return record.Record{}, ErrNotFound
	}
	r = fresh(r, id, versions[len(versions)-1].Version+1, now)
	if err := s.write(id, append(append([]record.Record(nil), versions...), r)); err != nil {
		return record.Record{}, err
	}
	return r, nil
}

// fresh sets the fields the store owns.
func fresh(r record.Record, id string, version int, now time.Time) record.Record {
	r.ID = id
	r.Version = version
	r.State = record.StateDraft
	r.CreatedAt = now.UTC()
	r.PublishedAt = time.Time{}
	r.RetiredAt = time.Time{}
	r.ConfigurationIDs = nil
	return r
}

// Transition replaces one version with the result of fn. fn gets a copy.
func (s *Store) Transition(id string, version int, fn func(record.Record) (record.Record, error)) (record.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := s.doc.Schemas[id]
	idx := -1
	for i, v := range versions {
		if v.Version == version {
			idx = i
		}
	}
	if idx < 0 {
		return record.Record{}, ErrNotFound
	}
	next, err := fn(versions[idx])
	if err != nil {
		return record.Record{}, err
	}
	if next.ID != id || next.Version != version {
		return record.Record{}, errors.New("store: a transition cannot change the id or the version")
	}
	list := append([]record.Record(nil), versions...)
	list[idx] = next
	if err := s.write(id, list); err != nil {
		return record.Record{}, err
	}
	return next, nil
}

// write saves the versions of id.
func (s *Store) write(id string, versions []record.Record) error {
	next := document{Revision: s.doc.Revision + 1, Schemas: make(map[string][]record.Record, len(s.doc.Schemas)+1)}
	for k, v := range s.doc.Schemas {
		next.Schemas[k] = v
	}
	next.Schemas[id] = versions
	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("store: encode state: %w", err)
	}
	if err := s.backend.Save(data); err != nil {
		return err
	}
	s.doc = next
	return nil
}

// Get returns one version. Version zero returns the latest one.
func (s *Store) Get(id string, version int) (record.Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := s.doc.Schemas[id]
	if len(versions) == 0 {
		return record.Record{}, false
	}
	if version == 0 {
		return versions[len(versions)-1], true
	}
	for _, v := range versions {
		if v.Version == version {
			return v, true
		}
	}
	return record.Record{}, false
}

// Versions returns every version of id, oldest first.
func (s *Store) Versions(id string) []record.Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]record.Record(nil), s.doc.Schemas[id]...)
}

// Latest returns the newest version of every schema, ordered by id.
func (s *Store) Latest() []record.Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]record.Record, 0, len(s.doc.Schemas))
	for _, versions := range s.doc.Schemas {
		out = append(out, versions[len(versions)-1])
	}
	return record.Sorted(out)
}

// All returns every version of every schema, ordered by id and version.
func (s *Store) All() []record.Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []record.Record
	for _, versions := range s.doc.Schemas {
		out = append(out, versions...)
	}
	return record.Sorted(out)
}

// Published returns every published version, ordered by id and version.
func (s *Store) Published() []record.Record {
	var out []record.Record
	for _, r := range s.All() {
		if r.State == record.StatePublished {
			out = append(out, r)
		}
	}
	return out
}

// LatestPublished returns the newest published version of every schema.
func (s *Store) LatestPublished() []record.Record {
	latest := map[string]record.Record{}
	for _, r := range s.Published() {
		latest[r.ID] = r
	}
	out := make([]record.Record, 0, len(latest))
	for _, r := range latest {
		out = append(out, r)
	}
	return record.Sorted(out)
}
