// SPDX-License-Identifier: Apache-2.0

// Package store keeps trust entries with versions. Each edit raises the
// entry version and the store revision. The revision is the sequence
// number of the next publication.
//
// The store saves the whole state through the shared store package
// (ADR-004 decision 3).
package store

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/entry"
)

// document is the saved form of the state.
type document struct {
	Revision uint64                 `json:"revision"`
	Entries  map[string]entry.Entry `json:"entries"`
}

// Store holds the entries behind a mutex and saves after each change.
type Store struct {
	mu      sync.RWMutex
	backend sharedstore.Document
	doc     document
}

// Open reads the saved state from the document.
func Open(b sharedstore.Document) (*Store, error) {
	data, found, err := b.Load()
	if err != nil {
		return nil, err
	}
	doc := document{Entries: map[string]entry.Entry{}}
	if found {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("store: parse state: %w", err)
		}
		if doc.Entries == nil {
			doc.Entries = map[string]entry.Entry{}
		}
	}
	return &Store{backend: b, doc: doc}, nil
}

// Revision returns the count of changes since the store was empty.
func (s *Store) Revision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.doc.Revision
}

// Get returns the entry with id.
func (s *Store) Get(id string) (entry.Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.doc.Entries[id]
	return e, ok
}

// List returns every entry ordered by id.
func (s *Store) List() []entry.Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]entry.Entry, 0, len(s.doc.Entries))
	for _, e := range s.doc.Entries {
		out = append(out, e)
	}
	return entry.Sorted(out)
}

// Upsert validates e, sets its version and updated_at, and saves it.
// created is true when no entry with the same id existed.
func (s *Store) Upsert(e entry.Entry, now time.Time) (stored entry.Entry, created bool, err error) {
	if err := e.Validate(); err != nil {
		return entry.Entry{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.doc.Entries[e.ID()]
	e.Version = old.Version + 1
	e.UpdatedAt = now.UTC()
	if e.Source == "" {
		e.Source = entry.SourceAdmin
	}
	next := s.snapshot()
	next.Entries[e.ID()] = e
	next.Revision++
	if err := s.save(next); err != nil {
		return entry.Entry{}, false, err
	}
	return e, !exists, nil
}

// Delete removes the entry with id. found is false when it did not exist.
func (s *Store) Delete(id string) (found bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.doc.Entries[id]; !ok {
		return false, nil
	}
	next := s.snapshot()
	delete(next.Entries, id)
	next.Revision++
	if err := s.save(next); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) snapshot() document {
	next := document{Revision: s.doc.Revision, Entries: make(map[string]entry.Entry, len(s.doc.Entries)+1)}
	for k, v := range s.doc.Entries {
		next.Entries[k] = v
	}
	return next
}

func (s *Store) save(next document) error {
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
