// SPDX-License-Identifier: Apache-2.0

// Package store keeps sources and field maps. It saves the whole state
// as one JSON document after each change. The Backend interface is a
// minimal local stand-in for a shared store package.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/source"
)

// ErrNotFound says the id names no record.
var ErrNotFound = errors.New("store: not found")

// Backend loads and saves the whole state document.
type Backend interface {
	// Load returns the saved document. found is false on first use.
	Load() (data []byte, found bool, err error)
	// Save writes the document.
	Save(data []byte) error
}

type memory struct {
	mu   sync.Mutex
	data []byte
}

// Memory returns a backend that keeps the document in the process.
func Memory() Backend { return &memory{} }

func (m *memory) Load() ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		return nil, false, nil
	}
	return append([]byte(nil), m.data...), true, nil
}

func (m *memory) Save(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append([]byte(nil), data...)
	return nil
}

type file struct{ path string }

// File returns a backend that keeps the document at path. Save writes a
// temporary file and renames it.
func File(path string) Backend { return file{path: path} }

func (f file) Load() ([]byte, bool, error) {
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: read %s: %w", f.path, err)
	}
	return data, true, nil
}

func (f file) Save(data []byte) error {
	tmp := filepath.Join(filepath.Dir(f.path), "."+filepath.Base(f.path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("store: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("store: rename %s: %w", tmp, err)
	}
	return nil
}

// document is the saved form of the state.
type document struct {
	Sequence  uint64                      `json:"sequence"`
	Sources   map[string]source.Source    `json:"sources"`
	FieldMaps map[string]mapping.FieldMap `json:"field_maps"`
}

// Store holds the state behind a mutex.
type Store struct {
	mu      sync.RWMutex
	backend Backend
	doc     document
}

// Open reads the saved state from b.
func Open(b Backend) (*Store, error) {
	data, found, err := b.Load()
	if err != nil {
		return nil, err
	}
	doc := document{}
	if found {
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("store: parse state: %w", err)
		}
	}
	if doc.Sources == nil {
		doc.Sources = map[string]source.Source{}
	}
	if doc.FieldMaps == nil {
		doc.FieldMaps = map[string]mapping.FieldMap{}
	}
	return &Store{backend: b, doc: doc}, nil
}

// MapKey returns the field map key of a source and schema pair.
func MapKey(sourceID, schemaID string) string { return sourceID + "\x00" + schemaID }

// Get returns the source with id.
func (s *Store) Get(id string) (source.Source, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src, ok := s.doc.Sources[id]
	return src, ok
}

// List returns every source ordered by creation time, then id.
func (s *Store) List() []source.Source {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]source.Source, 0, len(s.doc.Sources))
	for _, src := range s.doc.Sources {
		out = append(out, src)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Create validates src, assigns an id and the timestamps, and saves it.
func (s *Store) Create(src source.Source, now time.Time) (source.Source, error) {
	if err := src.Validate(); err != nil {
		return source.Source{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.snapshot()
	next.Sequence++
	src.ID = fmt.Sprintf("src-%d", next.Sequence)
	src.CreatedAt = now.UTC()
	src.UpdatedAt = src.CreatedAt
	next.Sources[src.ID] = src
	if err := s.save(next); err != nil {
		return source.Source{}, err
	}
	return src, nil
}

// Update validates src and replaces the record with the same id. It
// keeps the creation time.
func (s *Store) Update(src source.Source, now time.Time) (source.Source, error) {
	if err := src.Validate(); err != nil {
		return source.Source{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.doc.Sources[src.ID]
	if !ok {
		return source.Source{}, fmt.Errorf("%w: source %s", ErrNotFound, src.ID)
	}
	src.CreatedAt = old.CreatedAt
	src.UpdatedAt = now.UTC()
	next := s.snapshot()
	next.Sources[src.ID] = src
	if err := s.save(next); err != nil {
		return source.Source{}, err
	}
	return src, nil
}

// Delete removes the source with id and its field maps.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.doc.Sources[id]; !ok {
		return fmt.Errorf("%w: source %s", ErrNotFound, id)
	}
	next := s.snapshot()
	delete(next.Sources, id)
	for k, fm := range next.FieldMaps {
		if fm.SourceID == id {
			delete(next.FieldMaps, k)
		}
	}
	return s.save(next)
}

// GetFieldMap returns the map of a source and schema pair.
func (s *Store) GetFieldMap(sourceID, schemaID string) (mapping.FieldMap, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fm, ok := s.doc.FieldMaps[MapKey(sourceID, schemaID)]
	return fm, ok
}

// SetFieldMap validates fm and stores it. The source must exist.
func (s *Store) SetFieldMap(fm mapping.FieldMap) error {
	if err := fm.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.doc.Sources[fm.SourceID]; !ok {
		return fmt.Errorf("%w: source %s", ErrNotFound, fm.SourceID)
	}
	next := s.snapshot()
	next.FieldMaps[MapKey(fm.SourceID, fm.SchemaID)] = fm
	return s.save(next)
}

func (s *Store) snapshot() document {
	next := document{
		Sequence:  s.doc.Sequence,
		Sources:   make(map[string]source.Source, len(s.doc.Sources)+1),
		FieldMaps: make(map[string]mapping.FieldMap, len(s.doc.FieldMaps)+1),
	}
	for k, v := range s.doc.Sources {
		next.Sources[k] = v
	}
	for k, v := range s.doc.FieldMaps {
		next.FieldMaps[k] = v
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
