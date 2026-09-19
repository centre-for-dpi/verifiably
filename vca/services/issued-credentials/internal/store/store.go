// SPDX-License-Identifier: Apache-2.0

// Package store keeps the issued credential log as a persisted hash
// chain (ADR-017 decision 1). Every write appends one event to the
// chain. The state of a record is the fold of its events, so a status
// change never rewrites history.
//
// The store saves the whole chain as one JSON document after each
// change. The Backend interface is a minimal local stand-in for a shared
// store package.
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

	"github.com/centre-for-dpi/vc-adapters/core/hashchain"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/record"
)

// Errors the package returns.
var (
	ErrNotFound  = errors.New("store: no record with that id")
	ErrDuplicate = errors.New("store: a record with that id exists")
)

// Backend loads and saves the whole chain document.
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

// document is the saved form of the log.
type document struct {
	Entries []hashchain.Entry `json:"entries"`
	// PrunedIDs names the records a Prune call removed. The chain keeps
	// their events, so the head still proves that nothing went missing.
	PrunedIDs []string `json:"pruned_ids,omitempty"`
}

// Store is the append only log with a read index.
type Store struct {
	mu      sync.RWMutex
	backend Backend
	chain   hashchain.Chain
	state   map[string]record.Record
	order   []string
	pruned  map[string]struct{}
}

// Open loads the chain from b and verifies every link.
func Open(b Backend) (*Store, error) {
	s := &Store{backend: b, chain: hashchain.New(), state: map[string]record.Record{}, pruned: map[string]struct{}{}}
	data, found, err := b.Load()
	if err != nil {
		return nil, err
	}
	if !found {
		return s, nil
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("store: decode: %w", err)
	}
	chain, err := hashchain.Load(doc.Entries)
	if err != nil {
		return nil, fmt.Errorf("store: the log is not intact: %w", err)
	}
	s.chain = chain
	for _, id := range doc.PrunedIDs {
		s.pruned[id] = struct{}{}
	}
	if err := s.replay(); err != nil {
		return nil, err
	}
	return s, nil
}

// replay folds every event into the read index. A pruned record does not
// come back.
func (s *Store) replay() error {
	for _, e := range s.chain.Entries() {
		var ev record.Event
		if err := json.Unmarshal(e.Body, &ev); err != nil {
			return fmt.Errorf("store: decode entry %d: %w", e.Index, err)
		}
		s.fold(ev, e)
	}
	for id := range s.pruned {
		delete(s.state, id)
	}
	kept := s.order[:0]
	for _, id := range s.order {
		if _, gone := s.pruned[id]; !gone {
			kept = append(kept, id)
		}
	}
	s.order = kept
	return nil
}

// fold applies one event to the read index.
func (s *Store) fold(ev record.Event, e hashchain.Entry) {
	switch ev.Kind {
	case record.EventIssue:
		if ev.Record == nil {
			return
		}
		r := *ev.Record
		r.PreviousHash, r.RecordHash = e.PreviousHash, e.Hash
		s.state[r.ID] = r
		s.order = append(s.order, r.ID)
	case record.EventStatus:
		if ev.Change == nil {
			return
		}
		if r, ok := s.state[ev.Change.RecordID]; ok {
			s.state[r.ID] = r.Apply(*ev.Change)
		}
	}
}

// Append writes one issue event and returns the stored record.
func (s *Store) Append(r record.Record) (record.Record, error) {
	if err := r.Validate(); err != nil {
		return record.Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state[r.ID]; ok {
		return record.Record{}, fmt.Errorf("%w: %s", ErrDuplicate, r.ID)
	}
	if r.Status == "" {
		r.Status = record.Active
	}
	return s.commit(record.Event{Kind: record.EventIssue, Record: &r})
}

// SetStatus writes one status event and returns the changed record.
func (s *Store) SetStatus(id string, status record.Status, reason string, at time.Time) (record.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.state[id]
	if !ok {
		return record.Record{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err := record.NextStatus(cur.Status, status); err != nil {
		return record.Record{}, err
	}
	change := record.Change{RecordID: id, Status: status, Reason: reason, ChangedAt: at}
	if _, err := s.commit(record.Event{Kind: record.EventStatus, Change: &change}); err != nil {
		return record.Record{}, err
	}
	return s.state[id], nil
}

// commit appends ev to the chain and saves the document. The caller
// holds the write lock.
func (s *Store) commit(ev record.Event) (record.Record, error) {
	next, entry, err := s.chain.Append(ev)
	if err != nil {
		return record.Record{}, err
	}
	if err := s.saveChain(next); err != nil {
		return record.Record{}, err
	}
	s.chain = next
	s.fold(ev, entry)
	if ev.Kind == record.EventIssue {
		return s.state[ev.Record.ID], nil
	}
	return record.Record{}, nil
}

// saveChain writes c and the pruned ids through the backend.
func (s *Store) saveChain(c hashchain.Chain) error {
	doc := document{Entries: c.Entries()}
	for id := range s.pruned {
		doc.PrunedIDs = append(doc.PrunedIDs, id)
	}
	sort.Strings(doc.PrunedIDs)
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("store: encode: %w", err)
	}
	return s.backend.Save(data)
}

// Get returns one record. ok is false when the id names none.
func (s *Store) Get(id string) (record.Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.state[id]
	return r, ok
}

// All returns every record, newest first.
func (s *Store) All() []record.Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]record.Record, 0, len(s.state))
	for _, id := range s.order {
		if r, ok := s.state[id]; ok {
			out = append(out, r)
		}
	}
	record.SortNewestFirst(out)
	return out
}

// Head describes the tip of the chain.
type Head struct {
	// RecordID is the id of the record the last entry touched.
	RecordID string
	// Hash is the hash of the last entry.
	Hash string
	// Length is the number of entries in the chain.
	Length int64
}

// Head returns the tip of the chain. ok is false on an empty chain.
func (s *Store) Head() (Head, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.chain.Head()
	if !ok {
		return Head{}, false
	}
	return Head{RecordID: recordIDOf(e.Body), Hash: e.Hash, Length: int64(s.chain.Len())}, true
}

// recordIDOf reads the record id of one entry body.
func recordIDOf(body []byte) string {
	var ev record.Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return ""
	}
	if ev.Record != nil {
		return ev.Record.ID
	}
	if ev.Change != nil {
		return ev.Change.RecordID
	}
	return ""
}

// Verify walks the chain from the entry that first wrote fromRecordID.
// An empty id starts at the first entry. It returns the number of
// entries it checked and the id of the first broken entry.
func (s *Store) Verify(fromRecordID string) (checked int64, broken string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := s.chain.Entries()
	start := 0
	if fromRecordID != "" {
		start = -1
		for i, e := range entries {
			if recordIDOf(e.Body) == fromRecordID {
				start = i
				break
			}
		}
		if start < 0 {
			return 0, "", fmt.Errorf("%w: %s", ErrNotFound, fromRecordID)
		}
	}
	prev := ""
	if start > 0 {
		prev = entries[start-1].Hash
	}
	for _, e := range entries[start:] {
		if e.PreviousHash != prev || hashchain.HashOf(e.PreviousHash, e.Body) != e.Hash {
			return checked, recordIDOf(e.Body), nil
		}
		prev = e.Hash
		checked++
	}
	return checked, "", nil
}

// Prune drops every record whose retention ended before now
// (ADR-017 decision 5). It removes the record from the read index only.
// The chain keeps every event, so the head still proves that no entry
// went missing. It returns the number of records it dropped.
func (s *Store) Prune(now time.Time) (int, error) {
	return s.PruneWhere(now, "", false)
}

// PruneWhere drops the records of one schema whose retention ended
// before now. An empty schemaID covers every schema. A dry run counts
// the records that are due and drops none.
func (s *Store) PruneWhere(now time.Time, schemaID string, dryRun bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var kept, gone []string
	for _, id := range s.order {
		r, ok := s.state[id]
		if !ok {
			continue
		}
		due := !r.RetainUntil.IsZero() && now.After(r.RetainUntil)
		if due && (schemaID == "" || r.SchemaID == schemaID) {
			gone = append(gone, id)
			continue
		}
		kept = append(kept, id)
	}
	if len(gone) == 0 || dryRun {
		return len(gone), nil
	}
	for _, id := range gone {
		s.pruned[id] = struct{}{}
	}
	if err := s.saveChain(s.chain); err != nil {
		for _, id := range gone {
			delete(s.pruned, id)
		}
		return 0, err
	}
	for _, id := range gone {
		delete(s.state, id)
	}
	s.order = kept
	return len(gone), nil
}

// Len returns the number of records the read index holds.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.order)
}

// Pruned returns the number of records that Prune removed.
func (s *Store) Pruned() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return int64(len(s.pruned))
}
