// SPDX-License-Identifier: Apache-2.0

// Package store is the key value store every service uses for its state
// (ADR-018 decision 5, ADR-019 decision 4). A key names one document.
// A document is a byte slice, usually JSON.
//
// Two backends exist. Memory keeps documents in the process. File keeps
// one JSON file per key under a directory and writes each file through
// an atomic rename, so a reader never sees a partial document. A
// PostgreSQL backend is a follow-up. The interface is small on purpose
// so that a backend is easy to add.
//
// A key has one or more segments separated by "/". A segment holds
// letters, digits, ".", "_", and "-" only. A segment is never "." or "..".
package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ErrNotFound reports that no document has the key.
var ErrNotFound = errors.New("store: not found")

// ErrConflict reports that CompareAndSwap saw a different document.
var ErrConflict = errors.New("store: conflict")

// ErrBadKey reports a key that breaks the key rules.
var ErrBadKey = errors.New("store: bad key")

// KeyValue is the store interface.
type KeyValue interface {
	// Get returns the document with key. It returns ErrNotFound when
	// none exists.
	Get(ctx context.Context, key string) ([]byte, error)
	// Put writes the document with key. It replaces any document.
	Put(ctx context.Context, key string, value []byte) error
	// Delete removes the document with key. A missing key is not an error.
	Delete(ctx context.Context, key string) error
	// List returns every key with the prefix in sorted order.
	List(ctx context.Context, prefix string) ([]string, error)
	// CompareAndSwap writes value when the current document equals old.
	// A nil old means the key must not exist. It returns ErrConflict when
	// the current document differs.
	CompareAndSwap(ctx context.Context, key string, old, value []byte) error
}

// ValidateKey checks the key rules.
func ValidateKey(key string) error {
	if key == "" {
		return fmt.Errorf("%w: empty", ErrBadKey)
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("%w: %q has an empty or dot segment", ErrBadKey, key)
		}
		for _, r := range seg {
			if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
				return fmt.Errorf("%w: %q has the character %q", ErrBadKey, key, r)
			}
		}
	}
	return nil
}

// memory keeps documents in a map.
type memory struct {
	mu   sync.RWMutex
	docs map[string][]byte
}

// Memory returns a store that keeps documents in the process.
func Memory() KeyValue { return &memory{docs: map[string][]byte{}} }

func (m *memory) Get(_ context.Context, key string) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.docs[key]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(v), nil
}

func (m *memory) Put(_ context.Context, key string, value []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.docs[key] = clone(value)
	return nil
}

func (m *memory) Delete(_ context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.docs, key)
	return nil
}

func (m *memory) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for k := range m.docs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *memory) CompareAndSwap(_ context.Context, key string, old, value []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.docs[key]
	if !same(cur, ok, old) {
		return ErrConflict
	}
	m.docs[key] = clone(value)
	return nil
}

// file keeps one file per key under dir.
type file struct {
	mu  sync.Mutex
	dir string
}

// Extension is the suffix of every file the File backend writes.
const Extension = ".json"

// File returns a store that keeps one file per key under dir. It creates
// dir when it does not exist.
func File(dir string) (KeyValue, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", dir, err)
	}
	return &file{dir: dir}, nil
}

func (f *file) path(key string) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
	}
	return filepath.Join(f.dir, filepath.FromSlash(key)+Extension), nil
}

func (f *file) Get(_ context.Context, key string) ([]byte, error) {
	p, err := f.path(key)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.read(p)
}

func (f *file) read(p string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(p))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", p, err)
	}
	return data, nil
}

func (f *file) Put(_ context.Context, key string, value []byte) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.write(p, value)
}

func (f *file) write(p string, value []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("store: create %s: %w", filepath.Dir(p), err)
	}
	tmp := filepath.Join(filepath.Dir(p), "."+filepath.Base(p)+".tmp")
	if err := os.WriteFile(tmp, value, 0o600); err != nil {
		return fmt.Errorf("store: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("store: rename %s: %w", tmp, err)
	}
	return nil
}

func (f *file) Delete(_ context.Context, key string) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("store: remove %s: %w", p, err)
	}
	return nil
}

func (f *file) List(_ context.Context, prefix string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	err := filepath.WalkDir(f.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), Extension) || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		rel, err := filepath.Rel(f.dir, p)
		if err != nil {
			return err
		}
		key := strings.TrimSuffix(filepath.ToSlash(rel), Extension)
		if strings.HasPrefix(key, prefix) {
			out = append(out, key)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: list %s: %w", f.dir, err)
	}
	sort.Strings(out)
	return out, nil
}

func (f *file) CompareAndSwap(_ context.Context, key string, old, value []byte) error {
	p, err := f.path(key)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, err := f.read(p)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if !same(cur, exists, old) {
		return ErrConflict
	}
	return f.write(p, value)
}

// same reports whether the current document (cur, exists) equals old.
func same(cur []byte, exists bool, old []byte) bool {
	if old == nil {
		return !exists
	}
	return exists && string(cur) == string(old)
}

func clone(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return append([]byte(nil), b...)
}
