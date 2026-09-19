// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Document loads and saves one whole document. A service that keeps all
// of its state in one JSON document uses it. The service reads the
// document at start and writes it after each change.
type Document interface {
	// Load returns the saved document. found is false on first use.
	Load() (data []byte, found bool, err error)
	// Save writes the document. It replaces any saved document.
	Save(data []byte) error
}

// kvDoc keeps one document under one key of a KeyValue store.
type kvDoc struct {
	kv  KeyValue
	key string
}

// Doc returns a Document that keeps the document under key of kv. The
// backends of this package are local, so Doc uses a background context.
func Doc(kv KeyValue, key string) Document { return kvDoc{kv: kv, key: key} }

// MemoryDoc returns a Document that keeps the document in the process.
func MemoryDoc() Document { return Doc(Memory(), "state") }

func (d kvDoc) Load() ([]byte, bool, error) {
	data, err := d.kv.Get(context.Background(), d.key)
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (d kvDoc) Save(data []byte) error {
	return d.kv.Put(context.Background(), d.key, data)
}

// fileDoc keeps one document at one exact path.
type fileDoc struct {
	mu   *sync.Mutex
	path string
}

// FileDoc returns a Document that keeps the document at path. Save
// writes a temporary file and renames it, so a reader never sees a
// partial document. FileDoc does not create the parent directory.
func FileDoc(path string) Document { return fileDoc{mu: &sync.Mutex{}, path: path} }

func (f fileDoc) Load() ([]byte, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: read %s: %w", f.path, err)
	}
	return data, true, nil
}

func (f fileDoc) Save(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	tmp := filepath.Join(filepath.Dir(f.path), "."+filepath.Base(f.path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("store: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("store: rename %s: %w", tmp, err)
	}
	return nil
}

// JSON keeps named Go values as JSON documents in a KeyValue store. A
// name is a key, so the name rules are the key rules.
type JSON struct{ kv KeyValue }

// NewJSON returns a JSON store over kv.
func NewJSON(kv KeyValue) *JSON { return &JSON{kv: kv} }

// Load reads the document with name into v. It leaves v unchanged when
// no document has the name.
func (j *JSON) Load(name string, v any) error {
	raw, err := j.kv.Get(context.Background(), name)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("store: %s: %w", name, err)
	}
	return nil
}

// Save writes v as the document with name.
func (j *JSON) Save(name string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: %s: %w", name, err)
	}
	return j.kv.Put(context.Background(), name, raw)
}
