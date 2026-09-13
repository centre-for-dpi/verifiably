// SPDX-License-Identifier: Apache-2.0

// Package store persists named JSON documents in a directory. It is the
// local Persister until the shared services/internal/store lands.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Dir stores each document as <dir>/<name>.json with mode 0600.
type Dir struct {
	path string
}

// Open makes the directory and returns the store.
func Open(path string) (*Dir, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Dir{path: path}, nil
}

// New returns a Dir store when path is set, else a memory persister.
func New(path string) (oidcflow.Persister, error) {
	if path == "" {
		return oidcflow.NewMemoryPersister(), nil
	}
	return Open(path)
}

func (d *Dir) file(name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("store: bad document name %q", name)
	}
	return filepath.Join(d.path, name+".json"), nil
}

// Load implements oidcflow.Persister.
func (d *Dir) Load(name string, v any) error {
	f, err := d.file(name)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(f)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("store: %s: %w", name, err)
	}
	return nil
}

// Save implements oidcflow.Persister. It writes a temporary file and
// renames it, so a crash never leaves a half written document.
func (d *Dir) Save(name string, v any) error {
	f, err := d.file(name)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	tmp := f + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := os.Rename(tmp, f); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}
