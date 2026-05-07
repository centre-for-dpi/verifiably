package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// UserStore persists the runtime, admin-UI-managed slice of OIDC provider
// configs to a JSON file. It is the only path that writes to disk for
// auth providers — deploy.sh writes the system file but never touches
// the user file, so reruns of `./deploy.sh run all` no longer wipe the
// operator's additions.
//
// File layout: a JSON array of ProviderConfig objects, identical shape
// to auth-providers.system.json. Empty array on first write. The Source
// field is intentionally NOT persisted (json:"-" on the struct), so a
// hand-edited user file can't masquerade as a system entry.
type UserStore struct {
	path string
	mu   sync.Mutex
}

// NewUserStore returns a store pointed at path. The file is not opened
// or validated here — Load reports a missing file as an empty list and
// Save creates the file (including parent dir) on first write. This lets
// the constructor stay infallible so callers can wire it unconditionally
// during startup, even when admin mode is "off".
func NewUserStore(path string) *UserStore {
	return &UserStore{path: path}
}

// Path returns the file path the store writes to. Useful for log lines
// and the admin UI's "where state lives" hint.
func (s *UserStore) Path() string { return s.path }

// Load reads the user file and returns the configs with Source=user
// stamped. Missing file → empty slice (not an error). Malformed file →
// error so callers can decide whether to ignore (UI list page) or fail
// loudly (boot loader).
func (s *UserStore) Load() ([]ProviderConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *UserStore) loadLocked() ([]ProviderConfig, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, nil
	}
	var cfgs []ProviderConfig
	if err := json.Unmarshal(b, &cfgs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	for i := range cfgs {
		cfgs[i].Source = SourceUser
	}
	return cfgs, nil
}

// Save writes cfgs to disk by overwriting the file in place.
//
// Why not atomic write+rename: deploy.sh bind-mounts this file as a
// single-file Docker volume, and renaming over a single-file bind mount
// breaks the mount (the host sees a new inode but the container still
// holds the old one — same trap that bit us with sed -i on the
// credential-issuer-metadata.conf mount). The Source field is excluded
// from JSON via struct tag so a stray "source":"system" can't be
// smuggled into the file even if a caller forgot to clear it.
//
// Crash safety: a process killed mid-write can leave a truncated file.
// The loader treats empty/whitespace as "no providers" and unparseable
// JSON as a fatal startup error — both are easier to recover from than
// a phantom-mount situation, and this file is single-writer-single-
// operator in practice.
func (s *UserStore) Save(cfgs []ProviderConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(cfgs)
}

func (s *UserStore) saveLocked(cfgs []ProviderConfig) error {
	if cfgs == nil {
		cfgs = []ProviderConfig{}
	}
	b, err := json.MarshalIndent(cfgs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal user providers: %w", err)
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(s.path), err)
	}
	if err := os.WriteFile(s.path, b, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", s.path, err)
	}
	return nil
}

// Add upserts a single provider by id: if an entry with cfg.ID already
// exists it is replaced in place (preserving order), otherwise cfg is
// appended. Returns the resulting full slice so callers can hand it
// directly to a registry rebuild without a second Load.
func (s *UserStore) Add(cfg ProviderConfig) ([]ProviderConfig, error) {
	if strings.TrimSpace(cfg.ID) == "" {
		return nil, fmt.Errorf("provider id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.loadLocked()
	if err != nil {
		return nil, err
	}
	cfg.Source = "" // never persist the source label
	replaced := false
	for i := range cur {
		if cur[i].ID == cfg.ID {
			cur[i] = cfg
			replaced = true
			break
		}
	}
	if !replaced {
		cur = append(cur, cfg)
	}
	if err := s.saveLocked(cur); err != nil {
		return nil, err
	}
	for i := range cur {
		cur[i].Source = SourceUser
	}
	return cur, nil
}

// Remove drops the provider with the given id. Returns (remaining, true)
// when a row was removed, (remaining, false) when no entry matched.
// File-level idempotent: a second Remove of the same id is a no-op.
func (s *UserStore) Remove(id string) ([]ProviderConfig, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.loadLocked()
	if err != nil {
		return nil, false, err
	}
	idx := -1
	for i, c := range cur {
		if c.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return cur, false, nil
	}
	cur = append(cur[:idx], cur[idx+1:]...)
	if err := s.saveLocked(cur); err != nil {
		return nil, false, err
	}
	for i := range cur {
		cur[i].Source = SourceUser
	}
	return cur, true, nil
}
