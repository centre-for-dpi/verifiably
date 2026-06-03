package statuslistcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// entry is the JSON-serialised form of one cached status list.
type entry struct {
	IssuerDID string    `json:"issuer_did"`
	ListURL   string    `json:"list_url"`
	RawJWT    string    `json:"raw_jwt"`
	CachedAt  time.Time `json:"cached_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// jsonStore is a file-backed store keyed by list URL.
// An in-memory map is kept as a hot layer to avoid repeated disk reads within
// a single process lifetime; disk is the source of truth across restarts.
type jsonStore struct {
	dir   string
	mu    sync.RWMutex
	items map[string]entry // keyed by listURL
}

func newJSONStore(dir string) *jsonStore {
	return &jsonStore{
		dir:   dir,
		items: make(map[string]entry),
	}
}

// urlKey returns a stable filename for a given URL (first 16 bytes of SHA-256).
func urlKey(listURL string) string {
	h := sha256.Sum256([]byte(listURL))
	return hex.EncodeToString(h[:16]) + ".json"
}

// load returns the cached entry for listURL, checking the in-memory map then disk.
func (s *jsonStore) load(listURL string) (entry, bool) {
	s.mu.RLock()
	e, ok := s.items[listURL]
	s.mu.RUnlock()
	if ok {
		return e, true
	}
	data, err := os.ReadFile(filepath.Join(s.dir, urlKey(listURL)))
	if err != nil {
		return entry{}, false
	}
	var e2 entry
	if json.Unmarshal(data, &e2) != nil {
		return entry{}, false
	}
	s.mu.Lock()
	s.items[listURL] = e2
	s.mu.Unlock()
	return e2, true
}

// save writes the entry to disk and updates the in-memory map.
func (s *jsonStore) save(e entry) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.dir, urlKey(e.ListURL)), data, 0o644); err != nil {
		return err
	}
	s.mu.Lock()
	s.items[e.ListURL] = e
	s.mu.Unlock()
	return nil
}
