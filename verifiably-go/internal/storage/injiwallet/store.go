// Package injiwallet is a durable, per-user store of the credentials a holder has
// claimed through the in-app Inji web wallet (eSignet). It is keyed by the
// holder's OIDC login identity (provider|sub) so the wallet follows the user
// across browser sessions and server restarts — unlike the cookie-scoped session
// cache, which loses the credentials when the cookie changes and would otherwise
// leak them to whoever logs in next on the same browser.
//
// The store is a single AES-256-GCM-encrypted JSON file (the credentials carry
// PII). Writes are serialized through a mutex and the file is replaced
// atomically on every mutation — fine for a single-instance demo; swap the
// backing store for a database for multi-replica use.
package injiwallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// HeldCred is one credential kept in a holder's wallet.
type HeldCred struct {
	VCID      string    `json:"vcId"`                // stable id (vcID) used to dedupe + delete
	VC        string    `json:"vc"`                  // issued credential (JSON object or compact SD-JWT)
	HolderKey string    `json:"holderKey,omitempty"` // PEM of the ES256 cnf key (SD-JWT presentation)
	ClaimedAt time.Time `json:"claimedAt"`
}

// Store maps an OIDC user key -> that user's held credentials (newest first).
type Store struct {
	mu     sync.Mutex
	path   string
	key    []byte // AES-256 key; nil => plaintext (only when no session secret)
	byUser map[string][]HeldCred
}

// NewStore opens (or creates) the wallet file at path, decrypting with key.
func NewStore(path string, key []byte) (*Store, error) {
	s := &Store{path: path, key: key, byUser: map[string][]HeldCred{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("injiwallet: read %s: %w", s.path, err)
	}
	if len(raw) == 0 {
		return nil
	}
	plain := raw
	if s.key != nil {
		if plain, err = decrypt(s.key, raw); err != nil {
			return fmt.Errorf("injiwallet: decrypt %s: %w", s.path, err)
		}
	}
	if err := json.Unmarshal(plain, &s.byUser); err != nil {
		return fmt.Errorf("injiwallet: parse %s: %w", s.path, err)
	}
	if s.byUser == nil {
		s.byUser = map[string][]HeldCred{}
	}
	return nil
}

// flush writes the whole map back atomically; caller holds s.mu.
func (s *Store) flush() error {
	plain, err := json.Marshal(s.byUser)
	if err != nil {
		return err
	}
	out := plain
	if s.key != nil {
		if out, err = encrypt(s.key, plain); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// List returns userKey's held credentials, newest first. Never nil-panics; the
// returned slice is a copy the caller may retain.
func (s *Store) List(userKey string) []HeldCred {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.byUser[userKey]
	out := make([]HeldCred, len(src))
	copy(out, src)
	return out
}

// Add prepends c to userKey's wallet (newest first, deduped by VCID) and flushes.
// No-op for an empty userKey or VCID.
func (s *Store) Add(userKey string, c HeldCred) error {
	if userKey == "" || c.VCID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.byUser[userKey]
	kept := make([]HeldCred, 0, len(cur))
	for _, e := range cur {
		if e.VCID != c.VCID {
			kept = append(kept, e)
		}
	}
	s.byUser[userKey] = append([]HeldCred{c}, kept...)
	return s.flush()
}

// Delete removes the credential with vcID from userKey's wallet and flushes.
func (s *Store) Delete(userKey, vcID string) error {
	if userKey == "" || vcID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.byUser[userKey]
	kept := make([]HeldCred, 0, len(cur))
	for _, e := range cur {
		if e.VCID != vcID {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(cur) {
		return nil // nothing removed
	}
	if len(kept) == 0 {
		delete(s.byUser, userKey)
	} else {
		s.byUser[userKey] = kept
	}
	return s.flush()
}

func encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("injiwallet: ciphertext too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}
