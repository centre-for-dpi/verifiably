package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// NonceStore issues short-lived, single-use c_nonce values for the mDL
// proof-of-possession flow. In-memory and unbounded is fine at POC scale — a
// nonce lives seconds, not the lifetime of the process.
type NonceStore struct {
	mu     sync.Mutex
	ttl    time.Duration
	nonces map[string]time.Time // nonce -> expiry
}

// NewNonceStore creates a store where every issued nonce expires after ttl.
func NewNonceStore(ttl time.Duration) *NonceStore {
	return &NonceStore{
		ttl:    ttl,
		nonces: make(map[string]time.Time),
	}
}

// Issue mints a fresh nonce and registers its expiry.
func (s *NonceStore) Issue() string {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failing is a fatal environment problem, not a
		// recoverable API error; the caller has no useful fallback.
		panic("mdl: crypto/rand unavailable: " + err.Error())
	}
	nonce := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces[nonce] = time.Now().Add(s.ttl)
	return nonce
}

// Consume reports whether nonce was issued by this store, is still within its
// TTL, and has not already been consumed. It invalidates the nonce as part of
// the same call — a nonce can satisfy exactly one proof, ever.
func (s *NonceStore) Consume(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, ok := s.nonces[nonce]
	if !ok {
		return false
	}
	delete(s.nonces, nonce) // one-time use regardless of outcome
	return time.Now().Before(expiry)
}
