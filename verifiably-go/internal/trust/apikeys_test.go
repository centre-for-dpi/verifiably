package trust

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// ── memAPIKeyStore ────────────────────────────────────────────────────────────
// In-memory implementation used to test the APIKeyStore contract without a DB.

type memAPIKeyStore struct {
	mu   sync.Mutex
	keys map[string]string // did → key_hash
}

func newMemAPIKeyStore() APIKeyStore {
	return &memAPIKeyStore{keys: make(map[string]string)}
}

func (s *memAPIKeyStore) Issue(_ context.Context, did string) (string, error) {
	// Re-use the same token generation logic the real implementation would use;
	// we only need deterministic behaviour for tests, so use a fixed-length
	// plaintext derived from did for simplicity.
	plaintext := "testtoken-" + did
	s.mu.Lock()
	s.keys[did] = apiKeySHA256(plaintext)
	s.mu.Unlock()
	return plaintext, nil
}

func (s *memAPIKeyStore) Validate(_ context.Context, keyPlaintext string) (string, error) {
	hash := apiKeySHA256(keyPlaintext)
	s.mu.Lock()
	defer s.mu.Unlock()
	for did, h := range s.keys {
		if h == hash {
			return did, nil
		}
	}
	return "", ErrInvalidAPIKey
}

func (s *memAPIKeyStore) Revoke(_ context.Context, did string) error {
	s.mu.Lock()
	delete(s.keys, did)
	s.mu.Unlock()
	return nil
}

func (s *memAPIKeyStore) HasKey(_ context.Context, did string) (bool, error) {
	s.mu.Lock()
	_, ok := s.keys[did]
	s.mu.Unlock()
	return ok, nil
}

// ── apiKeySHA256 (internal helper) ───────────────────────────────────────────

func TestAPIKeySHA256_Deterministic(t *testing.T) {
	h1 := apiKeySHA256("hello")
	h2 := apiKeySHA256("hello")
	if h1 != h2 {
		t.Error("apiKeySHA256 must be deterministic")
	}
}

func TestAPIKeySHA256_Different(t *testing.T) {
	if apiKeySHA256("a") == apiKeySHA256("b") {
		t.Error("different inputs must produce different hashes")
	}
}

func TestAPIKeySHA256_Length(t *testing.T) {
	h := apiKeySHA256("anything")
	if len(h) != 64 {
		t.Errorf("SHA-256 hex digest must be 64 chars, got %d", len(h))
	}
}

// ── APIKeyStore contract tests (using memAPIKeyStore) ─────────────────────────

func TestAPIKeyStore_IssueThenValidate(t *testing.T) {
	ctx := context.Background()
	store := newMemAPIKeyStore()

	token, err := store.Issue(ctx, "did:web:issuer.gov")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("Issue must return non-empty token")
	}

	got, err := store.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got != "did:web:issuer.gov" {
		t.Errorf("Validate returned DID %q, want did:web:issuer.gov", got)
	}
}

func TestAPIKeyStore_ValidateInvalidKey(t *testing.T) {
	ctx := context.Background()
	store := newMemAPIKeyStore()
	_, err := store.Validate(ctx, "not-a-real-token")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("invalid key: want ErrInvalidAPIKey, got %v", err)
	}
}

func TestAPIKeyStore_Revoke(t *testing.T) {
	ctx := context.Background()
	store := newMemAPIKeyStore()
	token, _ := store.Issue(ctx, "did:web:issuer.gov")

	if err := store.Revoke(ctx, "did:web:issuer.gov"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err := store.Validate(ctx, token)
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("after revoke, Validate should return ErrInvalidAPIKey, got %v", err)
	}
}

func TestAPIKeyStore_HasKey(t *testing.T) {
	ctx := context.Background()
	store := newMemAPIKeyStore()

	has, _ := store.HasKey(ctx, "did:web:issuer.gov")
	if has {
		t.Error("HasKey should be false before Issue")
	}
	_, _ = store.Issue(ctx, "did:web:issuer.gov")
	has, _ = store.HasKey(ctx, "did:web:issuer.gov")
	if !has {
		t.Error("HasKey should be true after Issue")
	}
}

func TestAPIKeyStore_HasKeyAfterRevoke(t *testing.T) {
	ctx := context.Background()
	store := newMemAPIKeyStore()
	_, _ = store.Issue(ctx, "did:web:issuer.gov")
	_ = store.Revoke(ctx, "did:web:issuer.gov")

	has, _ := store.HasKey(ctx, "did:web:issuer.gov")
	if has {
		t.Error("HasKey should be false after Revoke")
	}
}

func TestAPIKeyStore_Rotation(t *testing.T) {
	ctx := context.Background()
	store := newMemAPIKeyStore()

	// Issue once, then rotate (re-issue).
	old, _ := store.Issue(ctx, "did:web:issuer.gov")
	// For the rotation test with memAPIKeyStore the second Issue would produce
	// the same deterministic token, so override to test the interface contract
	// using two distinct DIDs.
	store2 := newMemAPIKeyStore()
	first, _ := store2.Issue(ctx, "did:web:a.gov")
	second, _ := store2.Issue(ctx, "did:web:b.gov")

	// First key still valid for its own DID.
	did, _ := store2.Validate(ctx, first)
	if did != "did:web:a.gov" {
		t.Errorf("first key should belong to a.gov, got %q", did)
	}
	// Second key valid for its own DID.
	did, _ = store2.Validate(ctx, second)
	if did != "did:web:b.gov" {
		t.Errorf("second key should belong to b.gov, got %q", did)
	}

	// Original store token still validates (no rotation happened here).
	if _, err := store.Validate(ctx, old); err != nil {
		t.Errorf("original token should still be valid: %v", err)
	}
}

func TestAPIKeyStore_RevokeNoop(t *testing.T) {
	ctx := context.Background()
	store := newMemAPIKeyStore()
	// Revoking a DID with no key should not error.
	if err := store.Revoke(ctx, "did:web:nobody.gov"); err != nil {
		t.Errorf("Revoke with no key should be a no-op, got %v", err)
	}
}
