package trust

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrInvalidAPIKey is returned by Validate when no matching key exists.
var ErrInvalidAPIKey = errors.New("invalid API key")

// APIKeyStore manages per-issuer API keys for the ecosystem analytics API.
// Keys are shown once in plaintext at generation time and stored only as
// SHA-256 hashes. Rotation (Issue on an existing DID) invalidates the
// previous key atomically.
type APIKeyStore interface {
	// Issue generates a new 64-hex-char token for did, stores its SHA-256
	// hash, and returns the plaintext token. Any existing key for the same
	// DID is replaced.
	Issue(ctx context.Context, did string) (keyPlaintext string, err error)

	// Validate checks keyPlaintext against stored hashes and returns the
	// owning DID. Returns ErrInvalidAPIKey when no match is found.
	Validate(ctx context.Context, keyPlaintext string) (did string, err error)

	// Revoke deletes the key entry for did. No-op when did has no key.
	Revoke(ctx context.Context, did string) error

	// HasKey reports whether did has an active API key.
	HasKey(ctx context.Context, did string) (bool, error)
}

type pgAPIKeyStore struct {
	pool *pgxpool.Pool
}

// NewPGAPIKeyStore returns a PostgreSQL-backed APIKeyStore. pg.Open must have
// run runMigrations (which creates the issuer_api_keys table) before use.
func NewPGAPIKeyStore(pool *pgxpool.Pool) APIKeyStore {
	return &pgAPIKeyStore{pool: pool}
}

func (s *pgAPIKeyStore) Issue(ctx context.Context, did string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("apikeys: generate random bytes: %w", err)
	}
	plaintext := hex.EncodeToString(b)
	hash := apiKeySHA256(plaintext)
	_, err := s.pool.Exec(ctx, `
		INSERT INTO issuer_api_keys (did, key_hash)
		VALUES ($1, $2)
		ON CONFLICT (did) DO UPDATE
		    SET key_hash = EXCLUDED.key_hash, created_at = now()`,
		did, hash,
	)
	if err != nil {
		return "", fmt.Errorf("apikeys: upsert: %w", err)
	}
	return plaintext, nil
}

func (s *pgAPIKeyStore) Validate(ctx context.Context, keyPlaintext string) (string, error) {
	hash := apiKeySHA256(keyPlaintext)
	var did string
	if err := s.pool.QueryRow(ctx,
		`SELECT did FROM issuer_api_keys WHERE key_hash = $1`, hash,
	).Scan(&did); err != nil {
		return "", ErrInvalidAPIKey
	}
	return did, nil
}

func (s *pgAPIKeyStore) Revoke(ctx context.Context, did string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM issuer_api_keys WHERE did = $1`, did)
	return err
}

func (s *pgAPIKeyStore) HasKey(ctx context.Context, did string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM issuer_api_keys WHERE did = $1)`, did,
	).Scan(&exists)
	return exists, err
}

func apiKeySHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
