package pg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verifiably/verifiably-go/internal/statuslist"
)

// StatusListStore is the PostgreSQL-backed implementation of statuslist.Backend.
// It delegates bit operations to an in-memory *statuslist.Store (backed by a
// throwaway temp file) and syncs the raw byte state to Postgres on every
// mutation. Publish calls (read-only) go directly to the in-memory store.
type StatusListStore struct {
	mu   sync.Mutex
	st   *statuslist.Store // in-memory delegate for bit ops + signing
	pool *pgxpool.Pool
}

// NewStatusListStore creates or reopens the status list from Postgres.
// A temporary file is used as the statuslist.Store's file path; the pg store
// overwrites it on load so it always reflects the DB state.
func NewStatusListStore(pool *pgxpool.Pool, kind, listID, publishURL string) (*StatusListStore, error) {
	tmpDir := os.TempDir()
	tmpPath := filepath.Join(tmpDir, fmt.Sprintf("verifiably-sl-%s-%s.json", kind, listID))

	st, err := statuslist.NewStore(kind, listID, tmpPath, publishURL)
	if err != nil {
		return nil, fmt.Errorf("statuslist pg: init in-memory store: %w", err)
	}

	s := &StatusListStore{st: st, pool: pool}

	// Try to load existing state from Postgres.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var bits []byte
	var nextFree int
	err = pool.QueryRow(ctx,
		`SELECT bits, next_free FROM status_lists WHERE list_id = $1`, listID,
	).Scan(&bits, &nextFree)
	if err == nil && len(bits) > 0 {
		if loadErr := st.LoadRawBytes(bits, nextFree); loadErr != nil {
			return nil, fmt.Errorf("statuslist pg: restore bits: %w", loadErr)
		}
	} else {
		// First time — seed the DB with the empty list.
		_, dbErr := pool.Exec(ctx, `
			INSERT INTO status_lists (list_id, kind, next_free, bits, publish_url)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (list_id) DO NOTHING`,
			listID, kind, 0, st.RawBytes(), publishURL,
		)
		if dbErr != nil {
			return nil, fmt.Errorf("statuslist pg: seed row: %w", dbErr)
		}
	}
	return s, nil
}

func (s *StatusListStore) Allocate() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, err := s.st.Allocate()
	if err != nil {
		return 0, err
	}
	return idx, s.persist()
}

func (s *StatusListStore) Revoke(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.st.Revoke(index); err != nil {
		return err
	}
	return s.persist()
}

func (s *StatusListStore) Reinstate(index int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.st.Reinstate(index); err != nil {
		return err
	}
	return s.persist()
}

func (s *StatusListStore) IsRevoked(index int) bool    { return s.st.IsRevoked(index) }
func (s *StatusListStore) Size() int                   { return s.st.Size() }
func (s *StatusListStore) NextFree() int               { return s.st.NextFree() }
func (s *StatusListStore) GetKind() string             { return s.st.GetKind() }
func (s *StatusListStore) GetListID() string           { return s.st.GetListID() }
func (s *StatusListStore) GetPublishURL() string       { return s.st.GetPublishURL() }

func (s *StatusListStore) PublishBitstringJWT(key *statuslist.SigningKey) (string, error) {
	return s.st.PublishBitstringJWT(key)
}

func (s *StatusListStore) PublishTokenStatusList(key *statuslist.SigningKey) (string, error) {
	return s.st.PublishTokenStatusList(key)
}

// persist syncs the in-memory bit state to Postgres. Must be called under s.mu.
func (s *StatusListStore) persist() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.pool.Exec(ctx, `
		UPDATE status_lists
		SET bits = $1, next_free = $2, updated_at = now()
		WHERE list_id = $3`,
		s.st.RawBytes(), s.st.NextFree(), s.st.GetListID(),
	)
	return err
}
