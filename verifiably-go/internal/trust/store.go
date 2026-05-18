package trust

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── PostgreSQL-backed store ───────────────────────────────────────────────────

// pgStore persists trusted issuers in the `trusted_issuers` table.
// It maintains an in-memory snapshot (refreshed on every write and on
// TrustedIssuers calls) so IsTrusted hot-path reads never hit the DB.
type pgStore struct {
	pool *pgxpool.Pool
	mu   sync.RWMutex
	snap []TrustedIssuer // in-memory snapshot; nil means "not loaded yet"
}

// NewPGStore returns a Registry backed by the given connection pool.
// The caller must ensure the `trusted_issuers` table already exists
// (created by internal/storage/pg runMigrations).
func NewPGStore(pool *pgxpool.Pool) Registry {
	return &pgStore{pool: pool}
}

func (s *pgStore) IsTrusted(ctx context.Context, issuerDID, schemaID string) error {
	issuers, err := s.TrustedIssuers(ctx)
	if err != nil {
		return fmt.Errorf("trust: registry lookup: %w", err)
	}
	for _, e := range issuers {
		if e.DID != issuerDID {
			continue
		}
		if e.IsExpired() {
			return fmt.Errorf("%w: accreditation expired on %s", ErrUntrusted, e.ValidUntil.Format("2006-01-02"))
		}
		if !e.AuthorisesSchema(schemaID) {
			return fmt.Errorf("%w: issuer not authorised for schema %q", ErrUntrusted, schemaID)
		}
		return nil
	}
	return fmt.Errorf("%w: DID %q not found in registry", ErrUntrusted, issuerDID)
}

func (s *pgStore) TrustedIssuers(ctx context.Context) ([]TrustedIssuer, error) {
	s.mu.RLock()
	if s.snap != nil {
		cp := make([]TrustedIssuer, len(s.snap))
		copy(cp, s.snap)
		s.mu.RUnlock()
		return cp, nil
	}
	s.mu.RUnlock()
	return s.refresh(ctx)
}

func (s *pgStore) Add(ctx context.Context, e TrustedIssuer) error {
	if e.AccreditedAt.IsZero() {
		e.AccreditedAt = time.Now().UTC()
	}
	var validUntil *time.Time
	if !e.ValidUntil.IsZero() {
		t := e.ValidUntil.UTC()
		validUntil = &t
	}
	schemas := e.Schemas
	if schemas == nil {
		schemas = []string{}
	}
	statusListEndpoints := e.StatusListEndpoints
	if statusListEndpoints == nil {
		statusListEndpoints = []string{}
	}
	policy := e.StatusListPolicy
	if policy == "" {
		policy = "fail-closed"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO trusted_issuers
		  (did, display_name, schemas, accredited_at, valid_until,
		   service_endpoint, status_list_endpoints, status_list_policy, verifier_api_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (did) DO UPDATE
		  SET display_name          = EXCLUDED.display_name,
		      schemas               = EXCLUDED.schemas,
		      accredited_at         = EXCLUDED.accredited_at,
		      valid_until           = EXCLUDED.valid_until,
		      service_endpoint      = EXCLUDED.service_endpoint,
		      status_list_endpoints = EXCLUDED.status_list_endpoints,
		      status_list_policy    = EXCLUDED.status_list_policy,
		      verifier_api_key      = EXCLUDED.verifier_api_key`,
		e.DID, e.DisplayName, schemas, e.AccreditedAt.UTC(), validUntil,
		e.ServiceEndpoint, statusListEndpoints, policy, e.VerifierAPIKey)
	if err != nil {
		return fmt.Errorf("trust: upsert issuer: %w", err)
	}
	s.invalidate()
	return nil
}

func (s *pgStore) Remove(ctx context.Context, did string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM trusted_issuers WHERE did = $1`, did)
	if err != nil {
		return fmt.Errorf("trust: delete issuer: %w", err)
	}
	s.invalidate()
	return nil
}

func (s *pgStore) refresh(ctx context.Context) ([]TrustedIssuer, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT did, display_name, schemas, accredited_at, valid_until,
		       service_endpoint, status_list_endpoints, status_list_policy, verifier_api_key
		FROM trusted_issuers
		ORDER BY did`)
	if err != nil {
		return nil, fmt.Errorf("trust: query issuers: %w", err)
	}
	defer rows.Close()

	var result []TrustedIssuer
	for rows.Next() {
		var e TrustedIssuer
		var validUntil *time.Time
		if err := rows.Scan(&e.DID, &e.DisplayName, &e.Schemas, &e.AccreditedAt, &validUntil,
			&e.ServiceEndpoint, &e.StatusListEndpoints, &e.StatusListPolicy, &e.VerifierAPIKey); err != nil {
			return nil, fmt.Errorf("trust: scan issuer row: %w", err)
		}
		if validUntil != nil {
			e.ValidUntil = *validUntil
		}
		if e.Schemas == nil {
			e.Schemas = []string{}
		}
		if e.StatusListEndpoints == nil {
			e.StatusListEndpoints = []string{}
		}
		result = append(result, e)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("trust: iterate issuer rows: %w", rows.Err())
	}

	s.mu.Lock()
	s.snap = result
	s.mu.Unlock()

	cp := make([]TrustedIssuer, len(result))
	copy(cp, result)
	return cp, nil
}

func (s *pgStore) invalidate() {
	s.mu.Lock()
	s.snap = nil
	s.mu.Unlock()
}

// ── In-memory store (dev / test) ─────────────────────────────────────────────

// memStore is a thread-safe in-memory registry used when no PG pool is
// available (local dev, unit tests). Data does not survive process restarts.
type memStore struct {
	mu      sync.RWMutex
	issuers map[string]TrustedIssuer // keyed by DID
}

// NewMemStore returns an empty in-memory Registry.
func NewMemStore() Registry {
	return &memStore{issuers: make(map[string]TrustedIssuer)}
}

func (s *memStore) IsTrusted(_ context.Context, issuerDID, schemaID string) error {
	s.mu.RLock()
	e, ok := s.issuers[issuerDID]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: DID %q not found in registry", ErrUntrusted, issuerDID)
	}
	if e.IsExpired() {
		return fmt.Errorf("%w: accreditation expired on %s", ErrUntrusted, e.ValidUntil.Format("2006-01-02"))
	}
	if !e.AuthorisesSchema(schemaID) {
		return fmt.Errorf("%w: issuer not authorised for schema %q", ErrUntrusted, schemaID)
	}
	return nil
}

func (s *memStore) TrustedIssuers(_ context.Context) ([]TrustedIssuer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TrustedIssuer, 0, len(s.issuers))
	for _, e := range s.issuers {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DID < out[j].DID })
	return out, nil
}

func (s *memStore) Add(_ context.Context, e TrustedIssuer) error {
	if e.AccreditedAt.IsZero() {
		e.AccreditedAt = time.Now().UTC()
	}
	if e.Schemas == nil {
		e.Schemas = []string{}
	}
	s.mu.Lock()
	s.issuers[e.DID] = e
	s.mu.Unlock()
	return nil
}

func (s *memStore) Remove(_ context.Context, did string) error {
	s.mu.Lock()
	delete(s.issuers, did)
	s.mu.Unlock()
	return nil
}
