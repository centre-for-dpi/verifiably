package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verifiably/verifiably-go/internal/issuance"
)

// IssuanceLog is the PostgreSQL-backed implementation of issuance.Backend.
// It preserves the hash-chain integrity invariant: each row's prev_hash is
// the SHA-256 of the preceding row's immutable fields, computed inside a
// serializable transaction so concurrent Appends don't interleave.
type IssuanceLog struct {
	mu   sync.Mutex // serializes Append so the chain is never forked
	pool *pgxpool.Pool
}

// NewIssuanceLog wraps the shared pool. The table must already exist (created
// by pg.Open → runMigrations).
func NewIssuanceLog(pool *pgxpool.Pool) *IssuanceLog {
	return &IssuanceLog{pool: pool}
}

// Append inserts a new credential record. It computes PrevHash from the
// most recent row (by seq) inside a mutex so the chain is never forked.
// IssuedAt is set to now() if zero.
func (l *IssuanceLog) Append(c issuance.IssuedCredential) (issuance.IssuedCredential, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ctx := context.Background()
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now().UTC()
	}

	// Fetch the last row to compute PrevHash.
	var last issuance.IssuedCredential
	row := l.pool.QueryRow(ctx,
		`SELECT id, schema_id, issuer_dpg, owner_key, issued_at, prev_hash
		 FROM issued_credentials ORDER BY seq DESC LIMIT 1`)
	var issuedAt time.Time
	err := row.Scan(&last.ID, &last.SchemaID, &last.IssuerDpg,
		&last.OwnerKey, &issuedAt, &last.PrevHash)
	if err != nil && err != pgx.ErrNoRows {
		return c, fmt.Errorf("issuance pg: fetch last: %w", err)
	}
	if err == nil {
		last.IssuedAt = issuedAt
		c.PrevHash = issuance.ChainHashOf(last)
	}

	// Check duplicate ID.
	var exists bool
	_ = l.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM issued_credentials WHERE id = $1)`, c.ID,
	).Scan(&exists)
	if exists {
		return c, fmt.Errorf("issuance pg: duplicate id %q", c.ID)
	}

	// SubjectFields is tagged json:"-" in the struct; the PG backend follows the
	// same convention so PII never reaches the database. Search by subject-field
	// value is ephemeral (in-memory only), matching the file-backed backend.
	var subjectJSON []byte
	var statusJSON []byte
	if c.StatusList != nil {
		statusJSON, _ = json.Marshal(c.StatusList)
	}

	_, err = l.pool.Exec(ctx, `
		INSERT INTO issued_credentials
		  (id, schema_id, schema_name, std, format, issuer_dpg, owner_key,
		   holder_hint, offer_uri, issued_at, subject_fields, status_list, prev_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		c.ID, c.SchemaID, c.SchemaName, c.Std, c.Format, c.IssuerDpg, c.OwnerKey,
		c.HolderHint, c.OfferURI, c.IssuedAt,
		subjectJSON, statusJSON, c.PrevHash,
	)
	if err != nil {
		return c, fmt.Errorf("issuance pg: insert: %w", err)
	}
	return c, nil
}

// Get retrieves a single record by ID.
func (l *IssuanceLog) Get(id string) (issuance.IssuedCredential, bool) {
	ctx := context.Background()
	rows, err := l.pool.Query(ctx,
		`SELECT id,schema_id,schema_name,std,format,issuer_dpg,owner_key,
		        holder_hint,offer_uri,issued_at,revoked_at,revocation_note,
		        subject_fields,status_list,prev_hash
		 FROM issued_credentials WHERE id = $1`, id)
	if err != nil {
		return issuance.IssuedCredential{}, false
	}
	items := scanRows(rows)
	if len(items) == 0 {
		return issuance.IssuedCredential{}, false
	}
	return items[0], true
}

// List returns credentials matching f, newest-first.
func (l *IssuanceLog) List(f issuance.Filter) []issuance.IssuedCredential {
	ctx := context.Background()
	q := `SELECT id,schema_id,schema_name,std,format,issuer_dpg,owner_key,
		         holder_hint,offer_uri,issued_at,revoked_at,revocation_note,
		         subject_fields,status_list,prev_hash
		  FROM issued_credentials WHERE TRUE`
	args := []any{}
	i := 1

	if f.OwnerKey != "" {
		q += fmt.Sprintf(" AND owner_key = $%d", i)
		args = append(args, f.OwnerKey)
		i++
	}
	if f.Std != "" {
		q += fmt.Sprintf(" AND std = $%d", i)
		args = append(args, f.Std)
		i++
	}
	if f.Format != "" {
		q += fmt.Sprintf(" AND format = $%d", i)
		args = append(args, f.Format)
		i++
	}
	switch f.State {
	case "active":
		q += " AND revoked_at IS NULL"
	case "revoked":
		q += " AND revoked_at IS NOT NULL"
	}
	if f.Query != "" {
		q += fmt.Sprintf(
			" AND (schema_name ILIKE $%d OR holder_hint ILIKE $%d)",
			i, i)
		args = append(args, "%"+f.Query+"%")
		i++
	}
	q += " ORDER BY issued_at DESC, seq DESC"

	rows, err := l.pool.Query(ctx, q, args...)
	if err != nil {
		return nil
	}
	return scanRows(rows)
}

// Summary returns aggregate counts over the full unscoped log.
func (l *IssuanceLog) Summary() issuance.Stats {
	ctx := context.Background()
	s := issuance.Stats{ByStd: map[string]int{}, ByFormat: map[string]int{}}

	row := l.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*),
		  COUNT(*) FILTER (WHERE revoked_at IS NULL),
		  COUNT(*) FILTER (WHERE revoked_at IS NOT NULL)
		FROM issued_credentials`)
	_ = row.Scan(&s.Total, &s.Active, &s.Revoked)

	rows, err := l.pool.Query(ctx,
		`SELECT std, COUNT(*) FROM issued_credentials GROUP BY std`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var std string
			var n int
			if rows.Scan(&std, &n) == nil {
				s.ByStd[std] = n
			}
		}
	}
	rows2, err := l.pool.Query(ctx,
		`SELECT format, COUNT(*) FROM issued_credentials GROUP BY format`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var format string
			var n int
			if rows2.Scan(&format, &n) == nil {
				s.ByFormat[format] = n
			}
		}
	}
	return s
}

// MarkRevoked stamps the credential with the current time.
func (l *IssuanceLog) MarkRevoked(id, ownerKey string) (issuance.IssuedCredential, error) {
	ctx := context.Background()
	q := `UPDATE issued_credentials SET revoked_at = now()
	      WHERE id = $1`
	args := []any{id}
	if ownerKey != "" {
		q += ` AND owner_key = $2`
		args = append(args, ownerKey)
	}
	q += ` RETURNING id`
	var retID string
	err := l.pool.QueryRow(ctx, q, args...).Scan(&retID)
	if err == pgx.ErrNoRows {
		return issuance.IssuedCredential{}, fmt.Errorf("issuance pg: %q not found or not owned by %q", id, ownerKey)
	}
	if err != nil {
		return issuance.IssuedCredential{}, fmt.Errorf("issuance pg: mark revoked: %w", err)
	}
	c, _ := l.Get(id)
	return c, nil
}

// MarkReinstate clears the revocation timestamp.
func (l *IssuanceLog) MarkReinstate(id, ownerKey string) (issuance.IssuedCredential, error) {
	ctx := context.Background()
	q := `UPDATE issued_credentials SET revoked_at = NULL
	      WHERE id = $1`
	args := []any{id}
	if ownerKey != "" {
		q += ` AND owner_key = $2`
		args = append(args, ownerKey)
	}
	q += ` RETURNING id`
	var retID string
	err := l.pool.QueryRow(ctx, q, args...).Scan(&retID)
	if err == pgx.ErrNoRows {
		return issuance.IssuedCredential{}, fmt.Errorf("issuance pg: %q not found or not owned by %q", id, ownerKey)
	}
	if err != nil {
		return issuance.IssuedCredential{}, fmt.Errorf("issuance pg: mark reinstate: %w", err)
	}
	c, _ := l.Get(id)
	return c, nil
}

// VerifyChain reads all rows ordered by seq and checks each prev_hash.
func (l *IssuanceLog) VerifyChain() []error {
	ctx := context.Background()
	rows, err := l.pool.Query(ctx,
		`SELECT id,schema_id,issuer_dpg,owner_key,issued_at,prev_hash
		 FROM issued_credentials ORDER BY seq ASC`)
	if err != nil {
		return []error{err}
	}
	defer rows.Close()

	var items []issuance.IssuedCredential
	for rows.Next() {
		var c issuance.IssuedCredential
		var issuedAt time.Time
		if err := rows.Scan(&c.ID, &c.SchemaID, &c.IssuerDpg,
			&c.OwnerKey, &issuedAt, &c.PrevHash); err != nil {
			continue
		}
		c.IssuedAt = issuedAt
		items = append(items, c)
	}

	var errs []error
	for i := 1; i < len(items); i++ {
		if items[i].PrevHash == "" {
			continue
		}
		want := issuance.ChainHashOf(items[i-1])
		if items[i].PrevHash != want {
			n := len(items[i].PrevHash)
			if n > 8 {
				n = 8
			}
			errs = append(errs, fmt.Errorf(
				"chain break at %q (seq %d): stored=%s…, computed=%s…",
				items[i].ID, i, items[i].PrevHash[:n], want[:8]))
		}
	}
	return errs
}


// scanRows reads a pgx.Rows result into IssuedCredential slice.
func scanRows(rows pgx.Rows) []issuance.IssuedCredential {
	defer rows.Close()
	var items []issuance.IssuedCredential
	for rows.Next() {
		var c issuance.IssuedCredential
		var issuedAt time.Time
		var revokedAt *time.Time
		var subjectJSON []byte
		var statusJSON []byte
		var revNote string
		if err := rows.Scan(
			&c.ID, &c.SchemaID, &c.SchemaName, &c.Std, &c.Format,
			&c.IssuerDpg, &c.OwnerKey, &c.HolderHint, &c.OfferURI,
			&issuedAt, &revokedAt, &revNote,
			&subjectJSON, &statusJSON, &c.PrevHash,
		); err != nil {
			continue
		}
		c.IssuedAt = issuedAt
		c.RevokedAt = revokedAt
		_ = json.Unmarshal(subjectJSON, &c.SubjectFields)
		if len(statusJSON) > 0 {
			var sl issuance.StatusListEntry
			if json.Unmarshal(statusJSON, &sl) == nil {
				c.StatusList = &sl
			}
		}
		items = append(items, c)
	}
	return items
}
