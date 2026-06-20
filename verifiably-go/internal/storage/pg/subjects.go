package pg

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AllowedSubjectClaims is the set of certify.vc_subject claim columns the API may
// provision. It mirrors the FIELDS in scripts/gen-authcode-config.py (the
// generator that DDLs the table). Claims outside this allow-list are ignored —
// and, crucially, the list is what keeps the dynamic column SQL injection-safe.
var AllowedSubjectClaims = []string{
	"fullName", "givenName", "familyName", "gender", "dateOfBirth", "email", "phoneNumber",
}

// OpenRaw connects a pgx pool WITHOUT running verifiably's migrations. Use it for
// a foreign database (e.g. Inji Certify's inji_certify) where we only touch one
// known table and must never create verifiably's own schema.
func OpenRaw(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pg: parse DSN: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pg: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg: ping: %w", err)
	}
	return pool, nil
}

// SubjectStore upserts dynamic claim rows into certify.vc_subject — the source
// table the Inji auth-code Postgres data-provider reads when issuing a credential.
// Rows are keyed by the eSignet subject id (the access-token `sub`/PSU-token),
// which is exactly what the data-provider query binds as :id.
type SubjectStore struct{ pool *pgxpool.Pool }

// NewSubjectStore wraps a pool (opened with OpenRaw against the inji_certify DB).
func NewSubjectStore(pool *pgxpool.Pool) *SubjectStore { return &SubjectStore{pool: pool} }

// ProvisionSubject upserts the allow-listed claims keyed by subjectID into
// certify.vc_subject (INSERT … ON CONFLICT (individual_id) DO UPDATE). Column
// names come only from AllowedSubjectClaims and are quoted; values are bound.
func (s *SubjectStore) ProvisionSubject(ctx context.Context, subjectID string, claims map[string]string) error {
	cols := []string{"individual_id"}
	args := []any{subjectID}
	ph := []string{"$1"}
	updates := []string{}
	i := 2
	for _, col := range AllowedSubjectClaims {
		v, ok := claims[col]
		if !ok {
			continue
		}
		qc := pgx.Identifier{col}.Sanitize()
		cols = append(cols, qc)
		args = append(args, v)
		ph = append(ph, "$"+strconv.Itoa(i))
		updates = append(updates, qc+"=EXCLUDED."+qc)
		i++
	}
	q := "INSERT INTO certify.vc_subject (" + strings.Join(cols, ", ") + ") VALUES (" +
		strings.Join(ph, ", ") + ") ON CONFLICT (individual_id) DO "
	if len(updates) == 0 {
		q += "NOTHING"
	} else {
		q += "UPDATE SET " + strings.Join(updates, ", ")
	}
	if _, err := s.pool.Exec(ctx, q, args...); err != nil {
		return fmt.Errorf("pg: provision vc_subject: %w", err)
	}
	return nil
}
