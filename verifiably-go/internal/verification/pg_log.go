package verification

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type pgLog struct {
	pool *pgxpool.Pool
}

// NewPGLog returns a PostgreSQL-backed Log. The caller is responsible for
// calling runMigrations (via pg.Open) before any Append call.
func NewPGLog(pool *pgxpool.Pool) Log {
	return &pgLog{pool: pool}
}

// Append inserts one event. ON CONFLICT DO NOTHING makes re-delivery idempotent
// in case a goroutine retries after a transient network error.
func (l *pgLog) Append(ctx context.Context, e Event) error {
	_, err := l.pool.Exec(ctx, `
		INSERT INTO verification_events
			(id, issuer_did, schema_id, schema_name, verifier_dpg,
			 deployment_id, status, trust_status, status_list_src, verified_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO NOTHING`,
		e.ID, e.IssuerDID, e.SchemaID, e.SchemaName, e.VerifierDPG,
		e.DeploymentID, e.Status, e.TrustStatus, e.StatusListSrc, e.VerifiedAt,
	)
	return err
}

// QueryByIssuer returns all events for issuerDID newer than now-period,
// ordered newest-first. Uses the (issuer_did, verified_at DESC) index.
func (l *pgLog) QueryByIssuer(ctx context.Context, issuerDID string, period time.Duration) ([]Event, error) {
	since := time.Now().UTC().Add(-period)
	rows, err := l.pool.Query(ctx, `
		SELECT id, issuer_did, schema_id, schema_name, verifier_dpg,
		       deployment_id, status, trust_status, status_list_src, verified_at
		FROM verification_events
		WHERE issuer_did = $1 AND verified_at >= $2
		ORDER BY verified_at DESC`,
		issuerDID, since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.IssuerDID, &e.SchemaID, &e.SchemaName, &e.VerifierDPG,
			&e.DeploymentID, &e.Status, &e.TrustStatus, &e.StatusListSrc, &e.VerifiedAt,
		); err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
