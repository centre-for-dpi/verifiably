// Package pg provides PostgreSQL-backed implementations of the session,
// status-list, and issuance-log storage interfaces. All backends share a
// single pgxpool.Pool created by Open(). Migrations run automatically at
// startup via runMigrations so the schema is always in sync with the code.
//
// Wire-in: set VERIFIABLY_DATABASE_URL to a libpq-compatible DSN, e.g.
//
//	postgres://verifiably:secret@localhost:5432/verifiably?sslmode=disable
//
// When the env var is absent the file-backed stores are used instead.
package pg

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a connection pool to the given DSN and runs the schema
// migrations. Returns an error if the database is unreachable or the
// migrations fail.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
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
	if err := runMigrations(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg: migrations: %w", err)
	}
	return pool, nil
}

// runMigrations applies the DDL idempotently (IF NOT EXISTS everywhere).
// All tables live in the default (public) schema. No migration framework
// is used — the schema is small enough to manage inline.
func runMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	ddl := `
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    data       BYTEA        NOT NULL,
    expires_at TIMESTAMPTZ  NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS status_lists (
    list_id     TEXT PRIMARY KEY,
    kind        TEXT         NOT NULL CHECK (kind IN ('bitstring','token')),
    next_free   INT          NOT NULL DEFAULT 0,
    bits        BYTEA        NOT NULL,
    publish_url TEXT         NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS issued_credentials (
    id              TEXT        PRIMARY KEY,
    schema_id       TEXT        NOT NULL DEFAULT '',
    schema_name     TEXT        NOT NULL DEFAULT '',
    std             TEXT        NOT NULL DEFAULT '',
    format          TEXT        NOT NULL DEFAULT '',
    issuer_dpg      TEXT        NOT NULL DEFAULT '',
    owner_key       TEXT        NOT NULL DEFAULT '',
    holder_hint     TEXT        NOT NULL DEFAULT '',
    offer_uri       TEXT        NOT NULL DEFAULT '',
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    revocation_note TEXT        NOT NULL DEFAULT '',
    subject_fields  JSONB       NOT NULL DEFAULT '{}',
    status_list     JSONB,
    prev_hash       TEXT        NOT NULL DEFAULT '',
    seq             BIGSERIAL   NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS ic_owner_key_idx ON issued_credentials (owner_key);
CREATE INDEX IF NOT EXISTS ic_issued_at_idx ON issued_credentials (issued_at DESC, seq DESC);

CREATE TABLE IF NOT EXISTS bulk_jobs (
    id         TEXT        PRIMARY KEY,
    status     TEXT        NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','running','done','error')),
    total      INT         NOT NULL DEFAULT 0,
    done       INT         NOT NULL DEFAULT 0,
    errors     INT         NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    error_msg  TEXT        NOT NULL DEFAULT ''
);
`
	_, err := pool.Exec(ctx, ddl)
	return err
}
