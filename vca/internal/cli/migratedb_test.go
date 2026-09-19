// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// The fake driver answers the three queries of vca migrate export, so
// the CLI test needs no PostgreSQL server and no PostgreSQL driver.

var legacyOnce sync.Once

// openFakeLegacyDB returns a database with one row per legacy table.
func openFakeLegacyDB(t *testing.T) (*sql.DB, error) {
	t.Helper()
	legacyOnce.Do(func() { sql.Register("clifakelegacy", legacyDriver{}) })
	db, err := sql.Open("clifakelegacy", "legacy")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close: %v", closeErr)
		}
	})
	return db, nil
}

type legacyDriver struct{}

func (legacyDriver) Open(string) (driver.Conn, error) { return legacyConn{}, nil }

type legacyConn struct{}

func (legacyConn) Prepare(query string) (driver.Stmt, error) { return legacyStmt{query: query}, nil }
func (legacyConn) Close() error                              { return nil }
func (legacyConn) Begin() (driver.Tx, error)                 { return nil, errors.New("fake: no transactions") }

type legacyStmt struct{ query string }

func (legacyStmt) Close() error  { return nil }
func (legacyStmt) NumInput() int { return 0 }
func (legacyStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("fake: no exec")
}
func (s legacyStmt) Query([]driver.Value) (driver.Rows, error) {
	at := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	switch {
	case strings.Contains(s.query, "issued_credentials"):
		return &legacyRows{rows: [][]driver.Value{{
			"vc-1", "schema-a", "Licence", "w3c_vcdm_2", "ldp_vc", "waltid", "oidc|1", "A Person",
			"openid-credential-offer://x", at, nil, []byte(`{"id":"holder-1"}`),
			[]byte(`{"type":"token","listId":"token-v1","index":2}`),
		}}}, nil
	case strings.Contains(s.query, "status_lists"):
		return &legacyRows{rows: [][]driver.Value{
			{"token-v1", "token", int64(3), []byte{0, 0, 0, 0}},
		}}, nil
	default:
		return &legacyRows{rows: [][]driver.Value{
			{"did:web:issuer.example", "Issuer", "{schema-a}", "https://issuer.example",
				"{https://issuer.example/l}", "fail-closed", at, nil},
		}}, nil
	}
}

type legacyRows struct {
	rows [][]driver.Value
	at   int
}

func (r *legacyRows) Columns() []string {
	out := make([]string, len(r.rows[0]))
	for i := range out {
		out[i] = "c"
	}
	return out
}

func (r *legacyRows) Close() error { return nil }

func (r *legacyRows) Next(dest []driver.Value) error {
	if r.at >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.at])
	r.at++
	return nil
}
