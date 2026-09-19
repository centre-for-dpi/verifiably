// SPDX-License-Identifier: Apache-2.0

package migrate_test

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// fakeResult holds the answer of one query.
type fakeResult struct {
	columns []string
	rows    [][]driver.Value
	err     error
	rowErr  error
}

// fakeDriver answers the three queries of the migrator.
type fakeDriver struct {
	mu      sync.Mutex
	answers map[string]fakeResult
}

var (
	registerOnce sync.Once
	registry     = struct {
		mu sync.Mutex
		m  map[string]*fakeDriver
	}{m: map[string]*fakeDriver{}}
)

// openFake registers the answers under a DSN and opens a database.
func openFake(t *testing.T, answers map[string]fakeResult) *sql.DB {
	t.Helper()
	registerOnce.Do(func() { sql.Register("migratefake", dispatch{}) })
	dsn := t.Name()
	registry.mu.Lock()
	registry.m[dsn] = &fakeDriver{answers: answers}
	registry.mu.Unlock()
	db, err := sql.Open("migratefake", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf("close: %v", closeErr)
		}
	})
	return db
}

// dispatch finds the fake driver of a DSN.
type dispatch struct{}

func (dispatch) Open(dsn string) (driver.Conn, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	d, ok := registry.m[dsn]
	if !ok {
		return nil, errors.New("fake: unknown dsn")
	}
	return &fakeConn{d: d}, nil
}

type fakeConn struct{ d *fakeDriver }

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	return &fakeStmt{c: c, query: query}, nil
}
func (c *fakeConn) Close() error              { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) { return nil, errors.New("fake: no transactions") }

type fakeStmt struct {
	c     *fakeConn
	query string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return 0 }
func (s *fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("fake: no exec")
}

func (s *fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()
	for key, answer := range s.c.d.answers {
		if !strings.Contains(s.query, key) {
			continue
		}
		if answer.err != nil {
			return nil, answer.err
		}
		return &fakeRows{res: answer}, nil
	}
	return nil, errors.New("fake: no answer for the query")
}

type fakeRows struct {
	res fakeResult
	at  int
}

func (r *fakeRows) Columns() []string { return r.res.columns }
func (r *fakeRows) Close() error      { return nil }

func (r *fakeRows) Next(dest []driver.Value) error {
	if r.at >= len(r.res.rows) {
		if r.res.rowErr != nil {
			return r.res.rowErr
		}
		return io.EOF
	}
	copy(dest, r.res.rows[r.at])
	r.at++
	return nil
}
