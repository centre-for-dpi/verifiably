// SPDX-License-Identifier: Apache-2.0

// Package sqlsrc reads rows from a database with database/sql
// (ADR-015 decision 1). The driver is a name that the binary registered.
// The query must be one SELECT statement. The DSN comes from a secret
// reference that the caller resolved.
package sqlsrc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/table"
)

// Errors the package returns.
var (
	ErrDriver    = errors.New("sqlsrc: the driver is not available in this deployment")
	ErrNotSelect = errors.New("sqlsrc: the query must be one SELECT statement")
	ErrTooMany   = errors.New("sqlsrc: the query returns more rows than the limit")
	ErrField     = errors.New("sqlsrc: the field is not a column of the query")
)

// Limits when a field is zero.
const (
	DefaultTimeout = 30 * time.Second
	DefaultMaxRows = 10000
)

// Request describes one read.
type Request struct {
	Driver string
	DSN    string
	Query  string
	// Timeout bounds the connection and the query. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Reader runs queries.
type Reader struct {
	// MaxRows caps the rows read. Zero means DefaultMaxRows.
	MaxRows int
	// Open opens a database. Nil means sql.Open.
	Open func(driver, dsn string) (*sql.DB, error)
}

// CheckQuery checks that q is one SELECT statement. It allows a WITH
// clause and one trailing semicolon.
func CheckQuery(q string) error {
	q = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(q), ";"))
	if q == "" || strings.Contains(q, ";") {
		return ErrNotSelect
	}
	first := strings.ToLower(strings.Fields(q)[0])
	if first != "select" && first != "with" {
		return fmt.Errorf("%w: it starts with %q", ErrNotSelect, first)
	}
	return nil
}

// Available reports whether driver is registered.
func Available(driver string) bool {
	for _, d := range sql.Drivers() {
		if d == driver {
			return true
		}
	}
	return false
}

// Read runs the query and returns the rows as strings.
func (r Reader) Read(ctx context.Context, req Request) (table.Table, error) {
	db, ctx, done, err := r.open(ctx, req)
	if err != nil {
		return table.Table{}, err
	}
	defer done()
	return r.query(ctx, db, req.Query)
}

// Match returns the rows of the query whose column field holds value.
// The database filters: Match wraps the query of the source in an outer
// SELECT with one WHERE clause. The field must be a plain identifier
// and a column of the query, and the value travels as an argument, so
// neither can change the statement (ADR-052 decision 3).
func (r Reader) Match(ctx context.Context, req Request, field, value string) (table.Table, error) {
	if !identifier(field) {
		return table.Table{}, fmt.Errorf("%w: %q", ErrField, field)
	}
	db, ctx, done, err := r.open(ctx, req)
	if err != nil {
		return table.Table{}, err
	}
	defer done()
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(req.Query), ";"))
	outer := "SELECT * FROM (" + inner + ") vca_q WHERE "
	probe, err := r.query(ctx, db, outer+"1 = 0")
	if err != nil {
		return table.Table{}, err
	}
	if !contains(probe.Fields, field) {
		return table.Table{}, fmt.Errorf("%w: %q", ErrField, field)
	}
	quoted, placeholder := `"`+field+`"`, "$1"
	if req.Driver == "mysql" {
		quoted, placeholder = "`"+field+"`", "?"
	}
	return r.query(ctx, db, outer+"vca_q."+quoted+" = "+placeholder, value)
}

// identifier reports whether s is a plain column name: a letter or an
// underscore, then letters, digits, and underscores.
func identifier(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, c := range s {
		letter := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !letter && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// open checks the request and opens the database with one connection.
// done closes it and ends the timeout.
func (r Reader) open(ctx context.Context, req Request) (*sql.DB, context.Context, func(), error) {
	if !Available(req.Driver) {
		return nil, nil, nil, fmt.Errorf("%w: %q", ErrDriver, req.Driver)
	}
	if err := CheckQuery(req.Query); err != nil {
		return nil, nil, nil, err
	}
	open := r.Open
	if open == nil {
		open = sql.Open
	}
	db, err := open(req.Driver, req.DSN)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sqlsrc: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	return db, ctx, func() {
		cancel()
		// Nothing can act on a close fault of a handle.
		ignored := db.Close()
		_ = ignored
	}, nil
}

// query runs one statement and returns its rows as strings.
func (r Reader) query(ctx context.Context, db *sql.DB, statement string, args ...any) (table.Table, error) {
	rows, err := db.QueryContext(ctx, statement, args...)
	if err != nil {
		return table.Table{}, fmt.Errorf("sqlsrc: query: %w", err)
	}
	// Nothing can act on a close fault of a handle.
	defer func() { ignored := rows.Close(); _ = ignored }()
	cols, err := rows.Columns()
	if err != nil {
		return table.Table{}, fmt.Errorf("sqlsrc: columns: %w", err)
	}
	maxRows := r.MaxRows
	if maxRows <= 0 {
		maxRows = DefaultMaxRows
	}
	var out []map[string]string
	for rows.Next() {
		if len(out) >= maxRows {
			return table.Table{}, fmt.Errorf("%w: %d", ErrTooMany, maxRows)
		}
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return table.Table{}, fmt.Errorf("sqlsrc: scan: %w", err)
		}
		row := make(map[string]string, len(cols))
		for i, c := range cols {
			row[c] = Stringify(values[i])
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return table.Table{}, fmt.Errorf("sqlsrc: rows: %w", err)
	}
	return table.Table{Fields: cols, Rows: out, Total: int64(len(out))}, nil
}

// Stringify turns a scanned value into a row value. A time becomes an
// RFC 3339 date when it has no clock part, else a full RFC 3339 time.
func Stringify(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case time.Time:
		if x.Hour() == 0 && x.Minute() == 0 && x.Second() == 0 && x.Nanosecond() == 0 {
			return x.Format("2006-01-02")
		}
		return x.Format(time.RFC3339)
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	if b, err := json.Marshal(v); err == nil {
		return strings.Trim(string(b), `"`)
	}
	return fmt.Sprint(v)
}
