// SPDX-License-Identifier: Apache-2.0

package sqlsrc

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

// fakeDriver answers by DSN: "ok" returns two rows, "openfail" fails to
// open, "queryfail" fails the query, "nextfail" fails after one row.
type fakeDriver struct{}

type fakeConn struct{ dsn string }

type fakeRows struct {
	dsn string
	i   int
}

func (fakeDriver) Open(dsn string) (driver.Conn, error) {
	if dsn == "openfail" {
		return nil, errors.New("open failed")
	}
	return fakeConn{dsn: dsn}, nil
}

func (fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (fakeConn) Close() error                        { return nil }
func (fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }

// statements keeps the statements the fake driver ran, with the
// arguments after a bar.
var statements []string

func (c fakeConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	line := q + " |"
	for _, a := range args {
		line += " " + fmt.Sprint(a.Value)
	}
	statements = append(statements, line)
	if c.dsn == "queryfail" {
		return nil, errors.New("query failed")
	}
	return &fakeRows{dsn: c.dsn}, nil
}

func (r *fakeRows) Columns() []string {
	return []string{"id", "name", "born", "seen", "active", "blob", "score"}
}
func (r *fakeRows) Close() error { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	r.i++
	if r.dsn == "nextfail" && r.i == 2 {
		return errors.New("next failed")
	}
	if r.i > 2 {
		return io.EOF
	}
	born := time.Date(1988, 3, 14, 0, 0, 0, 0, time.UTC)
	seen := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	copy(dest, []driver.Value{int64(r.i), "Grace", born, seen, true, []byte("b"), 1.5})
	if r.i == 2 {
		dest[1] = nil
		dest[4] = false
	}
	return nil
}

func TestMain(m *testing.M) {
	sql.Register("fake", fakeDriver{})
	os.Exit(m.Run())
}

func TestCheckQuery(t *testing.T) {
	good := []string{"SELECT 1", " select * from t ; ", "WITH x AS (SELECT 1) SELECT * FROM x"}
	for _, q := range good {
		if err := CheckQuery(q); err != nil {
			t.Errorf("%q: %v", q, err)
		}
	}
	bad := []string{"", ";", "DELETE FROM t", "SELECT 1; DROP TABLE t", "update t set a=1"}
	for _, q := range bad {
		if err := CheckQuery(q); !errors.Is(err, ErrNotSelect) {
			t.Errorf("%q: %v", q, err)
		}
	}
}

func TestRead(t *testing.T) {
	r := Reader{}
	tb, err := r.Read(context.Background(), Request{Driver: "fake", DSN: "ok", Query: "SELECT 1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tb.Fields) != 7 || tb.Total != 2 || len(tb.Rows) != 2 {
		t.Fatalf("%+v", tb)
	}
	want := map[string]string{"id": "1", "name": "Grace", "born": "1988-03-14", "seen": "2024-01-02T03:04:05Z", "active": "true", "blob": "b", "score": "1.5"}
	for k, v := range want {
		if tb.Rows[0][k] != v {
			t.Errorf("%s: %q want %q", k, tb.Rows[0][k], v)
		}
	}
	if tb.Rows[1]["name"] != "" || tb.Rows[1]["active"] != "false" {
		t.Fatalf("%+v", tb.Rows[1])
	}
	tests := []struct {
		name string
		r    Reader
		req  Request
		want error
	}{
		{"driver", r, Request{Driver: "pgx", DSN: "ok", Query: "SELECT 1"}, ErrDriver},
		{"query", r, Request{Driver: "fake", DSN: "ok", Query: "DROP"}, ErrNotSelect},
		{"open", r, Request{Driver: "fake", DSN: "openfail", Query: "SELECT 1"}, nil},
		{"query fail", r, Request{Driver: "fake", DSN: "queryfail", Query: "SELECT 1"}, nil},
		{"next fail", r, Request{Driver: "fake", DSN: "nextfail", Query: "SELECT 1"}, nil},
		{"too many", Reader{MaxRows: 1}, Request{Driver: "fake", DSN: "ok", Query: "SELECT 1"}, ErrTooMany},
		{"open hook", Reader{Open: func(string, string) (*sql.DB, error) { return nil, errors.New("hook") }}, Request{Driver: "fake", DSN: "ok", Query: "SELECT 1"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.r.Read(context.Background(), tc.req)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err %v want %v", err, tc.want)
			}
		})
	}
}

func TestStringify(t *testing.T) {
	if Stringify(int64(3)) != "3" || Stringify(nil) != "" || Stringify(2.5) != "2.5" || Stringify(make(chan int)) == "" {
		t.Fatal("stringify")
	}
}

// TestMatchWrapsTheQuery proves the database filters: the query of the
// source sits inside an outer SELECT, the field is a quoted identifier
// that the query returns, and the value is an argument.
func TestMatchWrapsTheQuery(t *testing.T) {
	statements = nil
	tb, err := Reader{}.Match(context.Background(), Request{Driver: "fake", DSN: "ok", Query: " SELECT * FROM t ; "}, "name", "x' OR '1'='1")
	if err != nil || len(tb.Rows) != 2 {
		t.Fatalf("match = %+v %v", tb, err)
	}
	want := []string{
		"SELECT * FROM (SELECT * FROM t) vca_q WHERE 1 = 0 |",
		`SELECT * FROM (SELECT * FROM t) vca_q WHERE vca_q."name" = $1 | x' OR '1'='1`,
	}
	if fmt.Sprint(statements) != fmt.Sprint(want) {
		t.Fatalf("statements %q, want %q", statements, want)
	}
	sql.Register("mysql", fakeDriver{})
	statements = nil
	if _, err := (Reader{}).Match(context.Background(), Request{Driver: "mysql", DSN: "ok", Query: "SELECT 1"}, "id", "7"); err != nil {
		t.Fatal(err)
	}
	if statements[1] != "SELECT * FROM (SELECT 1) vca_q WHERE vca_q.`id` = ? | 7" {
		t.Fatalf("mysql statement %q", statements[1])
	}
}

func TestMatchRefuses(t *testing.T) {
	ok := Request{Driver: "fake", DSN: "ok", Query: "SELECT 1"}
	for _, field := range []string{"", "1st", "name;", `name" --`, "a b", string(make([]byte, 64))} {
		if _, err := (Reader{}).Match(context.Background(), ok, field, "v"); !errors.Is(err, ErrField) {
			t.Errorf("field %q: %v", field, err)
		}
	}
	if _, err := (Reader{}).Match(context.Background(), ok, "absent", "v"); !errors.Is(err, ErrField) {
		t.Errorf("a column the query lacks: %v", err)
	}
	if _, err := (Reader{}).Match(context.Background(), Request{Driver: "pgx", Query: "SELECT 1"}, "id", "v"); !errors.Is(err, ErrDriver) {
		t.Errorf("driver: %v", err)
	}
	if _, err := (Reader{}).Match(context.Background(), Request{Driver: "fake", DSN: "queryfail", Query: "SELECT 1"}, "id", "v"); err == nil {
		t.Error("a failed probe gave rows")
	}
	if !identifier("Member_No2") || identifier("_") == false {
		t.Error("plain identifiers")
	}
}
