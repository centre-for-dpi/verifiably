// SPDX-License-Identifier: Apache-2.0

package reader

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/httpsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/source"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/sqlsrc"
)

type fakeDriver struct{}
type fakeConn struct{}
type fakeRows struct{ i int }

func (fakeDriver) Open(dsn string) (driver.Conn, error) {
	if dsn != "postgres://ok" {
		return nil, errors.New("bad dsn")
	}
	return fakeConn{}, nil
}
func (fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (fakeConn) Close() error                        { return nil }
func (fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }
func (fakeConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &fakeRows{}, nil
}
func (*fakeRows) Columns() []string { return []string{"id", "name"} }
func (*fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	r.i++
	if r.i > 1 {
		return io.EOF
	}
	dest[0], dest[1] = int64(7), "Ada"
	return nil
}

func TestMain(m *testing.M) {
	sql.Register("fakepg", fakeDriver{})
	os.Exit(m.Run())
}

func env(name string) secrets.Ref { return secrets.Ref{Store: secrets.Env, Name: name} }

func newReader(t *testing.T, srv *httptest.Server, vars map[string]string) Reader {
	t.Helper()
	r := Reader{
		Secrets: secrets.Resolver{Getenv: func(k string) string { return vars[k] }},
		SQL:     sqlsrc.Reader{},
		CSVDir:  t.TempDir(),
		ReadFile: func(p string) ([]byte, error) {
			return os.ReadFile(p)
		},
	}
	if srv != nil {
		r.HTTP = httpsrc.Fetcher{Guard: httpsrc.Guard{AllowHosts: []string{"127.0.0.1"}, AllowHTTP: true, AllowPrivate: true}}
	}
	return r
}

func TestReadCSV(t *testing.T) {
	r := newReader(t, nil, nil)
	if err := os.WriteFile(filepath.Join(r.CSVDir, "people.csv"), []byte("id,name\n1,Ada\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src := source.Source{Kind: source.KindCSV, CSV: &source.CSV{FileRef: "people.csv", HasHeader: true}}
	tb, err := r.Read(context.Background(), src)
	if err != nil || len(tb.Rows) != 1 || tb.Rows[0]["name"] != "Ada" {
		t.Fatalf("file csv: %+v %v", tb, err)
	}
	inline := DataPrefix + base64.StdEncoding.EncodeToString([]byte("a;b\n1;2\n"))
	src.CSV = &source.CSV{FileRef: inline, Delimiter: ";", HasHeader: true}
	tb, err = r.Read(context.Background(), src)
	if err != nil || tb.Rows[0]["b"] != "2" {
		t.Fatalf("data url csv: %+v %v", tb, err)
	}
	bad := []source.CSV{{FileRef: DataPrefix + "%%%"}, {FileRef: "../etc/passwd"}, {FileRef: ".hidden"}, {FileRef: ""}, {FileRef: "missing.csv"}}
	for _, c := range bad {
		c := c
		src.CSV = &c
		if _, err := r.Read(context.Background(), src); err == nil {
			t.Errorf("%q must fail", c.FileRef)
		}
	}
	r.CSVDir = ""
	src.CSV = &source.CSV{FileRef: "people.csv"}
	if _, err := r.Read(context.Background(), src); !errors.Is(err, ErrNoCSVDir) {
		t.Fatalf("no dir: %v", err)
	}
	if _, err := r.Read(context.Background(), source.Source{Kind: "odd"}); !errors.Is(err, source.ErrInvalid) {
		t.Fatalf("odd kind: %v", err)
	}
}

func TestReadHTTP(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"rows":[{"id":1,"name":"Ada"}]}`))
	}))
	defer srv.Close()
	vars := map[string]string{"TOKEN": "t0k", "PASS": "pw"}
	r := newReader(t, srv, vars)
	h := &source.HTTP{URL: srv.URL, RowsPath: "/rows", Bearer: env("TOKEN")}
	src := source.Source{Kind: source.KindHTTP, HTTP: h}
	tb, err := r.Read(context.Background(), src)
	if err != nil || tb.Rows[0]["name"] != "Ada" || gotAuth != "Bearer t0k" {
		t.Fatalf("bearer: %+v %v %q", tb, err, gotAuth)
	}
	src.HTTP = &source.HTTP{URL: srv.URL, RowsPath: "/rows", BasicUser: "u", BasicPass: env("PASS")}
	if _, err := r.Read(context.Background(), src); err != nil || !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("basic: %v %q", err, gotAuth)
	}
	src.HTTP = &source.HTTP{URL: srv.URL, RowsPath: "/rows", MTLSCert: env("CERT"), MTLSKey: env("KEY")}
	if _, err := r.Read(context.Background(), src); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("mtls missing cert: %v", err)
	}
	vars["CERT"] = "not pem"
	if _, err := r.Read(context.Background(), src); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("mtls missing key: %v", err)
	}
	vars["KEY"] = "not pem"
	if _, err := r.Read(context.Background(), src); !errors.Is(err, httpsrc.ErrBadMTLS) {
		t.Fatalf("mtls bad pem: %v", err)
	}
	src.HTTP = &source.HTTP{URL: srv.URL, RowsPath: "/rows", Bearer: env("MISSING")}
	if _, err := r.Read(context.Background(), src); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing bearer: %v", err)
	}
}

func TestReadSQL(t *testing.T) {
	r := newReader(t, nil, map[string]string{"DSN": "postgres://ok"})
	src := source.Source{Kind: source.KindSQL, SQL: &source.SQL{Driver: "fakepg", DSN: env("DSN"), Query: "SELECT 1"}}
	tb, err := r.Read(context.Background(), src)
	if err != nil || tb.Rows[0]["name"] != "Ada" || tb.Rows[0]["id"] != "7" {
		t.Fatalf("sql: %+v %v", tb, err)
	}
	src.SQL.DSN = env("NOPE")
	if _, err := r.Read(context.Background(), src); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing dsn: %v", err)
	}
}
