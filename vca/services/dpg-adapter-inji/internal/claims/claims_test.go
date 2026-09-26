// SPDX-License-Identifier: Apache-2.0

package claims

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var start = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func writer(t *testing.T) (Writer, *time.Time) {
	t.Helper()
	now := start
	return Writer{Dir: t.TempDir(), Now: func() time.Time { return now }}, &now
}

func row(subject string) Row {
	return Row{
		Subject: subject, ConfigID: "vca-residence-ldp", ExpiresAt: start.Add(15 * time.Minute),
		ValidFrom: "2026-09-26T12:00:00Z", StatusURI: "https://status.gov.example/1", StatusIndex: "7",
		Claims: []string{"Amina Njeri", "1990-01-02"},
	}
}

// TestPutWritesOneFilePerSubject: the file name is the SHA-256 of the
// subject, it holds one CSV row of every column, and the database user
// can read it.
func TestPutWritesOneFilePerSubject(t *testing.T) {
	w, _ := writer(t)
	if err := w.Put(row(Key("abc"))); err != nil {
		t.Fatalf("Put: %v", err)
	}
	sum := sha256.Sum256([]byte(`{"id":"abc"}`))
	path := filepath.Join(w.Dir, hex.EncodeToString(sum[:])+".csv")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no file: %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode = %04o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a file of the temporary store
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Count(text, "\n") != 1 || !strings.HasSuffix(text, "\n") {
		t.Errorf("not one row: %q", text)
	}
	if !strings.HasPrefix(text, `"{""id"":""abc""}","vca-residence-ldp","2026-09-26T12:15:00Z"`) {
		t.Errorf("row = %q", text)
	}
	if got := strings.Count(text, `","`) + 1; got != Columns {
		t.Errorf("row has %d columns, want %d", got, Columns)
	}
	// A second subject gets its own file, and a second write of the same
	// subject replaces its file.
	if errErr := w.Put(row(Key("def"))); errErr != nil {
		t.Fatal(errErr)
	}
	again := row(Key("abc"))
	again.Claims = []string{"Other"}
	if errErr := w.Put(again); errErr != nil {
		t.Fatal(errErr)
	}
	entries, err := os.ReadDir(w.Dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %v %v", entries, err)
	}
	got, ok, err := w.Find(Key("abc"))
	if err != nil || !ok || got.Claims[0] != "Other" || len(got.Claims) != MaxClaims {
		t.Errorf("Find = %+v %v %v", got, ok, err)
	}
}

// TestPutIsAtomic: the writer renames a finished file into place, so the
// database never reads half a row. No temporary file stays behind, and
// no temporary name matches the pattern the table reads.
func TestPutIsAtomic(t *testing.T) {
	w, _ := writer(t)
	var seen []string
	w.rename = func(from, to string) error {
		seen = append(seen, filepath.Base(from), filepath.Base(to))
		if strings.HasSuffix(filepath.Base(from), ".csv") {
			t.Errorf("the temporary name %s matches *.csv", from)
		}
		raw, err := os.ReadFile(from) //nolint:gosec // G304: a file of the temporary store
		if err != nil || !strings.HasSuffix(string(raw), "\n") {
			t.Errorf("the file is not complete before the rename: %q %v", raw, err)
		}
		return os.Rename(from, to)
	}
	if err := w.Put(row(Key("abc"))); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("renames = %v", seen)
	}
	entries, err := os.ReadDir(w.Dir)
	if err != nil || len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".csv") {
		t.Errorf("entries = %v %v", entries, err)
	}
	// A failed rename removes the temporary file.
	w.rename = func(string, string) error { return os.ErrPermission }
	if errErr := w.Put(row(Key("def"))); errErr == nil {
		t.Error("a failed rename passed")
	}
	entries, err = os.ReadDir(w.Dir)
	if err != nil || len(entries) != 1 {
		t.Errorf("entries after a failed rename = %v %v", entries, err)
	}
}

// TestSweepDeletesExpiredRows: the sweep deletes the file of each row
// whose offer has expired and keeps the others.
func TestSweepDeletesExpiredRows(t *testing.T) {
	w, now := writer(t)
	short := row(Key("short"))
	short.ExpiresAt = start.Add(time.Minute)
	if err := w.Put(short); err != nil {
		t.Fatal(err)
	}
	if err := w.Put(row(Key("long"))); err != nil {
		t.Fatal(err)
	}
	// A file that is not a row stays, and a broken row goes.
	if err := os.WriteFile(filepath.Join(w.Dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.Dir, "broken.csv"), []byte("\"a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	*now = start.Add(2 * time.Minute)
	removed, err := w.Sweep()
	if err != nil || removed != 2 {
		t.Fatalf("Sweep = %d %v", removed, err)
	}
	if _, ok, ferr := w.Find(Key("short")); ok || ferr != nil {
		t.Error("the expired row stays")
	}
	if _, ok, ferr := w.Find(Key("long")); !ok || ferr != nil {
		t.Error("the live row went")
	}
	if _, err := os.Stat(filepath.Join(w.Dir, "notes.txt")); err != nil {
		t.Error("the sweep deleted a file that is not a row")
	}
	// Put sweeps too.
	*now = start.Add(time.Hour)
	if err := w.Put(row(Key("new"))); err != nil {
		t.Fatal(err)
	}
	if _, ok, ferr := w.Find(Key("long")); ok || ferr != nil {
		t.Error("Put did not sweep")
	}
	// A missing directory is an error.
	missing := Writer{Dir: filepath.Join(w.Dir, "none")}
	if _, err := missing.Sweep(); err == nil {
		t.Error("a missing directory passed")
	}
	if err := missing.Put(row("x")); err == nil {
		t.Error("a write to a missing directory passed")
	}
}

// TestKeyMatchesJacksonForm: the subject of a pre-authorized token is
// the JSON text Certify writes for the staged map. Key gives the same
// bytes.
func TestKeyMatchesJacksonForm(t *testing.T) {
	if got := Key("abc"); got != `{"id":"abc"}` {
		t.Errorf("Key = %s", got)
	}
	if got := Key("a<b>&c"); got != `{"id":"a<b>&c"}` {
		t.Errorf("Key does not keep HTML characters: %s", got)
	}
}

// TestRowEncodesObjectsAsJSON: a column holds the JSON text of an object,
// an array, a number, or a boolean, and a string as it is.
func TestRowEncodesObjectsAsJSON(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"Amina", "Amina"},
		{json.Number("42"), "42"},
		{float64(3.5), "3.5"},
		{true, "true"},
		{nil, ""},
		{map[string]any{"city": "Nairobi"}, `{"city":"Nairobi"}`},
		{[]any{"a", "b"}, `["a","b"]`},
	}
	for _, c := range cases {
		if got := Value(c.in); got != c.want {
			t.Errorf("Value(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	// A value with quotes, commas and a line break survives a round trip.
	w, _ := writer(t)
	r := row(Key("q"))
	r.Claims = []string{"a \"quoted\", value\nnext", ""}
	if err := w.Put(r); err != nil {
		t.Fatal(err)
	}
	got, ok, err := w.Find(Key("q"))
	if err != nil || !ok || got.Claims[0] != r.Claims[0] || got.Claims[1] != "" {
		t.Errorf("round trip = %+v %v %v", got.Claims, ok, err)
	}
	if got.ValidFrom != r.ValidFrom || got.StatusURI != r.StatusURI || got.StatusIndex != r.StatusIndex ||
		got.ConfigID != r.ConfigID || !got.ExpiresAt.Equal(r.ExpiresAt) {
		t.Errorf("reserved columns = %+v", got)
	}
	// More claims than columns fail.
	r.Claims = make([]string, MaxClaims+1)
	if err := w.Put(r); err == nil {
		t.Error("65 claims passed")
	}
	// Map returns the claims by name for a column list.
	named := got.Map([]string{"fullName", "note", "extra"})
	if named["fullName"] != got.Claims[0] || got.Claims[0] == "" || len(named) != 3 || named["extra"] != "" {
		t.Errorf("Map = %v", named)
	}
}

// TestColumnName: the columns are c1 to c64.
func TestColumnName(t *testing.T) {
	if ColumnName(0) != "c1" || ColumnName(63) != "c64" {
		t.Errorf("names = %s %s", ColumnName(0), ColumnName(63))
	}
}

// providerRow reads the keys of the fixture row in file order, and the
// values by key.
func providerRow(t *testing.T) ([]string, map[string]string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "doc", "postgres-provider-row.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if _, err = dec.Token(); err != nil {
		t.Fatal(err)
	}
	var keys []string
	values := map[string]string{}
	for dec.More() {
		var tok json.Token
		if tok, err = dec.Token(); err != nil {
			t.Fatal(err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatalf("key %v is not a string", tok)
		}
		var value string
		if err = dec.Decode(&value); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		keys = append(keys, key)
		values[key] = value
	}
	return keys, values
}

// columnOrder returns the column names of a row in table order.
func columnOrder() []string {
	out := append([]string(nil), reserved...)
	for i := range MaxClaims {
		out = append(out, ColumnName(i))
	}
	return out
}

// TestColumnsMatchTheProviderRow: the Postgres data provider returns the
// first row as a JSON object with the column names as keys
// (testdata/doc/postgres-provider-row.json). The template of a
// configuration reads those keys, so the writer must fill the same
// columns in the same order.
func TestColumnsMatchTheProviderRow(t *testing.T) {
	keys, values := providerRow(t)
	want := columnOrder()
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("the provider row has the columns\n%v\nwant\n%v", keys, want)
	}
	// The row of the fixture, written and read back, keeps every value
	// in its column.
	w, _ := writer(t)
	expires, err := time.Parse(time.RFC3339, values["expires_at"])
	if err != nil {
		t.Fatal(err)
	}
	r := Row{
		Subject: values["subject"], ConfigID: values["config_id"], ExpiresAt: expires,
		ValidFrom: values[ValidFromColumn], ValidUntil: values[ValidUntilColumn],
		StatusURI: values[StatusURIColumn], StatusIndex: values[StatusIndexColumn],
	}
	for i := range MaxClaims {
		r.Claims = append(r.Claims, values[ColumnName(i)])
	}
	w.Now = func() time.Time { return expires.Add(-time.Minute) }
	if perr := w.Put(r); perr != nil {
		t.Fatal(perr)
	}
	line, err := os.ReadFile(filepath.Join(w.Dir, fileName(r.Subject)))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSuffix(string(line), "\n"), `","`)
	if len(fields) != len(want) {
		t.Fatalf("the file holds %d fields, want %d", len(fields), len(want))
	}
	if got := strings.Trim(fields[len(reserved)], `"`); got != values["c1"] {
		t.Fatalf("c1 = %q, want %q", got, values["c1"])
	}
}

// TestColumnsMatchTheForeignTable: vca_claims.sql of the stack declares
// the columns of the foreign table in the order the writer fills them.
// file_fdw maps the fields of a CSV line onto the columns by position.
func TestColumnsMatchTheForeignTable(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "deploy", "vca", "dpg", "inji", "certify", "vca_claims.sql")
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a fixed path of the tree
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	open := strings.Index(sql, "certify.vca_claims (")
	end := strings.Index(sql, ") SERVER")
	if open < 0 || end < open {
		t.Fatalf("%s declares no table certify.vca_claims", path)
	}
	var got []string
	for _, line := range strings.Split(sql[open+len("certify.vca_claims ("):end], "\n") {
		line = strings.TrimSuffix(strings.TrimSpace(line), ",")
		if line == "" {
			continue
		}
		name, typ, _ := strings.Cut(line, " ")
		if typ != "text" {
			t.Errorf("column %s has the type %q, want text", name, typ)
		}
		got = append(got, name)
	}
	if want := columnOrder(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the foreign table has the columns\n%v\nwant\n%v", got, want)
	}
	for _, want := range []string{"program 'cat /vca/claims/*.csv", "format 'csv'", "header 'false'"} {
		if !strings.Contains(sql, want) {
			t.Errorf("%s lacks %q", path, want)
		}
	}
}

// TestFindReportsABrokenRow: a file that holds no row is an error for
// Find, and a missing directory is an error for Put, so a write never
// looks like it worked.
func TestFindReportsABrokenRow(t *testing.T) {
	w, _ := writer(t)
	if err := os.WriteFile(filepath.Join(w.Dir, fileName("broken")), []byte("\"a\",\"b\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Find("broken"); err == nil {
		t.Fatal("Find accepted a short row")
	}
	good := row("late")
	encoded := strings.Replace(string(encode(good)), good.ExpiresAt.Format(time.RFC3339), "tomorrow", 1)
	if err := os.WriteFile(filepath.Join(w.Dir, fileName("late")), []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Find("late"); err == nil || !strings.Contains(err.Error(), "end of the row") {
		t.Fatalf("Find accepted a row without an end: %v", err)
	}
	if err := os.Mkdir(filepath.Join(w.Dir, fileName("dir")), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.Find("dir"); err == nil {
		t.Fatal("Find read a directory")
	}
	gone := Writer{Dir: filepath.Join(w.Dir, "gone")}
	if err := gone.Put(row("x")); err == nil {
		t.Fatal("Put wrote into a missing directory")
	}
}

// TestWriterReadsTheRealClockByDefault: a writer without a clock keeps
// a row that ends in the future.
func TestWriterReadsTheRealClockByDefault(t *testing.T) {
	w := Writer{Dir: t.TempDir()}
	r := row("now")
	r.ExpiresAt = time.Now().Add(time.Hour)
	if err := w.Put(r); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := w.Find("now"); err != nil || !ok {
		t.Fatalf("Find = %v, %v", ok, err)
	}
}
