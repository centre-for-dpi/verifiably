// SPDX-License-Identifier: Apache-2.0

package migrate_test

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/internal/migrate"
)

// answers returns a full set of fake query answers.
func answers(t *testing.T) map[string]fakeResult {
	t.Helper()
	issuedAt := mustTime(t, "2025-06-01T00:00:00Z")
	revoked := mustTime(t, "2025-06-02T00:00:00Z")
	return map[string]fakeResult{
		"issued_credentials": {
			columns: []string{"id", "schema_id", "schema_name", "std", "format", "issuer_dpg",
				"owner_key", "holder_hint", "offer_uri", "issued_at", "revoked_at",
				"subject_fields", "status_list"},
			rows: [][]driver.Value{
				{"vc-1", "schema-a", "Licence", "w3c_vcdm_2", "ldp_vc", "waltid", "oidc|1",
					"A Person", "openid-credential-offer://x", issuedAt, nil,
					[]byte(`{"id":"holder-1"}`), []byte(`{"type":"bitstring","listId":"bitstring-v1","index":3}`)},
				{"vc-2", "schema-b", "Diploma", "", "", "", "", "", "", issuedAt, revoked,
					[]byte(``), []byte(`null`)},
			},
		},
		"status_lists": {
			columns: []string{"list_id", "kind", "next_free", "bits"},
			rows: [][]driver.Value{
				{"bitstring-v1", "bitstring", int64(4), []byte{0, 0, 0, 0}},
			},
		},
		"trusted_issuers": {
			columns: []string{"did", "display_name", "schemas", "service_endpoint",
				"status_list_endpoints", "status_list_policy", "accredited_at", "valid_until"},
			rows: [][]driver.Value{
				{"did:web:issuer.example", "Issuer", `{schema-a,"schema,b"}`, "https://issuer.example",
					"{}", "fail-closed", issuedAt, nil},
			},
		},
	}
}

func TestReadPostgres(t *testing.T) {
	db := openFake(t, answers(t))
	got, err := migrate.ReadPostgres(context.Background(), db)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got.Issued) != 2 || len(got.Lists) != 1 || len(got.Trust) != 1 {
		t.Fatalf("counts: %+v", got)
	}
	first := got.Issued[0]
	if first.SubjectFields["id"] != "holder-1" || first.StatusList.Index != 3 {
		t.Fatalf("issued: %+v", first)
	}
	if got.Issued[1].RevokedAt == nil || got.Issued[1].StatusList != nil {
		t.Fatalf("revoked: %+v", got.Issued[1])
	}
	if got.Lists[0].Size != 32 || got.Lists[0].NextFree != 4 {
		t.Fatalf("list: %+v", got.Lists[0])
	}
	if len(got.Trust[0].Schemas) != 2 || got.Trust[0].Schemas[1] != "schema,b" {
		t.Fatalf("schemas: %v", got.Trust[0].Schemas)
	}
	if got.Trust[0].StatusListEndpoints != nil {
		t.Fatalf("endpoints: %v", got.Trust[0].StatusListEndpoints)
	}
}

func TestReadPostgresValidUntil(t *testing.T) {
	a := answers(t)
	rows := a["trusted_issuers"].rows
	rows[0][7] = mustTime(t, "2030-01-01T00:00:00Z")
	got, err := migrate.ReadPostgres(context.Background(), openFake(t, a))
	if err != nil || got.Trust[0].ValidUntil.Year() != 2030 {
		t.Fatalf("valid until: %+v %v", got.Trust, err)
	}
}

func TestReadPostgresQueryErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, table := range []string{"issued_credentials", "status_lists", "trusted_issuers"} {
		a := answers(t)
		a[table] = fakeResult{err: boom}
		if _, err := migrate.ReadPostgres(context.Background(), openFake(t, a)); err == nil {
			t.Fatalf("%s: want an error", table)
		}
	}
}

func TestReadPostgresRowErrors(t *testing.T) {
	boom := errors.New("boom")
	for _, table := range []string{"issued_credentials", "status_lists", "trusted_issuers"} {
		a := answers(t)
		res := a[table]
		res.rowErr = boom
		a[table] = res
		if _, err := migrate.ReadPostgres(context.Background(), openFake(t, a)); err == nil {
			t.Fatalf("%s: want an error", table)
		}
	}
}

func TestReadPostgresScanErrors(t *testing.T) {
	// The column of each table that holds a number or a time. A string
	// in its place makes the scan fail.
	column := map[string]int{"issued_credentials": 9, "status_lists": 2, "trusted_issuers": 6}
	for table, at := range column {
		a := answers(t)
		res := a[table]
		rows := make([][]driver.Value, len(res.rows))
		for i := range res.rows {
			row := append([]driver.Value(nil), res.rows[i]...)
			row[at] = "not a value"
			rows[i] = row
		}
		res.rows = rows
		a[table] = res
		if _, err := migrate.ReadPostgres(context.Background(), openFake(t, a)); err == nil {
			t.Fatalf("%s: want a scan error", table)
		}
	}
}

func TestReadPostgresBadJSON(t *testing.T) {
	a := answers(t)
	res := a["issued_credentials"]
	res.rows[0][11] = []byte("{")
	a["issued_credentials"] = res
	if _, err := migrate.ReadPostgres(context.Background(), openFake(t, a)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("subject_fields: %v", err)
	}

	b := answers(t)
	other := b["issued_credentials"]
	other.rows[0][12] = []byte("{")
	b["issued_credentials"] = other
	if _, err := migrate.ReadPostgres(context.Background(), openFake(t, b)); !errors.Is(err, migrate.ErrInput) {
		t.Fatalf("status_list: %v", err)
	}
}

func TestParseTextArray(t *testing.T) {
	cases := map[string][]string{
		"":                      nil,
		"x":                     nil,
		"{}":                    nil,
		"{a,b}":                 {"a", "b"},
		`{a,"b,c"}`:             {"a", "b,c"},
		`{"a\"b"}`:              {`a"b`},
		`{https://a,https://b}`: {"https://a", "https://b"},
	}
	for in, want := range cases {
		got := migrate.ParseTextArray(in)
		if len(got) != len(want) {
			t.Fatalf("%q: got %v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q: got %v, want %v", in, got, want)
			}
		}
	}
}

func TestOpenPostgres(t *testing.T) {
	if _, err := migrate.OpenPostgres("no-such-driver", "dsn"); err == nil {
		t.Fatal("want an error for a missing driver")
	}
	openFake(t, answers(t))
	db, err := migrate.OpenPostgres("migratefake", t.Name())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("db.Close: %v", err)
	}
}
