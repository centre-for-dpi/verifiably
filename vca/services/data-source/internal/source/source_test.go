// SPDX-License-Identifier: Apache-2.0

package source

import (
	"errors"
	"testing"
	"time"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
)

func envRef(name string) *commonv1.SecretRef {
	return &commonv1.SecretRef{Store: commonv1.SecretRef_STORE_ENV, Name: name}
}

func TestRoundTrip(t *testing.T) {
	cases := []*datasourcev1.Source{
		{DisplayName: "csv", Kind: &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{FileRef: "a.csv", Delimiter: ";", HasHeader: true, Encoding: "utf-8"}}},
		{DisplayName: "bearer", Kind: &datasourcev1.Source_Http{Http: &datasourcev1.HttpSource{Url: "https://api.example/rows", Method: "get", Headers: map[string]string{"X-A": "1"}, RowsPath: "/rows", TimeoutSeconds: 5, Auth: &datasourcev1.HttpSource_BearerToken{BearerToken: envRef("TOKEN")}}}},
		{DisplayName: "basic", Kind: &datasourcev1.Source_Http{Http: &datasourcev1.HttpSource{Url: "https://api.example/rows", Auth: &datasourcev1.HttpSource_Basic{Basic: &datasourcev1.HttpSource_BasicAuth{Username: "u", Password: &commonv1.SecretRef{Store: commonv1.SecretRef_STORE_FILE, Name: "pw"}}}}}},
		{DisplayName: "mtls", Kind: &datasourcev1.Source_Http{Http: &datasourcev1.HttpSource{Url: "https://api.example/rows", Auth: &datasourcev1.HttpSource_Mtls{Mtls: &datasourcev1.HttpSource_MtlsAuth{Certificate: &commonv1.SecretRef{Store: commonv1.SecretRef_STORE_KMS, Name: "k/c"}, PrivateKey: &commonv1.SecretRef{Store: commonv1.SecretRef_STORE_KMS, Name: "k/k"}}}}}},
		{DisplayName: "sql", TenantId: "t1", Access: &datasourcev1.Source_Access{ViewFields: []string{"issuer-viewer", " "}, PreviewRows: []string{"issuer-operator"}, Issue: []string{"issuer-operator"}}, Kind: &datasourcev1.Source_Sql{Sql: &datasourcev1.SqlSource{Driver: "postgres", Dsn: envRef("DSN"), Query: "SELECT 1", TimeoutSeconds: 10}}},
	}
	for _, in := range cases {
		s := FromProto(in)
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", in.DisplayName, err)
		}
		s.CreatedAt = time.Unix(1, 0)
		s.UpdatedAt = time.Unix(2, 0)
		out := ToProto(s)
		if out.GetDisplayName() != in.GetDisplayName() || out.GetCreatedAt().GetSeconds() != 1 || out.GetUpdatedAt().GetSeconds() != 2 {
			t.Fatalf("%s: round trip lost fields: %v", in.DisplayName, out)
		}
		back := FromProto(out)
		back.CreatedAt, back.UpdatedAt = time.Time{}, time.Time{}
		if ToProto(back).String() != ToProto(FromProto(in)).String() {
			t.Fatalf("%s: second round trip differs:\n%v\n%v", in.DisplayName, ToProto(back), ToProto(FromProto(in)))
		}
	}
	http := FromProto(cases[1]).HTTP
	if http.Method != "GET" || http.Bearer != (secrets.Ref{Store: secrets.Env, Name: "TOKEN"}) || http.Timeout != 5*time.Second {
		t.Fatalf("http fields: %+v", http)
	}
	sql := FromProto(cases[4])
	if len(sql.Access.ViewFields) != 1 || sql.TimeoutOf() != 10*time.Second || sql.SQL.DSN.Store != secrets.Env {
		t.Fatalf("sql fields: %+v", sql)
	}
	if FromProto(cases[0]).TimeoutOf() != DefaultTimeout || FromProto(cases[2]).TimeoutOf() != DefaultTimeout {
		t.Fatal("default timeout")
	}
	if refFromProto(nil) != (secrets.Ref{}) || refToProto(secrets.Ref{Name: "x"}).GetStore() != commonv1.SecretRef_STORE_UNSPECIFIED {
		t.Fatal("empty refs")
	}
}

func TestValidateErrors(t *testing.T) {
	ok := func(s Source) Source { return s }
	env := secrets.Ref{Store: secrets.Env, Name: "X"}
	bad := []Source{
		{},
		ok(Source{DisplayName: "n"}),
		{DisplayName: "n", Kind: KindCSV},
		{DisplayName: "n", Kind: KindCSV, CSV: &CSV{}},
		{DisplayName: "n", Kind: KindCSV, CSV: &CSV{FileRef: "a", Delimiter: "ab"}},
		{DisplayName: "n", Kind: KindHTTP},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "/rel"}},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", Method: "PUT"}},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", Headers: map[string]string{"authorization": "x"}}},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", RowsPath: "rows"}},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", Bearer: env, BasicPass: env}},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", BasicPass: env}},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", MTLSCert: env}},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", Bearer: secrets.Ref{Store: secrets.Env, Name: "bad name"}}},
		{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", Timeout: time.Hour}},
		{DisplayName: "n", Kind: KindSQL},
		{DisplayName: "n", Kind: KindSQL, SQL: &SQL{}},
		{DisplayName: "n", Kind: KindSQL, SQL: &SQL{Driver: "pg"}},
		{DisplayName: "n", Kind: KindSQL, SQL: &SQL{Driver: "pg", DSN: env, Query: "DROP TABLE t"}},
		{DisplayName: "n", Kind: KindSQL, SQL: &SQL{Driver: "pg", DSN: env, Query: "SELECT 1", Timeout: -1}},
	}
	for i, s := range bad {
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: want ErrInvalid, got %v", i, err)
		}
	}
	good := Source{DisplayName: "n", Kind: KindHTTP, HTTP: &HTTP{URL: "https://a", BasicUser: "u", BasicPass: env, Timeout: time.Second}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if ToProto(Source{DisplayName: "x"}).GetKind() != nil {
		t.Fatal("unknown kind must give no kind")
	}
}
