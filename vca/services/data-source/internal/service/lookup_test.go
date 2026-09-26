// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/httpsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/reader"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
)

// The principal of the holder authorization server of the pair, as the
// interceptor puts it on the context for the service token.
var holderSignIn = authz.ServicePrincipal()

// registryCSV is a register with neutral values: one member per row.
const registryCSV = "member_no,given_name,region\nM-100,[GIVEN NAME A],North\nM-200,[GIVEN NAME B],South\nM-200,[GIVEN NAME C],East\n"

func csvRegistry(access *datasourcev1.Source_Access) *datasourcev1.Source {
	data := reader.DataPrefix + base64.StdEncoding.EncodeToString([]byte(registryCSV))
	return &datasourcev1.Source{DisplayName: "Member register", Access: access,
		Kind: &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{FileRef: data, HasHeader: true}}}
}

// signInAccess lets an operator and the holder sign in issue.
func signInAccess() *datasourcev1.Source_Access {
	return &datasourcev1.Source_Access{
		ViewFields: []string{authz.Operator}, PreviewRows: []string{authz.Operator},
		Issue: []string{authz.Operator, authz.HolderSignIn},
	}
}

// mapped stores a source and its field map to the schema member.
func mapped(t *testing.T, s *Service, src *datasourcev1.Source) string {
	t.Helper()
	created, err := s.Create(as(admin), connect.NewRequest(&datasourcev1.CreateRequest{Source: src}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSource().GetId()
	fm := &datasourcev1.FieldMap{SourceId: id, SchemaId: "member", SchemaVersion: 1, Rules: []*datasourcev1.FieldMap_Rule{
		{Property: "memberNumber", SourceFields: []string{"member_no"}},
		{Property: "givenName", SourceFields: []string{"given_name"}},
	}}
	if _, err := s.SetFieldMap(as(admin), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm})); err != nil {
		t.Fatal(err)
	}
	return id
}

func lookup(s *Service, ctx context.Context, id, field, value string) (*datasourcev1.LookupResponse, error) {
	res, err := s.Lookup(ctx, connect.NewRequest(&datasourcev1.LookupRequest{
		SourceId: id, Field: field, Value: value, SchemaId: "member", SchemaVersion: 1,
	}))
	if err != nil {
		return nil, err
	}
	return res.Msg, nil
}

func claimsOf(t *testing.T, res *datasourcev1.LookupResponse) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(res.GetSubjectData()), &out); err != nil {
		t.Fatalf("subject data %q: %v", res.GetSubjectData(), err)
	}
	return out
}

// TestLookupCsvByField proves the holder sign in gets the one row whose
// field holds the value, through the field map, with its values.
func TestLookupCsvByField(t *testing.T) {
	s := newService(t, nil)
	id := mapped(t, s, csvRegistry(signInAccess()))
	res, err := lookup(s, as(holderSignIn), id, "member_no", "M-100")
	if err != nil {
		t.Fatal(err)
	}
	got := claimsOf(t, res)
	if !res.GetFound() || res.GetAmbiguous() || got["memberNumber"] != "M-100" || got["givenName"] != "[GIVEN NAME A]" {
		t.Fatalf("lookup = %v %v, want the mapped row", res, got)
	}
	if _, ok := got["region"]; ok {
		t.Fatalf("claims %v hold a field the map does not name", got)
	}
	res, err = lookup(s, as(holderSignIn), id, "member_no", "M-999")
	if err != nil || res.GetFound() || res.GetSubjectData() != "" {
		t.Fatalf("absent value: %v %v", res, err)
	}
	res, err = lookup(s, as(holderSignIn), id, "member_no", "M-200")
	if err != nil || res.GetFound() || !res.GetAmbiguous() || res.GetSubjectData() != "" {
		t.Fatalf("two rows must give no subject: %v %v", res, err)
	}
}

// TestLookupMasksTheRowForStaff proves a staff test sees masked values,
// so no unmasked row leaves through the API (ADR-015 decision 4).
func TestLookupMasksTheRowForStaff(t *testing.T) {
	s := newService(t, nil)
	id := mapped(t, s, csvRegistry(signInAccess()))
	res, err := lookup(s, as(operator), id, "member_no", "M-100")
	if err != nil {
		t.Fatal(err)
	}
	got := claimsOf(t, res)
	masked := anyval.As[string](got["memberNumber"])
	if !res.GetFound() || masked == "M-100" || !strings.HasPrefix(masked, "M") {
		t.Fatalf("staff got %v, want masked values", got)
	}
}

// TestLookupHttpFiltersRows proves an HTTP source is read and filtered.
func TestLookupHttpFiltersRows(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		anyval.DiscardWrite(io.WriteString(w, `{"items":[{"member_no":"M-100","given_name":"[GIVEN NAME A]"},{"member_no":"M-300","given_name":"[GIVEN NAME D]"}]}`))
	}))
	defer api.Close()
	host := strings.TrimPrefix(api.URL, "http://")
	s := newService(t, nil)
	s.opts.Reader = reader.Reader{HTTP: httpsrc.Fetcher{Guard: httpsrc.Guard{AllowHosts: []string{host}, AllowHTTP: true, AllowPrivate: true}}}
	id := mapped(t, s, &datasourcev1.Source{DisplayName: "Member API", Access: signInAccess(),
		Kind: &datasourcev1.Source_Http{Http: &datasourcev1.HttpSource{Url: api.URL + "/members", Method: "GET", RowsPath: "/items"}}})
	res, err := lookup(s, as(holderSignIn), id, "member_no", "M-300")
	if err != nil {
		t.Fatal(err)
	}
	if got := claimsOf(t, res); !res.GetFound() || got["givenName"] != "[GIVEN NAME D]" {
		t.Fatalf("lookup = %v", got)
	}
}

// statements records what the lookup driver ran, with its arguments.
type statements struct {
	mu   sync.Mutex
	runs []string
}

func (s *statements) add(q string, args []driver.NamedValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var parts []string
	for _, a := range args {
		parts = append(parts, anyval.As[string](a.Value))
	}
	s.runs = append(s.runs, q+" | "+strings.Join(parts, ","))
}

func (s *statements) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.runs...)
}

var ran = &statements{}

// lookupDriver answers every query with the columns of a register. A
// query with an argument gets the one row whose member_no is that
// argument. A query without one gets no row.
type lookupDriver struct{}

type lookupConn struct{}

type lookupRows struct {
	row []driver.Value
	i   int
}

func (lookupDriver) Open(string) (driver.Conn, error) { return lookupConn{}, nil }

func (lookupConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (lookupConn) Close() error                        { return nil }
func (lookupConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }

func (lookupConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	ran.add(q, args)
	if len(args) == 1 && args[0].Value == "M-100" {
		return &lookupRows{row: []driver.Value{"M-100", "[GIVEN NAME A]"}}, nil
	}
	return &lookupRows{}, nil
}

func (r *lookupRows) Columns() []string { return []string{"member_no", "given_name"} }
func (r *lookupRows) Close() error      { return nil }
func (r *lookupRows) Next(dest []driver.Value) error {
	if r.row == nil || r.i > 0 {
		return io.EOF
	}
	r.i++
	copy(dest, r.row)
	return nil
}

func init() { sql.Register("lookupfake", lookupDriver{}) }

// TestLookupSqlWrapsTheQuery proves the database filters the rows: the
// service wraps the query of the source, quotes the field, and passes
// the value as an argument, never as text of the statement.
func TestLookupSqlWrapsTheQuery(t *testing.T) {
	s := newService(t, nil)
	s.opts.Reader = reader.Reader{Secrets: secrets.Resolver{Getenv: func(string) string { return "dsn" }}}
	id := mapped(t, s, &datasourcev1.Source{DisplayName: "Member database", Access: signInAccess(),
		Kind: &datasourcev1.Source_Sql{Sql: &datasourcev1.SqlSource{
			Driver: "lookupfake", Dsn: &commonv1.SecretRef{Store: commonv1.SecretRef_STORE_ENV, Name: "MEMBERS_DSN"}, Query: "SELECT member_no, given_name FROM members;",
		}}})
	before := len(ran.all())
	res, err := lookup(s, as(holderSignIn), id, "member_no", "M-100")
	if err != nil {
		t.Fatal(err)
	}
	if got := claimsOf(t, res); !res.GetFound() || got["givenName"] != "[GIVEN NAME A]" {
		t.Fatalf("lookup = %v", got)
	}
	runs := ran.all()[before:]
	want := []string{
		`SELECT * FROM (SELECT member_no, given_name FROM members) vca_q WHERE 1 = 0 | `,
		`SELECT * FROM (SELECT member_no, given_name FROM members) vca_q WHERE vca_q."member_no" = $1 | M-100`,
	}
	if strings.Join(runs, "\n") != strings.Join(want, "\n") {
		t.Fatalf("statements:\n%s\nwant:\n%s", strings.Join(runs, "\n"), strings.Join(want, "\n"))
	}
	for _, field := range []string{"region", `member_no" OR 1=1 --`} {
		if _, err := lookup(s, as(holderSignIn), id, field, "M-100"); code(err) != connect.CodeInvalidArgument {
			t.Fatalf("field %q: %v, want InvalidArgument", field, err)
		}
	}
}

// TestLookupUnknownFieldIsInvalidArgument proves a field the source
// does not hold, and a request without a field, a value, or a schema,
// is refused.
func TestLookupUnknownFieldIsInvalidArgument(t *testing.T) {
	s := newService(t, nil)
	id := mapped(t, s, csvRegistry(signInAccess()))
	if _, err := lookup(s, as(holderSignIn), id, "phone", "M-100"); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("unknown field: %v", err)
	}
	for name, req := range map[string]*datasourcev1.LookupRequest{
		"no field":  {SourceId: id, Value: "M-100", SchemaId: "member"},
		"no value":  {SourceId: id, Field: "member_no", SchemaId: "member"},
		"no schema": {SourceId: id, Field: "member_no", Value: "M-100"},
		"long":      {SourceId: id, Field: "member_no", Value: strings.Repeat("M", MaxLookupValue+1), SchemaId: "member"},
	} {
		if _, err := s.Lookup(as(holderSignIn), connect.NewRequest(req)); code(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", name, err)
		}
	}
	if _, err := s.Lookup(as(holderSignIn), connect.NewRequest(&datasourcev1.LookupRequest{
		SourceId: id, Field: "member_no", Value: "M-100", SchemaId: "unmapped",
	})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no field map: %v, want FailedPrecondition", err)
	}
}

// TestLookupNeedsIssueAccess proves the issue rule of the source
// decides: the holder sign in needs its role on the rule, a staff
// member needs one of the rule, and a call without a principal fails.
func TestLookupNeedsIssueAccess(t *testing.T) {
	s := newService(t, nil)
	closed := mapped(t, s, csvRegistry(&datasourcev1.Source_Access{ViewFields: []string{authz.Operator}, Issue: []string{authz.Operator}}))
	if _, err := lookup(s, as(holderSignIn), closed, "member_no", "M-100"); code(err) != connect.CodePermissionDenied {
		t.Fatalf("holder sign in on a source that does not name it: %v", err)
	}
	if _, err := lookup(s, as(viewer), closed, "member_no", "M-100"); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer: %v", err)
	}
	if _, err := lookup(s, context.Background(), closed, "member_no", "M-100"); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("no principal: %v", err)
	}
	if _, err := lookup(s, as(holderSignIn), "nope", "member_no", "M-100"); code(err) != connect.CodeNotFound {
		t.Fatalf("missing source: %v", err)
	}
	if _, err := lookup(s, as(operator), closed, "member_no", "M-100"); err != nil {
		t.Fatalf("an operator on the rule: %v", err)
	}
}

// TestServicePrincipalOpensNothingElse proves the principal of the
// service token reads no source list, no field, and no row preview.
func TestServicePrincipalOpensNothingElse(t *testing.T) {
	s := newService(t, nil)
	id := mapped(t, s, csvRegistry(signInAccess()))
	list, err := s.List(as(holderSignIn), connect.NewRequest(&datasourcev1.ListRequest{}))
	if err != nil || len(list.Msg.GetSources()) != 0 {
		t.Fatalf("list = %v %v", list, err)
	}
	if _, err := s.PreviewRows(as(holderSignIn), connect.NewRequest(&datasourcev1.PreviewRowsRequest{SourceId: id})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("preview: %v", err)
	}
	if _, err := s.Create(as(holderSignIn), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvRegistry(nil)})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.IssueRows(as(holderSignIn), id); code(err) != connect.CodePermissionDenied {
		t.Fatalf("issue rows: %v", err)
	}
}
