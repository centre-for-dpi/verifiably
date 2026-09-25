// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/mapping"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	datasourcev1 "github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/csvsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/httpsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/reader"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/sqlsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/store"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

var (
	admin    = authz.Principal{Subject: "a", Roles: []string{authz.Admin}}
	operator = authz.Principal{Subject: "o", Tenant: "t1", Roles: []string{authz.Operator}}
	viewer   = authz.Principal{Subject: "v", Tenant: "t1", Roles: []string{authz.Viewer}}
	other    = authz.Principal{Subject: "x", Tenant: "t2", Roles: []string{authz.Operator}}
)

func as(p authz.Principal) context.Context { return authz.WithPrincipal(context.Background(), p) }

func newService(t *testing.T, schema SchemaProperties) *Service {
	t.Helper()
	st, err := store.Open(sharedstore.MemoryDoc())
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Store: st, Schema: schema, PageSizeMax: 2, Now: func() time.Time { return time.Unix(100, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func csvSource(name string, access *datasourcev1.Source_Access) *datasourcev1.Source {
	data := reader.DataPrefix + base64.StdEncoding.EncodeToString([]byte("id,name,born\n1,Ada Lovelace,1815-12-10\n2,Grace Hopper,1906-12-09\n3,Bo,\n"))
	return &datasourcev1.Source{DisplayName: name, Access: access, Kind: &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{FileRef: data, HasHeader: true}}}
}

func code(err error) connect.Code {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return 0
}

func TestNewNeedsStore(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("want error")
	}
	s := newService(t, nil)
	if !s.Ready() {
		t.Fatal("ready")
	}
}

func TestSourceLifecycleAndRoles(t *testing.T) {
	s := newService(t, nil)
	access := &datasourcev1.Source_Access{ViewFields: []string{authz.Viewer, authz.Operator}, PreviewRows: []string{authz.Operator}, Issue: []string{authz.Operator}}

	if _, err := s.Create(context.Background(), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvSource("a", access)})); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("no principal: %v", err)
	}
	if _, err := s.Create(as(viewer), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvSource("a", access)})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer create: %v", err)
	}
	if _, err := s.Create(as(operator), connect.NewRequest(&datasourcev1.CreateRequest{Source: &datasourcev1.Source{}})); code(err) != connect.CodeInvalidArgument {
		t.Fatalf("invalid create: %v", err)
	}
	src := csvSource("a", access)
	src.TenantId = "t2"
	if _, err := s.Create(as(operator), connect.NewRequest(&datasourcev1.CreateRequest{Source: src})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("other tenant create: %v", err)
	}
	created, err := s.Create(as(operator), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvSource("a", access)}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSource().GetId()
	if id == "" || created.Msg.GetSource().GetTenantId() != "t1" || created.Msg.GetSource().GetCreatedAt().GetSeconds() != 100 {
		t.Fatalf("created: %v", created.Msg)
	}
	for i := 0; i < 2; i++ {
		if _, serr := s.Create(as(admin), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvSource("b", nil)})); serr != nil {
			t.Fatal(serr)
		}
	}

	// Get and List respect the view rule and the tenant.
	if _, serr := s.Get(as(viewer), connect.NewRequest(&datasourcev1.GetRequest{Id: id})); serr != nil {
		t.Fatalf("viewer get: %v", serr)
	}
	if _, serr := s.Get(as(other), connect.NewRequest(&datasourcev1.GetRequest{Id: id})); code(serr) != connect.CodeNotFound {
		t.Fatalf("other tenant get: %v", serr)
	}
	if _, serr := s.Get(as(viewer), connect.NewRequest(&datasourcev1.GetRequest{Id: "src-2"})); code(serr) != connect.CodePermissionDenied {
		t.Fatalf("viewer get admin only source: %v", serr)
	}
	if _, serr := s.Get(context.Background(), connect.NewRequest(&datasourcev1.GetRequest{Id: id})); code(serr) != connect.CodeUnauthenticated {
		t.Fatalf("no principal get: %v", serr)
	}
	list, err := s.List(as(viewer), connect.NewRequest(&datasourcev1.ListRequest{}))
	if err != nil || len(list.Msg.GetSources()) != 1 || list.Msg.GetPage().GetTotalSize() != 1 {
		t.Fatalf("viewer list: %v %v", list, err)
	}
	list, err = s.List(as(admin), connect.NewRequest(&datasourcev1.ListRequest{}))
	if err != nil || len(list.Msg.GetSources()) != 2 || list.Msg.GetPage().GetNextPageToken() != "2" || list.Msg.GetPage().GetTotalSize() != 3 {
		t.Fatalf("admin list page 1: %v %v", list, err)
	}
	list, err = s.List(as(admin), connect.NewRequest(&datasourcev1.ListRequest{Page: &commonv1.Pagination{PageToken: "2", PageSize: 9}}))
	if err != nil || len(list.Msg.GetSources()) != 1 || list.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("admin list page 2: %v %v", list, err)
	}
	list, err = s.List(as(admin), connect.NewRequest(&datasourcev1.ListRequest{TenantId: "t1"}))
	if err != nil || len(list.Msg.GetSources()) != 1 {
		t.Fatalf("tenant filter: %v %v", list, err)
	}
	if _, serr := s.List(as(admin), connect.NewRequest(&datasourcev1.ListRequest{Page: &commonv1.Pagination{PageToken: "x"}})); code(serr) != connect.CodeInvalidArgument {
		t.Fatalf("bad token: %v", serr)
	}
	if _, serr := s.List(context.Background(), connect.NewRequest(&datasourcev1.ListRequest{})); code(serr) != connect.CodeUnauthenticated {
		t.Fatalf("no principal list: %v", serr)
	}

	// Update keeps the tenant and needs an editor.
	upd := csvSource("a2", access)
	upd.Id = id
	got, err := s.Update(as(operator), connect.NewRequest(&datasourcev1.UpdateRequest{Source: upd}))
	if err != nil || got.Msg.GetSource().GetDisplayName() != "a2" || got.Msg.GetSource().GetTenantId() != "t1" {
		t.Fatalf("update: %v %v", got, err)
	}
	upd.TenantId = "t2"
	if _, serr := s.Update(as(operator), connect.NewRequest(&datasourcev1.UpdateRequest{Source: upd})); code(serr) != connect.CodePermissionDenied {
		t.Fatalf("move tenant: %v", serr)
	}
	upd.Id = "nope"
	if _, serr := s.Update(as(operator), connect.NewRequest(&datasourcev1.UpdateRequest{Source: upd})); code(serr) != connect.CodeNotFound {
		t.Fatalf("update missing: %v", serr)
	}
	if _, serr := s.Update(as(viewer), connect.NewRequest(&datasourcev1.UpdateRequest{Source: upd})); code(serr) != connect.CodePermissionDenied {
		t.Fatalf("viewer update: %v", serr)
	}
	bad := &datasourcev1.Source{Id: id, DisplayName: "x"}
	if _, serr := s.Update(as(operator), connect.NewRequest(&datasourcev1.UpdateRequest{Source: bad})); code(serr) != connect.CodeInvalidArgument {
		t.Fatalf("invalid update: %v", serr)
	}

	// Previews.
	fields, err := s.PreviewFields(as(viewer), connect.NewRequest(&datasourcev1.PreviewFieldsRequest{SourceId: id}))
	if err != nil || len(fields.Msg.GetFields()) != 3 || fields.Msg.GetFields()[2].GetType() != "date" || fields.Msg.GetFields()[1].GetExample() != "A**********e" {
		t.Fatalf("fields: %v %v", fields, err)
	}
	if _, serr := s.PreviewRows(as(viewer), connect.NewRequest(&datasourcev1.PreviewRowsRequest{SourceId: id})); code(serr) != connect.CodePermissionDenied {
		t.Fatalf("viewer preview rows: %v", serr)
	}
	rows, err := s.PreviewRows(as(operator), connect.NewRequest(&datasourcev1.PreviewRowsRequest{SourceId: id, Limit: 2}))
	if err != nil || len(rows.Msg.GetRows()) != 2 || rows.Msg.GetTotalRows() != 3 || rows.Msg.GetRows()[0].GetValues()["id"] != "*" {
		t.Fatalf("rows: %v %v", rows, err)
	}
	rows, err = s.PreviewRows(as(admin), connect.NewRequest(&datasourcev1.PreviewRowsRequest{SourceId: id, Limit: 99}))
	if err != nil || len(rows.Msg.GetRows()) != 3 {
		t.Fatalf("rows capped: %v %v", rows, err)
	}
	if _, serr := s.PreviewRows(as(admin), connect.NewRequest(&datasourcev1.PreviewRowsRequest{SourceId: "nope"})); code(serr) != connect.CodeNotFound {
		t.Fatalf("preview missing: %v", serr)
	}
	if _, serr := s.PreviewFields(context.Background(), connect.NewRequest(&datasourcev1.PreviewFieldsRequest{SourceId: id})); code(serr) != connect.CodeUnauthenticated {
		t.Fatalf("no principal preview: %v", serr)
	}
	broken := csvSource("broken", nil)
	broken.Kind = &datasourcev1.Source_Csv{Csv: &datasourcev1.CsvSource{FileRef: "missing.csv"}}
	b, err := s.Create(as(admin), connect.NewRequest(&datasourcev1.CreateRequest{Source: broken}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PreviewFields(as(admin), connect.NewRequest(&datasourcev1.PreviewFieldsRequest{SourceId: b.Msg.GetSource().GetId()})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("unreadable source: %v", err)
	}

	// RunBulk checks the issue rule then defers to the issuance service.
	if err := s.RunBulk(as(viewer), connect.NewRequest(&datasourcev1.RunBulkRequest{SourceId: id}), nil); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer run: %v", err)
	}
	if err := s.RunBulk(as(operator), connect.NewRequest(&datasourcev1.RunBulkRequest{SourceId: id}), nil); code(err) != connect.CodeUnimplemented {
		t.Fatalf("operator run: %v", err)
	}
	if err := s.RunBulk(as(operator), connect.NewRequest(&datasourcev1.RunBulkRequest{SourceId: "nope"}), nil); code(err) != connect.CodeNotFound {
		t.Fatalf("run missing: %v", err)
	}
	if err := s.RunBulk(context.Background(), connect.NewRequest(&datasourcev1.RunBulkRequest{SourceId: id}), nil); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("run no principal: %v", err)
	}

	// Delete.
	if _, err := s.Delete(as(viewer), connect.NewRequest(&datasourcev1.DeleteRequest{Id: id})); code(err) != connect.CodePermissionDenied {
		t.Fatalf("viewer delete: %v", err)
	}
	if _, err := s.Delete(as(other), connect.NewRequest(&datasourcev1.DeleteRequest{Id: id})); code(err) != connect.CodeNotFound {
		t.Fatalf("other delete: %v", err)
	}
	if _, err := s.Delete(as(operator), connect.NewRequest(&datasourcev1.DeleteRequest{Id: id})); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get(as(operator), connect.NewRequest(&datasourcev1.GetRequest{Id: id})); code(err) != connect.CodeNotFound {
		t.Fatalf("get after delete: %v", err)
	}
}

func TestFieldMaps(t *testing.T) {
	var schemaErr error
	s := newService(t, func(_ context.Context, id string, v int) ([]string, error) {
		return []string{"name", "birthDate", "country"}, schemaErr
	})
	created, err := s.Create(as(operator), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvSource("a", &datasourcev1.Source_Access{ViewFields: []string{authz.Operator}})}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSource().GetId()
	fm := &datasourcev1.FieldMap{SourceId: id, SchemaId: "person", SchemaVersion: 2, Rules: []*datasourcev1.FieldMap_Rule{
		{Property: "name", SourceFields: []string{"name"}, Transform: datasourcev1.Transform_TRANSFORM_TRIM},
		{Property: "birthDate", SourceFields: []string{"born"}, Transform: datasourcev1.Transform_TRANSFORM_DATE_FORMAT, Params: map[string]string{"input_layout": "2006-01-02", "output_layout": "02/01/2006"}},
	}}
	set, err := s.SetFieldMap(as(operator), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm}))
	if err != nil || len(set.Msg.GetUnmappedProperties()) != 1 || set.Msg.GetUnmappedProperties()[0] != "country" {
		t.Fatalf("set: %v %v", set, err)
	}
	if set.Msg.GetFieldMap().GetRules()[1].GetTransform() != datasourcev1.Transform_TRANSFORM_DATE_FORMAT {
		t.Fatalf("transform round trip: %v", set.Msg.GetFieldMap())
	}
	got, err := s.GetFieldMap(as(operator), connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: id, SchemaId: "person"}))
	if err != nil || len(got.Msg.GetFieldMap().GetRules()) != 2 || got.Msg.GetFieldMap().GetSchemaVersion() != 2 {
		t.Fatalf("get: %v %v", got, err)
	}
	if _, serr := s.GetFieldMap(as(operator), connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: id, SchemaId: "other"})); code(serr) != connect.CodeNotFound {
		t.Fatalf("get missing: %v", serr)
	}
	if _, serr := s.GetFieldMap(as(operator), connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: "nope"})); code(serr) != connect.CodeNotFound {
		t.Fatalf("get missing source: %v", serr)
	}
	if _, serr := s.GetFieldMap(as(viewer), connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: id, SchemaId: "person"})); code(serr) != connect.CodePermissionDenied {
		t.Fatalf("viewer get: %v", serr)
	}
	if _, serr := s.GetFieldMap(context.Background(), connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: id})); code(serr) != connect.CodeUnauthenticated {
		t.Fatalf("no principal get: %v", serr)
	}
	if _, serr := s.SetFieldMap(as(viewer), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm})); code(serr) != connect.CodePermissionDenied {
		t.Fatalf("viewer set: %v", serr)
	}
	adminOnly, verr := s.Create(as(admin), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvSource("b", nil)}))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	fm2 := &datasourcev1.FieldMap{SourceId: adminOnly.Msg.GetSource().GetId(), SchemaId: "x", Rules: fm.Rules}
	if _, serr := s.SetFieldMap(as(operator), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm2})); code(serr) != connect.CodePermissionDenied {
		t.Fatalf("operator set on admin only source: %v", serr)
	}
	fm.SchemaId = ""
	if _, serr := s.SetFieldMap(as(operator), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm})); code(serr) != connect.CodeInvalidArgument {
		t.Fatalf("empty schema: %v", serr)
	}
	fm.SchemaId = "person"
	fm.Rules = []*datasourcev1.FieldMap_Rule{{Property: "p", SourceFields: []string{"a"}, Transform: datasourcev1.Transform(99)}}
	if _, serr := s.SetFieldMap(as(operator), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm})); code(serr) != connect.CodeInvalidArgument {
		t.Fatalf("unknown transform: %v", serr)
	}
	fm.Rules = []*datasourcev1.FieldMap_Rule{{Property: "p", SourceFields: []string{"a"}}}
	fm.SourceId = "nope"
	if _, serr := s.SetFieldMap(as(operator), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm})); code(serr) != connect.CodeNotFound {
		t.Fatalf("missing source: %v", serr)
	}
	fm.SourceId = id
	schemaErr = errors.New("down")
	if _, serr := s.SetFieldMap(as(operator), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm})); code(serr) != connect.CodeUnavailable {
		t.Fatalf("schema down: %v", serr)
	}
	if _, serr := s.SetFieldMap(context.Background(), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm})); code(serr) != connect.CodeUnauthenticated {
		t.Fatalf("no principal set: %v", serr)
	}
	// Without a schema lookup the response lists no unmapped property.
	plain := newService(t, nil)
	c2, verr := plain.Create(as(admin), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvSource("a", nil)}))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	fm.SourceId = c2.Msg.GetSource().GetId()
	set, err = plain.SetFieldMap(as(admin), connect.NewRequest(&datasourcev1.SetFieldMapRequest{FieldMap: fm}))
	if err != nil || len(set.Msg.GetUnmappedProperties()) != 0 {
		t.Fatalf("plain set: %v %v", set, err)
	}
	// Delete removes the map with the source.
	if _, err := s.Delete(as(operator), connect.NewRequest(&datasourcev1.DeleteRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetFieldMap(as(operator), connect.NewRequest(&datasourcev1.GetFieldMapRequest{SourceId: id, SchemaId: "person"})); code(err) != connect.CodeNotFound {
		t.Fatalf("map after delete: %v", err)
	}
	// A constant rule keeps its transform through both conversions.
	core := FieldMapFromProto(&datasourcev1.FieldMap{Rules: []*datasourcev1.FieldMap_Rule{{Property: "c", Transform: datasourcev1.Transform_TRANSFORM_CONSTANT, Params: map[string]string{"value": "KE"}}}})
	if core.Rules[0].Transform != mapping.Constant || FieldMapToProto(core).GetRules()[0].GetTransform() != datasourcev1.Transform_TRANSFORM_CONSTANT {
		t.Fatalf("constant: %+v", core)
	}
}

func TestToConnect(t *testing.T) {
	cases := map[error]connect.Code{
		store.ErrNotFound:          connect.CodeNotFound,
		mapping.ErrDuplicateRule:   connect.CodeInvalidArgument,
		csvsrc.ErrTooLarge:         connect.CodeResourceExhausted,
		httpsrc.ErrPrivateIP:       connect.CodePermissionDenied,
		httpsrc.ErrRedirect:        connect.CodePermissionDenied,
		secrets.ErrNotFound:        connect.CodeFailedPrecondition,
		sqlsrc.ErrDriver:           connect.CodeFailedPrecondition,
		httpsrc.ErrNotJSON:         connect.CodeFailedPrecondition,
		httpsrc.ErrStatus:          connect.CodeUnavailable,
		errors.New("dial timeout"): connect.CodeUnavailable,
	}
	for in, want := range cases {
		if got := code(toConnect(in)); got != want {
			t.Errorf("%v: got %v want %v", in, got, want)
		}
	}
	var ce *connect.Error
	if !errors.As(toConnect(csvsrc.ErrTooLarge), &ce) || len(ce.Details()) != 1 {
		t.Fatal("VCA-303 detail missing")
	}
	msg, err := ce.Details()[0].Value()
	if err != nil || mustAs[*commonv1.Error](t, msg).GetCode() != "VCA-303" {
		t.Fatalf("detail: %v %v", msg, err)
	}
	if !errors.As(denied("r"), &ce) || len(ce.Details()) != 1 {
		t.Fatal("VCA-302 detail missing")
	}
}

func TestPage(t *testing.T) {
	if s, e, n, err := page(nil, 5, 10); err != nil || s != 0 || e != 5 || n != "" {
		t.Fatalf("all: %d %d %q %v", s, e, n, err)
	}
	if s, e, n, err := page(&commonv1.Pagination{PageSize: 2, PageToken: "4"}, 5, 10); err != nil || s != 4 || e != 5 || n != "" {
		t.Fatalf("last: %d %d %q %v", s, e, n, err)
	}
	if s, e, _, err := page(&commonv1.Pagination{PageToken: "9"}, 5, 10); err != nil || s != 5 || e != 5 {
		t.Fatalf("past end: %d %d %v", s, e, err)
	}
	if _, _, _, err := page(&commonv1.Pagination{PageToken: "-1"}, 5, 10); err == nil {
		t.Fatal("negative token")
	}
}

// TestIssueRowsNeedsTheIssueRule proves a bulk run reads the rows of a
// source unmasked only for a role on the issue rule of the source.
func TestIssueRowsNeedsTheIssueRule(t *testing.T) {
	s := newService(t, nil)
	s.opts.Reader = reader.Reader{}
	access := &datasourcev1.Source_Access{ViewFields: []string{authz.Viewer, authz.Operator}, PreviewRows: []string{authz.Viewer}, Issue: []string{authz.Operator}}
	created, err := s.Create(as(operator), connect.NewRequest(&datasourcev1.CreateRequest{Source: csvSource("farmers", access)}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSource().GetId()
	tb, err := s.IssueRows(as(operator), id)
	if err != nil {
		t.Fatal(err)
	}
	if len(tb.Rows) != 3 || tb.Rows[0]["name"] != "Ada Lovelace" {
		t.Fatalf("rows = %v, want the values as the source holds them", tb.Rows)
	}
	if _, err := s.IssueRows(as(viewer), id); code(err) != connect.CodePermissionDenied {
		t.Fatalf("a viewer must not read the rows: %v", err)
	}
	if _, err := s.IssueRows(context.Background(), id); code(err) != connect.CodeUnauthenticated {
		t.Fatalf("no principal: %v", err)
	}
}
