// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/record"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/store"
)

const doc = `{"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}`

var now = time.Date(2024, 1, 31, 10, 0, 0, 0, time.UTC)

// fakeBackend records RegisterCredentialConfiguration calls.
type fakeBackend struct {
	backendv1connect.UnimplementedIssuerBackendServiceHandler
	calls []*backendv1.CredentialConfiguration
	err   error
	empty bool
}

func (f *fakeBackend) RegisterCredentialConfiguration(_ context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	f.calls = append(f.calls, req.Msg.GetConfiguration())
	id := "dpg:" + req.Msg.GetConfiguration().GetId()
	if f.empty {
		id = ""
	}
	return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: id}), nil
}

func newService(t *testing.T, backend backendv1connect.IssuerBackendServiceClient) (*Service, *fakeBackend) {
	t.Helper()
	st, err := store.Open(sharedstore.MemoryDoc(), store.Options{NewID: func(typ string) string { return strings.ToLower(typ) }})
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := backend.(*fakeBackend)
	s, err := New(Options{Store: st, Backend: backend, Metadata: metadata.Options{BaseURL: "https://r"}, PageSizeMax: 2, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return s, fb
}

func schema(typ string) *schemav1.Schema {
	return &schemav1.Schema{
		Type: typ, JsonSchema: doc, Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT, commonv1.Format_FORMAT_LDP_VC},
		Display: []*schemav1.Display{{Name: typ + " card", Locale: "en", Description: "A " + typ}}, SdClaims: []string{"name"},
	}
}

func create(t *testing.T, s *Service, typ string) *schemav1.Schema {
	t.Helper()
	resp, err := s.Create(context.Background(), connect.NewRequest(&schemav1.CreateRequest{Schema: schema(typ)}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg.GetSchema()
}

func code(err error) connect.Code {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return 0
}

func TestNew(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("store required")
	}
	s, _ := newService(t, nil)
	if !s.Ready() || s.Store() == nil {
		t.Fatal("ready")
	}
	if s.MetadataOptions().Now != now {
		t.Fatal("now")
	}
	st, _ := store.Open(sharedstore.MemoryDoc(), store.Options{})
	if d, err := New(Options{Store: st}); err != nil || d.opts.PageSizeMax != DefaultPageSize || d.opts.Now == nil {
		t.Fatal("defaults")
	}
}

func TestCreateUpdateGet(t *testing.T) {
	ctx := context.Background()
	s, _ := newService(t, nil)
	v1 := create(t, s, "Degree")
	if v1.GetId() != "degree" || v1.GetVersion() != 1 || v1.GetState() != schemav1.State_STATE_DRAFT {
		t.Fatalf("v1 %v", v1)
	}
	if _, err := s.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("invalid create")
	}
	up, err := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: &schemav1.Schema{Id: "degree", Type: "Degree", JsonSchema: doc, Formats: v1.GetFormats()}}))
	if err != nil || up.Msg.GetSchema().GetVersion() != 2 {
		t.Fatalf("update %v %v", up, err)
	}
	if _, err := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: &schemav1.Schema{Id: "Bad Id"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("bad id")
	}
	if _, err := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: &schemav1.Schema{Id: "degree"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("invalid update")
	}
	if _, err := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: schemaWithID("ghost")})); code(err) != connect.CodeNotFound {
		t.Fatal("missing schema")
	}
	got, err := s.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: "degree"}))
	if err != nil || got.Msg.GetSchema().GetVersion() != 2 {
		t.Fatal("get latest")
	}
	if _, err := s.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: "degree", Version: 9})); code(err) != connect.CodeNotFound {
		t.Fatal("get missing")
	}
	versions, err := s.ListVersions(ctx, connect.NewRequest(&schemav1.ListVersionsRequest{Id: "degree"}))
	if err != nil || len(versions.Msg.GetSchemas()) != 2 || versions.Msg.GetSchemas()[0].GetVersion() != 2 {
		t.Fatal("versions newest first")
	}
	if _, err := s.ListVersions(ctx, connect.NewRequest(&schemav1.ListVersionsRequest{Id: "ghost"})); code(err) != connect.CodeNotFound {
		t.Fatal("versions missing")
	}
}

func schemaWithID(id string) *schemav1.Schema {
	m := schema("X")
	m.Id = id
	return m
}

func TestPublishAndRetire(t *testing.T) {
	ctx := context.Background()
	s, fb := newService(t, &fakeBackend{})
	create(t, s, "Degree")
	pub, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree"}))
	if err != nil {
		t.Fatal(err)
	}
	if pub.Msg.GetConfigurationId() != "dpg:Degree_dc+sd-jwt" || pub.Msg.GetSchema().GetState() != schemav1.State_STATE_PUBLISHED {
		t.Fatalf("publish %v", pub.Msg)
	}
	if len(fb.calls) != 2 || fb.calls[0].GetType() != "Degree" || fb.calls[0].GetFormat() != commonv1.Format_FORMAT_DC_SD_JWT || fb.calls[0].GetSdClaims()[0] != "name" {
		t.Fatalf("calls %v", fb.calls)
	}
	var display []map[string]any
	if err := json.Unmarshal([]byte(fb.calls[0].GetDisplay()), &display); err != nil || display[0]["name"] != "Degree card" {
		t.Fatalf("display %s %v", fb.calls[0].GetDisplay(), err)
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree"})); code(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no draft left: %v", err)
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree", Version: 1})); code(err) != connect.CodeFailedPrecondition {
		t.Fatal("published version")
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree", Version: 5})); code(err) != connect.CodeNotFound {
		t.Fatal("missing version")
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "ghost"})); code(err) != connect.CodeNotFound {
		t.Fatal("missing schema")
	}
	vct, err := s.GetVct(ctx, connect.NewRequest(&schemav1.GetVctRequest{Vct: "Degree"}))
	if err != nil || vct.Msg.GetSchemaId() != "degree" || vct.Msg.GetVersion() != 1 || !strings.Contains(vct.Msg.GetTypeMetadata(), `"vct":"https://r/.well-known/vct/Degree"`) {
		t.Fatalf("vct %v %v", vct, err)
	}
	if _, err := s.GetVct(ctx, connect.NewRequest(&schemav1.GetVctRequest{Vct: "ghost"})); code(err) != connect.CodeNotFound {
		t.Fatal("vct missing")
	}
	meta, err := s.GetIssuerMetadata(ctx, connect.NewRequest(&schemav1.GetIssuerMetadataRequest{}))
	if err != nil || len(meta.Msg.GetCredentialConfigurationsSupported()) != 2 || meta.Msg.GetGeneratedAt().AsTime() != now {
		t.Fatalf("metadata %v %v", meta, err)
	}
	if !strings.Contains(meta.Msg.GetCredentialConfigurationsSupported()["dpg:Degree_dc+sd-jwt"], `"format":"dc+sd-jwt"`) {
		t.Fatal("configuration by DPG id")
	}
	pubList, err := s.ListPublic(ctx, connect.NewRequest(&schemav1.ListPublicRequest{}))
	if err != nil || len(pubList.Msg.GetSchemas()) != 1 || pubList.Msg.GetSchemas()[0].GetConfigurationIds()["ldp_vc"] != "dpg:Degree_ldp_vc" {
		t.Fatalf("public %v %v", pubList, err)
	}
	// A second draft, published, then retire every published version.
	if _, err := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: schemaWithID("degree")})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree", Version: 2})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree", Version: 9})); code(err) != connect.CodeNotFound {
		t.Fatal("retire missing version")
	}
	ret, err := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree", Version: 2, Reason: "test"}))
	if err != nil || len(ret.Msg.GetSchemas()) != 1 || ret.Msg.GetSchemas()[0].GetState() != schemav1.State_STATE_RETIRED {
		t.Fatalf("retire one %v %v", ret, err)
	}
	if _, err := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree", Version: 2})); code(err) != connect.CodeFailedPrecondition {
		t.Fatal("retire twice")
	}
	ret, err = s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree"}))
	if err != nil || len(ret.Msg.GetSchemas()) != 1 || ret.Msg.GetSchemas()[0].GetVersion() != 1 {
		t.Fatalf("retire all %v %v", ret, err)
	}
	if _, err := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree"})); code(err) != connect.CodeNotFound {
		t.Fatal("nothing to retire")
	}
	if _, err := s.GetVct(ctx, connect.NewRequest(&schemav1.GetVctRequest{Vct: "Degree"})); code(err) != connect.CodeNotFound {
		t.Fatal("retired vct")
	}
}

func TestPublishBackendVariants(t *testing.T) {
	ctx := context.Background()
	s, _ := newService(t, &fakeBackend{err: errors.New("down")})
	create(t, s, "Degree")
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree"})); code(err) != connect.CodeUnavailable {
		t.Fatalf("backend down: %v", err)
	}
	s, _ = newService(t, &fakeBackend{empty: true})
	create(t, s, "Degree")
	pub, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree"}))
	if err != nil || pub.Msg.GetConfigurationId() != "Degree_dc+sd-jwt" {
		t.Fatalf("empty id keeps the derived id: %v %v", pub, err)
	}
	s, _ = newService(t, nil)
	create(t, s, "Degree")
	pub, err = s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree"}))
	if err != nil || pub.Msg.GetConfigurationId() != "Degree_dc+sd-jwt" {
		t.Fatalf("no backend: %v %v", pub, err)
	}
}

func TestListSearchAndPaging(t *testing.T) {
	ctx := context.Background()
	s, _ := newService(t, nil)
	for _, typ := range []string{"Alpha", "Beta", "Gamma"} {
		create(t, s, typ)
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "beta"})); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{}))
	if err != nil || len(list.Msg.GetSchemas()) != 2 || list.Msg.GetPage().GetNextPageToken() != "2" || list.Msg.GetPage().GetTotalSize() != 3 {
		t.Fatalf("page 1 %v %v", list, err)
	}
	list, err = s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Page: &commonv1.Pagination{PageToken: "2", PageSize: 10}}))
	if err != nil || len(list.Msg.GetSchemas()) != 1 || list.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("page 2 %v %v", list, err)
	}
	if list, _ := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Page: &commonv1.Pagination{PageToken: "99"}})); len(list.Msg.GetSchemas()) != 0 {
		t.Fatal("offset past the end")
	}
	if _, err := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Page: &commonv1.Pagination{PageToken: "x"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("bad token")
	}
	list, _ = s.List(ctx, connect.NewRequest(&schemav1.ListRequest{State: schemav1.State_STATE_PUBLISHED}))
	if len(list.Msg.GetSchemas()) != 1 || list.Msg.GetSchemas()[0].GetId() != "beta" {
		t.Fatal("state filter")
	}
	list, _ = s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Format: commonv1.Format_FORMAT_MSO_MDOC}))
	if len(list.Msg.GetSchemas()) != 0 {
		t.Fatal("format filter")
	}
	if _, err := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Format: commonv1.Format_FORMAT_LDP_VC_BBS})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("unsupported format")
	}
	list, _ = s.List(ctx, connect.NewRequest(&schemav1.ListRequest{TenantId: "t1"}))
	if len(list.Msg.GetSchemas()) != 0 {
		t.Fatal("tenant filter")
	}
	found, err := s.Search(ctx, connect.NewRequest(&schemav1.SearchRequest{Query: "gam"}))
	if err != nil || len(found.Msg.GetSchemas()) != 1 || found.Msg.GetSchemas()[0].GetId() != "gamma" {
		t.Fatalf("search %v %v", found, err)
	}
	if _, err := s.Search(ctx, connect.NewRequest(&schemav1.SearchRequest{Query: strings.Repeat("a", MaxQueryLength+1)})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("long query")
	}
	if _, err := s.Search(ctx, connect.NewRequest(&schemav1.SearchRequest{Page: &commonv1.Pagination{PageToken: "-1"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("bad search token")
	}
	if _, err := s.ListPublic(ctx, connect.NewRequest(&schemav1.ListPublicRequest{Page: &commonv1.Pagination{PageToken: "z"}})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("bad public token")
	}
}

func TestStoreError(t *testing.T) {
	if code(storeError(store.ErrNotFound)) != connect.CodeNotFound {
		t.Fatal("not found")
	}
	if code(storeError(errors.New("record: bad"))) != connect.CodeFailedPrecondition {
		t.Fatal("record")
	}
	if code(storeError(errors.New("store: disk"))) != connect.CodeInternal {
		t.Fatal("internal")
	}
	if code(errors.New("plain")) != 0 {
		t.Fatal("plain")
	}
	_ = record.StateDraft
}
