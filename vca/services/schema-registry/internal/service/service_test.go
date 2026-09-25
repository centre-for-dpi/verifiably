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
	fb, ok := backend.(*fakeBackend)
	if backend != nil && !ok {
		t.Fatalf("want a fake backend, got %T", backend)
	}
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
	st, verr := store.Open(sharedstore.MemoryDoc(), store.Options{})
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
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
	if _, serr := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: &schemav1.Schema{Id: "Bad Id"}})); code(serr) != connect.CodeInvalidArgument {
		t.Fatal("bad id")
	}
	if _, serr := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: &schemav1.Schema{Id: "degree"}})); code(serr) != connect.CodeInvalidArgument {
		t.Fatal("invalid update")
	}
	if _, serr := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: schemaWithID("ghost")})); code(serr) != connect.CodeNotFound {
		t.Fatal("missing schema")
	}
	got, err := s.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: "degree"}))
	if err != nil || got.Msg.GetSchema().GetVersion() != 2 {
		t.Fatal("get latest")
	}
	if _, serr := s.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: "degree", Version: 9})); code(serr) != connect.CodeNotFound {
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
	if serr := json.Unmarshal([]byte(fb.calls[0].GetDisplay()), &display); serr != nil || display[0]["name"] != "Degree card" {
		t.Fatalf("display %s %v", fb.calls[0].GetDisplay(), serr)
	}
	if _, serr := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree"})); code(serr) != connect.CodeFailedPrecondition {
		t.Fatalf("no draft left: %v", serr)
	}
	if _, serr := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree", Version: 1})); code(serr) != connect.CodeFailedPrecondition {
		t.Fatal("published version")
	}
	if _, serr := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree", Version: 5})); code(serr) != connect.CodeNotFound {
		t.Fatal("missing version")
	}
	if _, serr := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "ghost"})); code(serr) != connect.CodeNotFound {
		t.Fatal("missing schema")
	}
	vct, err := s.GetVct(ctx, connect.NewRequest(&schemav1.GetVctRequest{Vct: "Degree"}))
	if err != nil || vct.Msg.GetSchemaId() != "degree" || vct.Msg.GetVersion() != 1 || !strings.Contains(vct.Msg.GetTypeMetadata(), `"vct":"https://r/.well-known/vct/Degree"`) {
		t.Fatalf("vct %v %v", vct, err)
	}
	if _, serr := s.GetVct(ctx, connect.NewRequest(&schemav1.GetVctRequest{Vct: "ghost"})); code(serr) != connect.CodeNotFound {
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
	if _, serr := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: schemaWithID("degree")})); serr != nil {
		t.Fatal(serr)
	}
	if _, serr := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree", Version: 2})); serr != nil {
		t.Fatal(serr)
	}
	if _, serr := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree", Version: 9})); code(serr) != connect.CodeNotFound {
		t.Fatal("retire missing version")
	}
	ret, err := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree", Version: 2, Reason: "test"}))
	if err != nil || len(ret.Msg.GetSchemas()) != 1 || ret.Msg.GetSchemas()[0].GetState() != schemav1.State_STATE_RETIRED {
		t.Fatalf("retire one %v %v", ret, err)
	}
	if _, serr := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree", Version: 2})); code(serr) != connect.CodeFailedPrecondition {
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
	if past, ierr := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Page: &commonv1.Pagination{PageToken: "99"}})); ierr != nil || len(past.Msg.GetSchemas()) != 0 {
		t.Fatal("offset past the end")
	}
	if _, serr := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Page: &commonv1.Pagination{PageToken: "x"}})); code(serr) != connect.CodeInvalidArgument {
		t.Fatal("bad token")
	}
	list, listErr2 := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{State: schemav1.State_STATE_PUBLISHED}))
	if listErr2 != nil {
		t.Fatalf("unexpected error: %v", listErr2)
	}
	if len(list.Msg.GetSchemas()) != 1 || list.Msg.GetSchemas()[0].GetId() != "beta" {
		t.Fatal("state filter")
	}
	list, listErr1 := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Format: commonv1.Format_FORMAT_MSO_MDOC}))
	if listErr1 != nil {
		t.Fatalf("unexpected error: %v", listErr1)
	}
	if len(list.Msg.GetSchemas()) != 0 {
		t.Fatal("format filter")
	}
	if _, serr := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{Format: commonv1.Format_FORMAT_LDP_VC_BBS})); code(serr) != connect.CodeInvalidArgument {
		t.Fatal("unsupported format")
	}
	list, listErr := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{TenantId: "t1"}))
	if listErr != nil {
		t.Fatalf("unexpected error: %v", listErr)
	}
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

// TestDeleteDraftOnly checks that only a draft version can go. A
// published version gives FailedPrecondition with the sentence that
// names the way out, and the last draft takes the schema with it.
func TestDeleteDraftOnly(t *testing.T) {
	ctx := context.Background()
	s, _ := newService(t, nil)
	create(t, s, "Degree")
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree"})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: schemaWithID("degree")})); err != nil {
		t.Fatal(err)
	}
	_, err := s.DeleteDraft(ctx, connect.NewRequest(&schemav1.DeleteDraftRequest{Id: "degree", Version: 1}))
	if code(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "Retire a published version.") {
		t.Fatalf("published version: %v", err)
	}
	del, err := s.DeleteDraft(ctx, connect.NewRequest(&schemav1.DeleteDraftRequest{Id: "degree"}))
	if err != nil || del.Msg.GetSchema().GetVersion() != 2 || del.Msg.GetSchemaRemoved() {
		t.Fatalf("latest draft: %v %v", del, err)
	}
	versions, err := s.ListVersions(ctx, connect.NewRequest(&schemav1.ListVersionsRequest{Id: "degree"}))
	if err != nil || len(versions.Msg.GetSchemas()) != 1 || versions.Msg.GetSchemas()[0].GetVersion() != 1 {
		t.Fatalf("versions after delete: %v %v", versions, err)
	}
	if _, derr := s.DeleteDraft(ctx, connect.NewRequest(&schemav1.DeleteDraftRequest{Id: "degree"})); code(derr) != connect.CodeFailedPrecondition {
		t.Fatalf("no draft left: %v", derr)
	}
	if _, rerr := s.Retire(ctx, connect.NewRequest(&schemav1.RetireRequest{Id: "degree", Version: 1})); rerr != nil {
		t.Fatal(rerr)
	}
	_, err = s.DeleteDraft(ctx, connect.NewRequest(&schemav1.DeleteDraftRequest{Id: "degree", Version: 1}))
	if code(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "A retired version stays") {
		t.Fatalf("retired version: %v", err)
	}
	for _, req := range []*schemav1.DeleteDraftRequest{{Id: "degree", Version: 7}, {Id: "ghost"}} {
		if _, derr := s.DeleteDraft(ctx, connect.NewRequest(req)); code(derr) != connect.CodeNotFound {
			t.Fatalf("%v: %v", req, derr)
		}
	}
	// The only version of a schema is a draft: the schema goes with it.
	create(t, s, "Permit")
	del, err = s.DeleteDraft(ctx, connect.NewRequest(&schemav1.DeleteDraftRequest{Id: "permit", Version: 1}))
	if err != nil || !del.Msg.GetSchemaRemoved() {
		t.Fatalf("only draft: %v %v", del, err)
	}
	if _, gerr := s.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: "permit"})); code(gerr) != connect.CodeNotFound {
		t.Fatalf("schema after its last draft: %v", gerr)
	}
	list, err := s.List(ctx, connect.NewRequest(&schemav1.ListRequest{}))
	if err != nil || len(list.Msg.GetSchemas()) != 1 {
		t.Fatalf("list after delete: %v %v", list, err)
	}
}

// TestMappingIsStoredAndChecked checks that a version keeps its context
// extensions and its claim mappings, and that the service refuses a
// mapping that breaks a rule with InvalidArgument.
func TestMappingIsStoredAndChecked(t *testing.T) {
	ctx := context.Background()
	s, _ := newService(t, nil)
	create(t, s, "Degree")
	m := schemaWithID("degree")
	m.Contexts = []string{" https://schema.org/ ", ""}
	m.ClaimMappings = []*schemav1.ClaimMapping{{Claim: "name", Iri: "https://schema.org/name", Labels: []*schemav1.ClaimLabel{{Locale: "en", Label: "Name"}}}}
	up, err := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: m}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, connect.NewRequest(&schemav1.GetRequest{Id: "degree", Version: up.Msg.GetSchema().GetVersion()}))
	if err != nil || len(got.Msg.GetSchema().GetContexts()) != 1 || got.Msg.GetSchema().GetContexts()[0] != "https://schema.org/" ||
		got.Msg.GetSchema().GetClaimMappings()[0].GetLabels()[0].GetLabel() != "Name" {
		t.Fatalf("stored %v %v", got, err)
	}
	for _, bad := range []*schemav1.Schema{
		func() *schemav1.Schema { b := schemaWithID("degree"); b.Contexts = []string{"schema.org"}; return b }(),
		func() *schemav1.Schema {
			b := schemaWithID("degree")
			b.ClaimMappings = []*schemav1.ClaimMapping{{Claim: "ghost"}}
			return b
		}(),
	} {
		if _, err := s.Update(ctx, connect.NewRequest(&schemav1.UpdateRequest{Schema: bad})); code(err) != connect.CodeInvalidArgument {
			t.Fatalf("update %v: %v", bad.GetContexts(), err)
		}
		if _, err := s.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: bad})); code(err) != connect.CodeInvalidArgument {
			t.Fatalf("create %v: %v", bad.GetContexts(), err)
		}
	}
}

// TestPublishSendsContexts hands the context extensions of an ldp_vc
// version to the adapter, which registers them with the stack.
func TestPublishSendsContexts(t *testing.T) {
	ctx := context.Background()
	s, fb := newService(t, &fakeBackend{})
	m := schema("Degree")
	m.Contexts = []string{"https://example.org/contexts/degree.jsonld"}
	if _, err := s.Create(ctx, connect.NewRequest(&schemav1.CreateRequest{Schema: m})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, connect.NewRequest(&schemav1.PublishRequest{Id: "degree"})); err != nil {
		t.Fatal(err)
	}
	if len(fb.calls) != 2 {
		t.Fatalf("calls %d", len(fb.calls))
	}
	for _, c := range fb.calls {
		if len(c.GetContexts()) != 1 || c.GetContexts()[0] != m.Contexts[0] {
			t.Fatalf("contexts %v", c.GetContexts())
		}
	}
}
