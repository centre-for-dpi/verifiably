// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/dedi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/etsi"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/keys"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/lookup"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/store"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// flaky is a backend whose Save fails once failAt is reached.
type flaky struct {
	saves  int
	failAt int
}

func (f *flaky) Load() ([]byte, bool, error) { return nil, false, nil }
func (f *flaky) Save([]byte) error {
	f.saves++
	if f.failAt > 0 && f.saves >= f.failAt {
		return errors.New("disk full")
	}
	return nil
}

type fixture struct {
	svc   *Service
	clock *time.Time
	ring  *keys.Ring
}

func newFixture(t *testing.T, backend sharedstore.Document, publishers ...publish.Publisher) fixture {
	t.Helper()
	if backend == nil {
		backend = sharedstore.MemoryDoc()
	}
	st, err := store.Open(backend)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := keys.Generate(jose.ES256, t0)
	ring, _ := keys.NewRing(k)
	if len(publishers) == 0 {
		publishers = []publish.Publisher{etsi.Publisher{}, dedi.Publisher{}}
	}
	now := t0
	clock := func() time.Time { return now }
	cache := lookup.New(publishers, ring.JWKS, lookup.Options{Policy: lookup.FailClosed, MaxAge: time.Hour, Now: clock})
	fetch := func(_ context.Context, url string) ([]byte, error) {
		if strings.Contains(url, "missing") {
			return nil, errors.New("404")
		}
		return []byte(`{"id":"did:web:issuer.example"}`), nil
	}
	resolver := did.NewResolver(fetch, nil)
	svc, err := New(Options{
		Store: st, Ring: ring, Publishers: publishers, Cache: cache, Resolver: &resolver,
		BaseURL: "https://trust.example", Issuer: publish.Issuer{ID: "did:web:trust.example", Name: "R"},
		ListTTL: time.Hour, PageSizeMax: 2, Now: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{svc: svc, clock: &now, ring: ring}
}

func didID(s string) *trustv1.TrustEntry_Identifier {
	return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: s}}
}

func protoEntry(didStr string, role commonv1.Role, status trustv1.Status) *trustv1.TrustEntry {
	return &trustv1.TrustEntry{Identifier: didID(didStr), DisplayName: "E", Role: role, Status: status}
}

func upsert(t *testing.T, svc *Service, e *trustv1.TrustEntry) {
	t.Helper()
	if _, err := svc.UpsertEntry(context.Background(), connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: e})); err != nil {
		t.Fatal(err)
	}
}

func code(err error) connect.Code {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce.Code()
	}
	return connect.Code(0)
}

func TestNewErrors(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("missing options")
	}
	st, _ := store.Open(sharedstore.MemoryDoc())
	k, _ := keys.Generate(jose.ES256, t0)
	ring, _ := keys.NewRing(k)
	bad := failing{method: "etsi", publishErr: errors.New("no")}
	cache := lookup.New([]publish.Publisher{bad}, ring.JWKS, lookup.Options{})
	if _, err := New(Options{Store: st, Ring: ring, Publishers: []publish.Publisher{bad}, Cache: cache}); err == nil {
		t.Fatal("publish error")
	}
	dup := []publish.Publisher{etsi.Publisher{}, etsi.Publisher{}}
	if _, err := New(Options{Store: st, Ring: ring, Publishers: dup, Cache: lookup.New(dup, ring.JWKS, lookup.Options{})}); err == nil {
		t.Fatal("duplicate paths")
	}
	unverifiable := failing{method: "etsi", verifyErr: errors.New("bad signature")}
	cache = lookup.New([]publish.Publisher{unverifiable}, ring.JWKS, lookup.Options{})
	if _, err := New(Options{Store: st, Ring: ring, Publishers: []publish.Publisher{unverifiable}, Cache: cache}); err == nil {
		t.Fatal("verify error")
	}
	ok := failing{method: "etsi"}
	svc, err := New(Options{Store: st, Ring: ring, Publishers: []publish.Publisher{ok}, Cache: lookup.New([]publish.Publisher{ok}, ring.JWKS, lookup.Options{})})
	if err != nil || svc.opts.PageSizeMax != DefaultPageSize || svc.opts.ListTTL != 24*time.Hour || !svc.Ready() {
		t.Fatal("defaults")
	}
}

// failing is a publisher with programmable errors.
type failing struct {
	method     string
	publishErr error
	verifyErr  error
}

func (f failing) Method() string { return f.method }
func (f failing) Publish(in publish.Input) (publish.Publication, error) {
	if f.publishErr != nil {
		return publish.Publication{}, f.publishErr
	}
	return publish.Publication{Method: f.method, Files: map[string]publish.File{"/" + f.method: {}}, Sequence: in.Sequence}, nil
}
func (f failing) Verify(map[string]publish.File, jose.JWKS, time.Time) (publish.Verified, error) {
	if f.verifyErr != nil {
		return publish.Verified{}, f.verifyErr
	}
	return publish.Verified{ExpiresAt: t0.Add(time.Hour)}, nil
}

func TestCRUDAndPublish(t *testing.T) {
	f := newFixture(t, nil)
	svc := f.svc
	ctx := context.Background()
	if !svc.Ready() || len(svc.Snapshot().Methods()) != 2 || !strings.Contains(string(svc.JWKSJSON()), f.ring.Active().ID) {
		t.Fatal("initial publication")
	}
	resp, err := svc.UpsertEntry(ctx, connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: protoEntry("did:web:issuer.example", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetEntry().GetUpdatedAt().AsTime() != t0 {
		t.Fatal("updated_at")
	}
	bad := []*trustv1.TrustEntry{
		nil,
		protoEntry("did:web:missing.example", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE),
	}
	for i, e := range bad {
		if _, err := svc.UpsertEntry(ctx, connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: e})); code(err) != connect.CodeInvalidArgument {
			t.Errorf("upsert case %d: %v", i, err)
		}
	}
	got, err := svc.GetEntry(ctx, connect.NewRequest(&trustv1.GetEntryRequest{Identifier: didID("did:web:issuer.example")}))
	if err != nil || got.Msg.GetEntry().GetDisplayName() != "E" {
		t.Fatal("get", err)
	}
	if _, err := svc.GetEntry(ctx, connect.NewRequest(&trustv1.GetEntryRequest{Identifier: didID("did:web:none")})); code(err) != connect.CodeNotFound {
		t.Fatal("get missing", err)
	}
	if _, err := svc.GetEntry(ctx, connect.NewRequest(&trustv1.GetEntryRequest{})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("get invalid", err)
	}
	pub, err := svc.Publish(ctx, connect.NewRequest(&trustv1.PublishRequest{Method: trustv1.Method_METHOD_DEDI}))
	if err != nil || len(pub.Msg.GetPublications()) != 1 || pub.Msg.GetPublications()[0].GetMethod() != trustv1.Method_METHOD_DEDI || pub.Msg.GetPublications()[0].GetEntryCount() != 1 {
		t.Fatalf("publish dedi %v %+v", err, pub)
	}
	if pub.Msg.GetPublications()[0].GetKeyId() != f.ring.Active().ID || pub.Msg.GetPublications()[0].GetUrl() != "https://trust.example/.well-known/dedi.index.json" {
		t.Fatalf("publication %+v", pub.Msg.GetPublications()[0])
	}
	all, err := svc.Publish(ctx, connect.NewRequest(&trustv1.PublishRequest{}))
	if err != nil || len(all.Msg.GetPublications()) != 2 {
		t.Fatal("publish all", err)
	}
	if _, err := svc.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{Identifier: didID("did:web:issuer.example")})); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{Identifier: didID("did:web:issuer.example")})); code(err) != connect.CodeNotFound {
		t.Fatal("delete twice", err)
	}
	if _, err := svc.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("delete invalid", err)
	}
	if p, _ := svc.Snapshot().Publication("etsi"); p.EntryCount != 0 {
		t.Fatal("delete republishes")
	}
}

func TestPublishMethodNotEnabled(t *testing.T) {
	f := newFixture(t, nil, etsi.Publisher{})
	if _, err := f.svc.Publish(context.Background(), connect.NewRequest(&trustv1.PublishRequest{Method: trustv1.Method_METHOD_DEDI})); code(err) != connect.CodeFailedPrecondition {
		t.Fatal(err)
	}
	if svc := f.svc; svc.enabled("dedi") || !svc.enabled("etsi") {
		t.Fatal("enabled")
	}
}

func TestListEntries(t *testing.T) {
	f := newFixture(t, nil)
	svc := f.svc
	ctx := context.Background()
	upsert(t, svc, protoEntry("did:web:a", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE))
	upsert(t, svc, protoEntry("did:web:b", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_REVOKED))
	typed := protoEntry("did:web:c", commonv1.Role_ROLE_VERIFIER, trustv1.Status_STATUS_ACTIVE)
	typed.CredentialTypes = []string{"A"}
	upsert(t, svc, typed)
	list := func(req *trustv1.ListEntriesRequest) *trustv1.ListEntriesResponse {
		t.Helper()
		resp, err := svc.ListEntries(ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg
	}
	page := list(&trustv1.ListEntriesRequest{})
	if len(page.GetEntries()) != 2 || page.GetPage().GetNextPageToken() != "2" || page.GetPage().GetTotalSize() != 3 {
		t.Fatalf("page 1 %+v", page)
	}
	page = list(&trustv1.ListEntriesRequest{Page: &commonv1.Pagination{PageToken: "2", PageSize: 10}})
	if len(page.GetEntries()) != 1 || page.GetPage().GetNextPageToken() != "" || page.GetEntries()[0].GetIdentifier().GetDid() != "did:web:c" {
		t.Fatalf("page 2 %+v", page)
	}
	page = list(&trustv1.ListEntriesRequest{Page: &commonv1.Pagination{PageToken: "9"}})
	if len(page.GetEntries()) != 0 {
		t.Fatal("offset past the end")
	}
	if len(list(&trustv1.ListEntriesRequest{Role: commonv1.Role_ROLE_ISSUER}).GetEntries()) != 2 {
		t.Fatal("role filter")
	}
	if len(list(&trustv1.ListEntriesRequest{Status: trustv1.Status_STATUS_REVOKED}).GetEntries()) != 1 {
		t.Fatal("status filter")
	}
	if got := list(&trustv1.ListEntriesRequest{CredentialType: "B"}).GetEntries(); len(got) != 2 {
		t.Fatalf("type filter %d", len(got))
	}
	bad := []*trustv1.ListEntriesRequest{
		{Page: &commonv1.Pagination{PageToken: "x"}},
		{Page: &commonv1.Pagination{PageToken: "-1"}},
		{Role: commonv1.Role_ROLE_ADMIN},
		{Status: trustv1.Status(9)},
	}
	for i, req := range bad {
		if _, err := svc.ListEntries(ctx, connect.NewRequest(req)); code(err) != connect.CodeInvalidArgument {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestTrustLookup(t *testing.T) {
	f := newFixture(t, nil)
	svc := f.svc
	ctx := context.Background()
	upsert(t, svc, protoEntry("did:web:a", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE))
	lookupReq := func(id string, role commonv1.Role, at *timestamppb.Timestamp) *trustv1.TrustLookupResponse {
		t.Helper()
		resp, err := svc.TrustLookup(ctx, connect.NewRequest(&trustv1.TrustLookupRequest{Identifier: didID(id), Role: role, At: at}))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Msg
	}
	r := lookupReq("did:web:a", commonv1.Role_ROLE_ISSUER, nil)
	if r.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED || r.GetEntry() == nil || r.GetProvenance().GetMethod() != trustv1.Method_METHOD_ETSI || !r.GetProvenance().GetCached() {
		t.Fatalf("trusted %+v", r)
	}
	if r.GetProvenance().GetListUrl() != "https://trust.example/trust-list/etsi.jws" || r.GetProvenance().GetKeyId() != f.ring.Active().ID || r.GetProvenance().GetCheckedAt().AsTime() != t0 {
		t.Fatalf("provenance %+v", r.GetProvenance())
	}
	r = lookupReq("did:web:a", commonv1.Role_ROLE_VERIFIER, nil)
	if r.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED || r.GetReason() == "" {
		t.Fatalf("untrusted %+v", r)
	}
	if r := lookupReq("did:web:z", commonv1.Role_ROLE_ISSUER, timestamppb.New(t0)); r.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_UNKNOWN {
		t.Fatalf("unknown %+v", r)
	}
	*f.clock = t0.Add(3 * time.Hour)
	r = lookupReq("did:web:a", commonv1.Role_ROLE_ISSUER, nil)
	if r.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE || r.GetProvenance() == nil {
		t.Fatalf("stale %+v", r)
	}
	if _, err := svc.TrustLookup(ctx, connect.NewRequest(&trustv1.TrustLookupRequest{})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("no id", err)
	}
	if _, err := svc.TrustLookup(ctx, connect.NewRequest(&trustv1.TrustLookupRequest{Identifier: didID("did:web:a")})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("no role", err)
	}
}

const tsl = `<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><TrustServiceProviderList>
<TrustServiceProvider><TSPInformation><TSPName><Name xml:lang="en">P</Name></TSPName></TSPInformation><TSPServices>
<TSPService><ServiceInformation><ServiceName><Name xml:lang="en">S</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509SubjectName>CN=CA</X509SubjectName></DigitalId></ServiceDigitalIdentity><ServiceStatus>http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted</ServiceStatus></ServiceInformation></TSPService>
<TSPService><ServiceInformation><ServiceName><Name xml:lang="en">Empty</Name></ServiceName><ServiceDigitalIdentity/><ServiceStatus>x</ServiceStatus></ServiceInformation></TSPService>
</TSPServices></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`

func TestImportEtsi(t *testing.T) {
	f := newFixture(t, nil)
	svc := f.svc
	ctx := context.Background()
	dry, err := svc.ImportEtsi(ctx, connect.NewRequest(&trustv1.ImportEtsiRequest{Xml: []byte(tsl), DryRun: true}))
	if err != nil || dry.Msg.GetCreated() != 1 || dry.Msg.GetUpdated() != 0 || len(dry.Msg.GetSkipped()) != 1 {
		t.Fatalf("dry run %v %+v", err, dry)
	}
	if svc.opts.Store.Revision() != 0 {
		t.Fatal("dry run must not write")
	}
	real, err := svc.ImportEtsi(ctx, connect.NewRequest(&trustv1.ImportEtsiRequest{Xml: []byte(tsl)}))
	if err != nil || real.Msg.GetCreated() != 1 {
		t.Fatal("import", err)
	}
	again, err := svc.ImportEtsi(ctx, connect.NewRequest(&trustv1.ImportEtsiRequest{Xml: []byte(tsl)}))
	if err != nil || again.Msg.GetUpdated() != 1 || again.Msg.GetCreated() != 0 {
		t.Fatal("import again", err)
	}
	if p, _ := svc.Snapshot().Publication("etsi"); p.EntryCount != 1 {
		t.Fatal("import republishes")
	}
	x509 := &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: "CN=CA"}}
	r, err := svc.TrustLookup(ctx, connect.NewRequest(&trustv1.TrustLookupRequest{Identifier: x509, Role: commonv1.Role_ROLE_ISSUER}))
	if err != nil || r.Msg.GetOutcome() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED {
		t.Fatal("lookup imported", err)
	}
	if _, err := svc.ImportEtsi(ctx, connect.NewRequest(&trustv1.ImportEtsiRequest{Xml: []byte("<x")})); code(err) != connect.CodeInvalidArgument {
		t.Fatal("bad xml", err)
	}
	empty, err := svc.ImportEtsi(ctx, connect.NewRequest(&trustv1.ImportEtsiRequest{Xml: []byte(`<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"/>`)}))
	if err != nil || empty.Msg.GetCreated() != 0 {
		t.Fatal("empty list", err)
	}
}

func TestStoreFailures(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, &flaky{failAt: 1})
	e := protoEntry("did:web:a", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)
	if _, err := f.svc.UpsertEntry(ctx, connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: e})); code(err) != connect.CodeInternal {
		t.Fatal("upsert save", err)
	}
	if _, err := f.svc.ImportEtsi(ctx, connect.NewRequest(&trustv1.ImportEtsiRequest{Xml: []byte(tsl)})); code(err) != connect.CodeInternal {
		t.Fatal("import save", err)
	}
	f = newFixture(t, &flaky{failAt: 2})
	upsert(t, f.svc, e)
	if _, err := f.svc.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{Identifier: didID("did:web:a")})); code(err) != connect.CodeInternal {
		t.Fatal("delete save", err)
	}
}

func TestRepublishFailures(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(sharedstore.MemoryDoc())
	k, _ := keys.Generate(jose.ES256, t0)
	ring, _ := keys.NewRing(k)
	p := &togglePublisher{}
	cache := lookup.New([]publish.Publisher{p}, ring.JWKS, lookup.Options{Now: func() time.Time { return t0 }})
	svc, err := New(Options{Store: st, Ring: ring, Publishers: []publish.Publisher{p}, Cache: cache, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	p.err = errors.New("signer down")
	e := protoEntry("did:web:a", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)
	if _, err := svc.UpsertEntry(ctx, connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: e})); code(err) != connect.CodeInternal {
		t.Fatal("upsert republish", err)
	}
	if _, err := svc.Publish(ctx, connect.NewRequest(&trustv1.PublishRequest{})); code(err) != connect.CodeInternal {
		t.Fatal("publish", err)
	}
	if _, err := svc.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{Identifier: didID("did:web:a")})); code(err) != connect.CodeInternal {
		t.Fatal("delete republish", err)
	}
	if _, err := svc.ImportEtsi(ctx, connect.NewRequest(&trustv1.ImportEtsiRequest{Xml: []byte(tsl)})); code(err) != connect.CodeInternal {
		t.Fatal("import republish", err)
	}
}

// togglePublisher fails Publish once err is set.
type togglePublisher struct{ err error }

func (p *togglePublisher) Method() string { return "etsi" }
func (p *togglePublisher) Publish(publish.Input) (publish.Publication, error) {
	if p.err != nil {
		return publish.Publication{}, p.err
	}
	return publish.Publication{Method: "etsi", Files: map[string]publish.File{"/etsi": {}}}, nil
}
func (p *togglePublisher) Verify(map[string]publish.File, jose.JWKS, time.Time) (publish.Verified, error) {
	return publish.Verified{ExpiresAt: t0.Add(time.Hour)}, nil
}

func TestOverConnect(t *testing.T) {
	f := newFixture(t, nil)
	mux := http.NewServeMux()
	mux.Handle(trustv1connect.NewTrustServiceHandler(f.svc))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := trustv1connect.NewTrustServiceClient(srv.Client(), srv.URL)
	if _, err := client.UpsertEntry(context.Background(), connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: protoEntry("did:web:a", commonv1.Role_ROLE_ISSUER, trustv1.Status_STATUS_ACTIVE)})); err != nil {
		t.Fatal(err)
	}
	resp, err := client.ListEntries(context.Background(), connect.NewRequest(&trustv1.ListEntriesRequest{}))
	if err != nil || len(resp.Msg.GetEntries()) != 1 {
		t.Fatal("list over connect", err)
	}
	if methodName(trustv1.Method_METHOD_ETSI) != "etsi" || methodProto("x") != trustv1.Method_METHOD_UNSPECIFIED || outcomeProto("x") != trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE {
		t.Fatal("enum helpers")
	}
}
