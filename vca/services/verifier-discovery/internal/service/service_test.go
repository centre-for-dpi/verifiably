// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/crawl"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/fetch"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
)

// clock is the fixed time of the tests.
var clock = time.Unix(1700000000, 0).UTC()

// newStore returns a store with two issuers.
func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	issuers := []catalog.Issuer{
		{
			CredentialIssuer: "https://a.example", DID: "did:web:a", DisplayName: "Alpha",
			Trust: catalog.TrustTrusted, CrawledAt: clock,
			Types: []catalog.CredentialType{
				{Type: "https://a.example/pid", ConfigurationID: "pid", Format: "dc+sd-jwt",
					Display:    []catalog.Display{{Name: "Person ID", Description: "identity"}},
					JSONSchema: `{"type":"object"}`,
					Fields:     []catalog.Field{{Path: "given_name", Type: "string", Mandatory: true}}},
				{Type: "DegreeCredential", ConfigurationID: "degree", Format: "jwt_vc_json"},
			},
		},
		{CredentialIssuer: "https://b.example", DisplayName: "Beta", Trust: catalog.TrustUnknown,
			Types: []catalog.CredentialType{{Type: "LicenceCredential", Format: "ldp_vc"}}},
	}
	for _, issuer := range issuers {
		if err := st.PutIssuer(ctx, issuer); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// newService wires a service over the store.
func newService(t *testing.T, crawler *crawl.Crawler, pageSize int) *service.Service {
	t.Helper()
	svc, err := service.New(service.Options{
		Store: newStore(t), Crawler: crawler, PageSizeMax: pageSize,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestNewNeedsStore(t *testing.T) {
	if _, err := service.New(service.Options{}); err == nil {
		t.Error("a service needs a store")
	}
}

func TestReadyAndDefaults(t *testing.T) {
	svc := newService(t, nil, 0)
	if !svc.Ready() {
		t.Error("a service with a store is ready")
	}
}

func TestListIssuers(t *testing.T) {
	svc := newService(t, nil, 1)
	resp, err := svc.ListIssuers(context.Background(), connect.NewRequest(&discoveryv1.ListIssuersRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.GetIssuers()) != 1 || resp.Msg.GetIssuers()[0].GetDisplayName() != "Alpha" {
		t.Fatalf("issuers = %+v", resp.Msg.GetIssuers())
	}
	if resp.Msg.GetPage().GetNextPageToken() != "1" || resp.Msg.GetPage().GetTotalSize() != 2 {
		t.Errorf("page = %+v", resp.Msg.GetPage())
	}
	second, err := svc.ListIssuers(context.Background(), connect.NewRequest(&discoveryv1.ListIssuersRequest{
		Page: &commonv1.Pagination{PageToken: "1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.GetIssuers()) != 1 || second.Msg.GetIssuers()[0].GetDisplayName() != "Beta" {
		t.Errorf("second page = %+v", second.Msg.GetIssuers())
	}
	if second.Msg.GetPage().GetNextPageToken() != "" {
		t.Error("the last page has no token")
	}
	if _, err := svc.ListIssuers(context.Background(), connect.NewRequest(&discoveryv1.ListIssuersRequest{
		Page: &commonv1.Pagination{PageToken: "nonsense"},
	})); err == nil {
		t.Error("a bad token wants an error")
	}
	past, err := svc.ListIssuers(context.Background(), connect.NewRequest(&discoveryv1.ListIssuersRequest{
		Page: &commonv1.Pagination{PageToken: "99"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(past.Msg.GetIssuers()) != 0 {
		t.Error("a token past the end gives an empty page")
	}
}

func TestListCredentialTypes(t *testing.T) {
	svc := newService(t, nil, 50)
	all, err := svc.ListCredentialTypes(context.Background(), connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Msg.GetTypes()) != 3 {
		t.Fatalf("types = %+v", all.Msg.GetTypes())
	}
	byIssuer, err := svc.ListCredentialTypes(context.Background(), connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{
		CredentialIssuer: "https://a.example/",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(byIssuer.Msg.GetTypes()) != 2 {
		t.Errorf("the issuer filter keeps two types, got %+v", byIssuer.Msg.GetTypes())
	}
	byFormat, err := svc.ListCredentialTypes(context.Background(), connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{
		Format: commonv1.Format_FORMAT_LDP_VC,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(byFormat.Msg.GetTypes()) != 1 {
		t.Errorf("format filter = %+v", byFormat.Msg.GetTypes())
	}
	byQuery, err := svc.ListCredentialTypes(context.Background(), connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{
		Query: "person",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(byQuery.Msg.GetTypes()) != 1 {
		t.Errorf("the search matches the display name, got %+v", byQuery.Msg.GetTypes())
	}
	byType, err := svc.ListCredentialTypes(context.Background(), connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{
		Query: "degree",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(byType.Msg.GetTypes()) != 1 {
		t.Errorf("the search matches the type name, got %+v", byType.Msg.GetTypes())
	}
	if _, err := svc.ListCredentialTypes(context.Background(), connect.NewRequest(&discoveryv1.ListCredentialTypesRequest{
		Query: strings.Repeat("a", service.MaxQueryLength+1),
	})); err == nil {
		t.Error("a long query wants an error")
	}
}

func TestMatches(t *testing.T) {
	item := catalog.CredentialType{Type: "A", Format: "ldp_vc", Display: []catalog.Display{{Description: "about identity"}}}
	if !service.Matches(item, "", "identity") {
		t.Error("the search matches the description")
	}
	if service.Matches(item, "", "nothing") {
		t.Error("a query that matches nothing is false")
	}
	if service.Matches(item, "dc+sd-jwt", "") {
		t.Error("a different format is false")
	}
}

func TestGetFields(t *testing.T) {
	svc := newService(t, nil, 50)
	resp, err := svc.GetFields(context.Background(), connect.NewRequest(&discoveryv1.GetFieldsRequest{
		CredentialIssuer: "https://a.example", Type: "https://a.example/pid",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.GetFields()) != 1 || resp.Msg.GetJsonSchema() == "" {
		t.Errorf("fields = %+v", resp.Msg)
	}
	if _, err := svc.GetFields(context.Background(), connect.NewRequest(&discoveryv1.GetFieldsRequest{
		CredentialIssuer: "https://missing.example", Type: "x",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a missing issuer wants not found, got %v", err)
	}
	if _, err := svc.GetFields(context.Background(), connect.NewRequest(&discoveryv1.GetFieldsRequest{
		CredentialIssuer: "https://a.example", Type: "missing",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a missing type wants not found, got %v", err)
	}
}

// templateRequest returns one create request.
func templateRequest(name string) *discoveryv1.CreateTemplateRequest {
	return &discoveryv1.CreateTemplateRequest{Template: &discoveryv1.PresentationTemplate{
		DisplayName: name, Purpose: "Prove your age",
		Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
			Type: "https://a.example/pid", Format: commonv1.Format_FORMAT_DC_SD_JWT, Claims: []string{"birth_date"},
		}},
	}}
}

func TestTemplateLifecycle(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, nil, 50)
	created, err := svc.CreateTemplate(ctx, connect.NewRequest(templateRequest("Age check")))
	if err != nil {
		t.Fatal(err)
	}
	stored := created.Msg.GetTemplate()
	if stored.GetId() != "age-check" || stored.GetVersion() != 1 {
		t.Fatalf("template = %+v", stored)
	}
	if stored.GetDcql() == "" || stored.GetCreatedAt() == nil {
		t.Errorf("template = %+v", stored)
	}
	if _, err := svc.CreateTemplate(ctx, connect.NewRequest(templateRequest("Age check"))); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Errorf("a second create wants already exists, got %v", err)
	}
	next := templateRequest("Age check")
	next.Template.Id = "age-check"
	versioned, err := svc.VersionTemplate(ctx, connect.NewRequest(&discoveryv1.VersionTemplateRequest{Template: next.Template}))
	if err != nil {
		t.Fatal(err)
	}
	if versioned.Msg.GetTemplate().GetVersion() != 2 {
		t.Errorf("version = %d", versioned.Msg.GetTemplate().GetVersion())
	}
	versions, err := svc.Versions(ctx, "age-check")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Errorf("versions = %v", versions)
	}
	got, err := svc.GetTemplate(ctx, connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: "age-check"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetTemplate().GetVersion() != 2 {
		t.Errorf("the latest version answers, got %+v", got.Msg.GetTemplate())
	}
	list, err := svc.ListTemplates(ctx, connect.NewRequest(&discoveryv1.ListTemplatesRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetTemplates()) != 1 {
		t.Errorf("the list holds the latest version only, got %+v", list.Msg.GetTemplates())
	}
	removed, err := svc.DeleteTemplate(ctx, connect.NewRequest(&discoveryv1.DeleteTemplateRequest{Id: "age-check"}))
	if err != nil {
		t.Fatal(err)
	}
	if removed.Msg.GetVersionsRemoved() != 2 {
		t.Errorf("removed = %d", removed.Msg.GetVersionsRemoved())
	}
	if _, err := svc.DeleteTemplate(ctx, connect.NewRequest(&discoveryv1.DeleteTemplateRequest{Id: "age-check"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a second delete wants not found, got %v", err)
	}
	if _, err := svc.GetTemplate(ctx, connect.NewRequest(&discoveryv1.GetTemplateRequest{Id: "age-check"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a removed template wants not found, got %v", err)
	}
}

func TestTemplateTenantFilter(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, nil, 50)
	first := templateRequest("Alpha check")
	first.Template.TenantId = "t1"
	if _, err := svc.CreateTemplate(ctx, connect.NewRequest(first)); err != nil {
		t.Fatal(err)
	}
	second := templateRequest("Beta check")
	second.Template.TenantId = "t2"
	if _, err := svc.CreateTemplate(ctx, connect.NewRequest(second)); err != nil {
		t.Fatal(err)
	}
	list, err := svc.ListTemplates(ctx, connect.NewRequest(&discoveryv1.ListTemplatesRequest{TenantId: "t2"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetTemplates()) != 1 || list.Msg.GetTemplates()[0].GetTenantId() != "t2" {
		t.Errorf("tenant filter = %+v", list.Msg.GetTemplates())
	}
	if _, err := svc.ListTemplates(ctx, connect.NewRequest(&discoveryv1.ListTemplatesRequest{
		Page: &commonv1.Pagination{PageToken: "x"},
	})); err == nil {
		t.Error("a bad token wants an error")
	}
}

func TestTemplateRejects(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, nil, 50)
	bad := templateRequest("!!!")
	if _, err := svc.CreateTemplate(ctx, connect.NewRequest(bad)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a name with no letters wants invalid argument, got %v", err)
	}
	empty := &discoveryv1.CreateTemplateRequest{Template: &discoveryv1.PresentationTemplate{Id: "x", DisplayName: "X"}}
	if _, err := svc.CreateTemplate(ctx, connect.NewRequest(empty)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a template without a query wants invalid argument, got %v", err)
	}
	if _, err := svc.VersionTemplate(ctx, connect.NewRequest(&discoveryv1.VersionTemplateRequest{
		Template: &discoveryv1.PresentationTemplate{Id: "a/b"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Error("a bad id wants invalid argument")
	}
	if _, err := svc.VersionTemplate(ctx, connect.NewRequest(&discoveryv1.VersionTemplateRequest{
		Template: &discoveryv1.PresentationTemplate{Id: "missing", DisplayName: "X"},
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Error("a missing template wants not found")
	}
}

func TestCatalogue(t *testing.T) {
	svc := newService(t, nil, 50)
	list, err := svc.Catalogue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Errorf("catalogue = %+v", list)
	}
}

// fakeTrust answers an empty trust list.
type fakeTrust struct {
	trustv1connect.UnimplementedTrustServiceHandler
	err error
}

func (f fakeTrust) ListEntries(context.Context, *connect.Request[trustv1.ListEntriesRequest]) (*connect.Response[trustv1.ListEntriesResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&trustv1.ListEntriesResponse{}), nil
}

// noFetch answers no document.
type noFetch struct{}

func (noFetch) Get(context.Context, string) (fetch.Doc, error) {
	return fetch.Doc{}, errors.New("no network")
}
func (noFetch) Forget(string) {}

func TestCrawlRPC(t *testing.T) {
	ctx := context.Background()
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	off, err := crawl.New(crawl.Options{Fetch: noFetch{}, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st, Crawler: off})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Crawl(ctx, connect.NewRequest(&discoveryv1.CrawlRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a crawl without a trust registry wants failed precondition, got %v", err)
	}
	on, err := crawl.New(crawl.Options{Trust: fakeTrust{}, Fetch: noFetch{}, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	svc, err = service.New(service.Options{Store: st, Crawler: on})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Crawl(ctx, connect.NewRequest(&discoveryv1.CrawlRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetCrawled() != 0 || resp.Msg.GetCrawledAt() == nil {
		t.Errorf("response = %+v", resp.Msg)
	}
	broken, err := crawl.New(crawl.Options{Trust: fakeTrust{err: errors.New("down")}, Fetch: noFetch{}, Store: st})
	if err != nil {
		t.Fatal(err)
	}
	svc, err = service.New(service.Options{Store: st, Crawler: broken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Crawl(ctx, connect.NewRequest(&discoveryv1.CrawlRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a trust list error wants unavailable, got %v", err)
	}
	// A service with no crawler at all refuses too.
	svc, err = service.New(service.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Crawl(ctx, connect.NewRequest(&discoveryv1.CrawlRequest{})); err == nil {
		t.Error("a service without a crawler refuses the RPC")
	}
}
