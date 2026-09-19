// SPDX-License-Identifier: Apache-2.0

package crawl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/crawl"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
)

// fakeTrust answers the two RPCs the crawler calls.
type fakeTrust struct {
	trustv1connect.UnimplementedTrustServiceHandler
	pages    [][]*trustv1.TrustEntry
	tokens   []string
	listErr  error
	lookup   trustv1.TrustLookupResponse_Outcome
	lookupNo bool
	calls    int
}

func (f *fakeTrust) ListEntries(_ context.Context, req *connect.Request[trustv1.ListEntriesRequest]) (*connect.Response[trustv1.ListEntriesResponse], error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	index := 0
	if token := req.Msg.GetPage().GetPageToken(); token != "" {
		for i, t := range f.tokens {
			if t == token {
				index = i + 1
			}
		}
	}
	f.calls++
	next := ""
	if index < len(f.tokens) {
		next = f.tokens[index]
	}
	return connect.NewResponse(&trustv1.ListEntriesResponse{
		Entries: f.pages[index],
		Page:    &commonv1.PageResult{NextPageToken: next},
	}), nil
}

func (f *fakeTrust) TrustLookup(context.Context, *connect.Request[trustv1.TrustLookupRequest]) (*connect.Response[trustv1.TrustLookupResponse], error) {
	if f.lookupNo {
		return nil, errors.New("the registry is down")
	}
	return connect.NewResponse(&trustv1.TrustLookupResponse{Outcome: f.lookup}), nil
}

// entry builds one trust entry.
func entry(did, endpoint, name string) *trustv1.TrustEntry {
	return &trustv1.TrustEntry{
		Identifier:      &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: did}},
		DisplayName:     name,
		ServiceEndpoint: endpoint,
	}
}

// fakeFetch answers from a map of URL to body.
type fakeFetch struct {
	docs    map[string]string
	errs    map[string]error
	forgot  []string
	fetched []string
}

func (f *fakeFetch) Get(_ context.Context, url string) (fetchguard.Doc, error) {
	f.fetched = append(f.fetched, url)
	if err, ok := f.errs[url]; ok {
		return fetchguard.Doc{}, err
	}
	body, ok := f.docs[url]
	if !ok {
		return fetchguard.Doc{}, errors.New("not found")
	}
	return fetchguard.Doc{URL: url, Body: []byte(body)}, nil
}

func (f *fakeFetch) Forget(url string) { f.forgot = append(f.forgot, url) }

const metadata = `{"credential_issuer":"https://issuer.example",
  "credential_configurations_supported":{"pid":{"format":"dc+sd-jwt","vct":"https://issuer.example/pid"}}}`

const schemas = `{"schemas":[{"id":"pid","version":1,"vct":"https://issuer.example/pid",
  "json_schema":{"type":"object","properties":{"given_name":{"type":"string"}}}}]}`

// setup wires a crawler over fakes.
func setup(t *testing.T, trust trustv1connect.TrustServiceClient, docs map[string]string, errs map[string]error) (*crawl.Crawler, *store.Store, *fakeFetch) {
	t.Helper()
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeFetch{docs: docs, errs: errs}
	clock := time.Unix(1700000000, 0).UTC()
	c, err := crawl.New(crawl.Options{Trust: trust, Fetch: f, Store: st, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	return c, st, f
}

func TestNewRejectsMissingParts(t *testing.T) {
	if _, err := crawl.New(crawl.Options{}); err == nil {
		t.Error("a crawler needs a fetcher")
	}
	if _, err := crawl.New(crawl.Options{Fetch: &fakeFetch{}}); err == nil {
		t.Error("a crawler needs a store")
	}
}

func TestRunStoresCatalogue(t *testing.T) {
	trust := &fakeTrust{
		pages:  [][]*trustv1.TrustEntry{{entry("did:web:issuer.example", "https://issuer.example/", "Ministry"), entry("did:web:x", "", "No endpoint")}},
		lookup: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}
	docs := map[string]string{
		"https://issuer.example" + catalog.MetadataPath: metadata,
		"https://issuer.example" + catalog.SchemasPath:  schemas,
	}
	c, st, f := setup(t, trust, docs, nil)
	if !c.Enabled() {
		t.Fatal("a crawler with a trust client is enabled")
	}
	res, err := c.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Crawled != 1 || len(res.Failed) != 0 {
		t.Fatalf("result = %+v", res)
	}
	issuer, err := st.GetIssuer(context.Background(), "https://issuer.example")
	if err != nil {
		t.Fatal(err)
	}
	if issuer.DisplayName != "Ministry" || issuer.Trust != catalog.TrustTrusted {
		t.Errorf("issuer = %+v", issuer)
	}
	if len(issuer.Types) != 1 || len(issuer.Types[0].Fields) != 1 {
		t.Errorf("types = %+v", issuer.Types)
	}
	if issuer.CrawledAt.IsZero() {
		t.Error("the crawl stamps the time")
	}
	if len(f.forgot) != 2 {
		t.Errorf("the crawl asks the fetcher to read from the server, got %v", f.forgot)
	}
}

func TestRunPagesTheTrustList(t *testing.T) {
	trust := &fakeTrust{
		pages: [][]*trustv1.TrustEntry{
			{entry("did:web:a", "https://a.example", "A")},
			{entry("did:web:b", "https://b.example", "B")},
		},
		tokens: []string{"page2"},
		lookup: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}
	docs := map[string]string{
		"https://a.example" + catalog.MetadataPath: `{"credential_issuer":"https://a.example"}`,
		"https://a.example" + catalog.SchemasPath:  `{"schemas":[]}`,
		"https://b.example" + catalog.MetadataPath: `{"credential_issuer":"https://b.example"}`,
		"https://b.example" + catalog.SchemasPath:  `{"schemas":[]}`,
	}
	c, st, _ := setup(t, trust, docs, nil)
	res, err := c.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Crawled != 2 {
		t.Errorf("result = %+v", res)
	}
	list, err := st.ListIssuers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Errorf("issuers = %+v", list)
	}
}

func TestRunSelectsIssuers(t *testing.T) {
	trust := &fakeTrust{
		pages:  [][]*trustv1.TrustEntry{{entry("did:web:a", "https://a.example", "A"), entry("did:web:b", "https://b.example", "B")}},
		lookup: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}
	docs := map[string]string{
		"https://a.example" + catalog.MetadataPath: `{"credential_issuer":"https://a.example"}`,
		"https://a.example" + catalog.SchemasPath:  `{"schemas":[]}`,
	}
	c, _, _ := setup(t, trust, docs, nil)
	res, err := c.Run(context.Background(), []string{"https://a.example/"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Crawled != 1 {
		t.Errorf("result = %+v", res)
	}
	if _, err := c.Run(context.Background(), []string{"https://c.example"}); err == nil {
		t.Error("an issuer outside the trust list wants an error")
	}
}

func TestRunKeepsTheLastGoodCatalogue(t *testing.T) {
	trust := &fakeTrust{
		pages:  [][]*trustv1.TrustEntry{{entry("did:web:a", "https://a.example", "A")}},
		lookup: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}
	docs := map[string]string{
		"https://a.example" + catalog.MetadataPath: `{"credential_issuer":"https://a.example",
			"credential_configurations_supported":{"pid":{"format":"ldp_vc","vct":"A"}}}`,
		"https://a.example" + catalog.SchemasPath: `{"schemas":[]}`,
	}
	c, st, f := setup(t, trust, docs, nil)
	if _, err := c.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	// The next crawl fails on the metadata.
	f.errs = map[string]error{"https://a.example" + catalog.MetadataPath: errors.New("the host is down")}
	res, err := c.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Crawled != 0 || len(res.Failed) != 1 {
		t.Fatalf("result = %+v", res)
	}
	issuer, err := st.GetIssuer(context.Background(), "https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(issuer.Types) != 1 {
		t.Errorf("the last good catalogue stays, got %+v", issuer)
	}
	if issuer.LastError == "" {
		t.Error("the record names the error of the last crawl")
	}
}

func TestRunRecordsBrokenMetadata(t *testing.T) {
	trust := &fakeTrust{
		pages:  [][]*trustv1.TrustEntry{{entry("did:web:a", "https://a.example", "A")}},
		lookup: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}
	docs := map[string]string{"https://a.example" + catalog.MetadataPath: "{"}
	c, st, _ := setup(t, trust, docs, nil)
	res, err := c.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 {
		t.Fatalf("result = %+v", res)
	}
	issuer, err := st.GetIssuer(context.Background(), "https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	if issuer.LastError == "" {
		t.Error("the record names the error")
	}
}

func TestRunKeepsTypesWhenSchemasFail(t *testing.T) {
	trust := &fakeTrust{
		pages:  [][]*trustv1.TrustEntry{{entry("did:web:a", "https://a.example", "")}},
		lookup: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}
	docs := map[string]string{
		"https://a.example" + catalog.MetadataPath: `{"display":[{"name":"From metadata"}],
			"credential_configurations_supported":{"pid":{"format":"ldp_vc","vct":"A"}}}`,
	}
	c, st, _ := setup(t, trust, docs, nil)
	res, err := c.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Crawled != 1 {
		t.Fatalf("a missing schema list still stores the types, got %+v", res)
	}
	issuer, err := st.GetIssuer(context.Background(), "https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	if issuer.CredentialIssuer != "https://a.example" || issuer.DisplayName != "From metadata" {
		t.Errorf("issuer = %+v", issuer)
	}
	if issuer.LastError == "" {
		t.Error("the record names the schema error")
	}
}

func TestRunBrokenSchemaList(t *testing.T) {
	trust := &fakeTrust{
		pages:  [][]*trustv1.TrustEntry{{entry("did:web:a", "https://a.example", "A")}},
		lookup: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}
	docs := map[string]string{
		"https://a.example" + catalog.MetadataPath: `{"credential_issuer":"https://a.example"}`,
		"https://a.example" + catalog.SchemasPath:  "not json",
	}
	c, st, _ := setup(t, trust, docs, nil)
	if _, err := c.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	issuer, err := st.GetIssuer(context.Background(), "https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	if issuer.LastError == "" {
		t.Error("the record names the schema error")
	}
}

func TestRunWithoutTrustRegistry(t *testing.T) {
	c, _, _ := setup(t, nil, nil, nil)
	if c.Enabled() {
		t.Error("a crawler without a trust client is off")
	}
	if _, err := c.Run(context.Background(), nil); err == nil {
		t.Error("a crawl without a trust registry wants an error")
	}
}

func TestRunTrustListError(t *testing.T) {
	c, _, _ := setup(t, &fakeTrust{listErr: errors.New("the registry is down")}, nil, nil)
	if _, err := c.Run(context.Background(), nil); err == nil {
		t.Error("a trust list error wants an error")
	}
}

func TestLookupFailureIsUnavailable(t *testing.T) {
	trust := &fakeTrust{
		pages:    [][]*trustv1.TrustEntry{{entry("did:web:a", "https://a.example", "A")}},
		lookupNo: true,
	}
	docs := map[string]string{
		"https://a.example" + catalog.MetadataPath: `{"credential_issuer":"https://a.example"}`,
		"https://a.example" + catalog.SchemasPath:  `{"schemas":[]}`,
	}
	c, st, _ := setup(t, trust, docs, nil)
	if _, err := c.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	issuer, err := st.GetIssuer(context.Background(), "https://a.example")
	if err != nil {
		t.Fatal(err)
	}
	if issuer.Trust != catalog.TrustUnavailable {
		t.Errorf("trust = %q", issuer.Trust)
	}
}

// failStore fails every write.
type failStore struct{}

func (failStore) PutIssuer(context.Context, catalog.Issuer) error { return errors.New("disk is full") }
func (failStore) GetIssuer(context.Context, string) (catalog.Issuer, error) {
	return catalog.Issuer{}, errors.New("disk is full")
}

func TestRunStoreErrors(t *testing.T) {
	trust := &fakeTrust{
		pages:  [][]*trustv1.TrustEntry{{entry("did:web:a", "https://a.example", "A")}},
		lookup: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
	}
	f := &fakeFetch{docs: map[string]string{
		"https://a.example" + catalog.MetadataPath: `{"credential_issuer":"https://a.example"}`,
		"https://a.example" + catalog.SchemasPath:  `{"schemas":[]}`,
	}}
	c, err := crawl.New(crawl.Options{Trust: trust, Fetch: f, Store: failStore{}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 {
		t.Errorf("a store error fails the issuer, got %+v", res)
	}
	// A fetch error then also fails to write the error record.
	f.errs = map[string]error{"https://a.example" + catalog.MetadataPath: errors.New("down")}
	res, err = c.Run(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed) != 1 {
		t.Errorf("result = %+v", res)
	}
}
