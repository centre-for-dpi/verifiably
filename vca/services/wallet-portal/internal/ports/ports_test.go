// SPDX-License-Identifier: Apache-2.0

package ports_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
)

// fakeDiscovery answers the two catalogue RPCs in pages.
type fakeDiscovery struct {
	discoveryv1connect.DiscoveryServiceClient
	issuerPages [][]*discoveryv1.Issuer
	typePages   [][]*discoveryv1.CredentialType
	issuerErr   error
	typeErr     error
	calls       int
}

func (f *fakeDiscovery) ListIssuers(_ context.Context, req *connect.Request[discoveryv1.ListIssuersRequest],
) (*connect.Response[discoveryv1.ListIssuersResponse], error) {
	if f.issuerErr != nil {
		return nil, f.issuerErr
	}
	page := index(req.Msg.GetPage().GetPageToken())
	resp := &discoveryv1.ListIssuersResponse{Issuers: f.issuerPages[page], Page: &commonv1.PageResult{}}
	if page+1 < len(f.issuerPages) {
		resp.Page.NextPageToken = "p1"
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeDiscovery) ListCredentialTypes(_ context.Context,
	req *connect.Request[discoveryv1.ListCredentialTypesRequest],
) (*connect.Response[discoveryv1.ListCredentialTypesResponse], error) {
	f.calls++
	if f.typeErr != nil {
		return nil, f.typeErr
	}
	page := index(req.Msg.GetPage().GetPageToken())
	resp := &discoveryv1.ListCredentialTypesResponse{Types: f.typePages[page], Page: &commonv1.PageResult{}}
	if page+1 < len(f.typePages) {
		resp.Page.NextPageToken = "p1"
	}
	return connect.NewResponse(resp), nil
}

func index(token string) int {
	if token == "" {
		return 0
	}
	return 1
}

func newFake() *fakeDiscovery {
	return &fakeDiscovery{
		issuerPages: [][]*discoveryv1.Issuer{
			{{CredentialIssuer: "https://a.example", DisplayName: "Agency A",
				Trust: trustv1.TrustLookupResponse_OUTCOME_TRUSTED}},
			{{CredentialIssuer: "https://b.example", DisplayName: "Agency B"}},
		},
		typePages: [][]*discoveryv1.CredentialType{
			{{CredentialIssuer: "https://a.example", Type: "DriverLicence", ConfigurationId: "dl_sd_jwt",
				Format: commonv1.Format_FORMAT_DC_SD_JWT, SchemaId: "dl", SchemaVersion: 2,
				Display: []*schemav1.Display{{Name: "Driver licence"}}}},
			{{CredentialIssuer: "https://b.example", Type: "Passport"}},
		},
	}
}

func TestCatalogueReadsEveryPage(t *testing.T) {
	cat, err := ports.NewCatalogue(newFake(), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := cat.Offerings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("offerings = %d", len(got))
	}
	first := got[0]
	if first.GetIssuerName() != "Agency A" || first.GetTrust() != trustv1.TrustLookupResponse_OUTCOME_TRUSTED {
		t.Fatalf("offering = %+v", first)
	}
	schema := first.GetSchema()
	if schema.GetId() != "dl" || schema.GetVersion() != 2 || schema.GetType() != "DriverLicence" {
		t.Fatalf("schema = %+v", schema)
	}
	if schema.GetConfigurationIds()["FORMAT_DC_SD_JWT"] != "dl_sd_jwt" {
		t.Fatalf("configuration ids = %v", schema.GetConfigurationIds())
	}
	if len(schema.GetFormats()) != 1 {
		t.Fatalf("formats = %v", schema.GetFormats())
	}
	second := got[1].GetSchema()
	if second.GetId() != "Passport" || len(second.GetFormats()) != 0 {
		t.Fatalf("second schema = %+v", second)
	}
}

func TestCatalogueErrors(t *testing.T) {
	if _, err := ports.NewCatalogue(nil, 10); !errors.Is(err, ports.ErrNoCatalogue) {
		t.Fatalf("nil client: %v", err)
	}
	issuerDown := newFake()
	issuerDown.issuerErr = errors.New("down")
	cat, err := ports.NewCatalogue(issuerDown, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := cat.Offerings(context.Background()); serr == nil {
		t.Fatal("want an issuer error")
	}
	typeDown := newFake()
	typeDown.typeErr = errors.New("down")
	cat, err = ports.NewCatalogue(typeDown, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cat.Offerings(context.Background()); err == nil {
		t.Fatal("want a type error")
	}
}

func TestCachedCatalogue(t *testing.T) {
	calls := 0
	clock := time.Unix(1000, 0)
	cat := ports.Cached(ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
		calls++
		return []*walletportalv1.Offering{{CredentialIssuer: "https://a.example"}}, nil
	}), time.Minute, func() time.Time { return clock })
	for i := 0; i < 3; i++ {
		if _, err := cat.Offerings(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err := cat.Offerings(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls after the TTL = %d", calls)
	}
	down := ports.Cached(ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
		return nil, errors.New("down")
	}), time.Minute, nil)
	if _, err := down.Offerings(context.Background()); err == nil {
		t.Fatal("want an error")
	}
}

func TestDisplayOf(t *testing.T) {
	cat := ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
		return []*walletportalv1.Offering{
			{CredentialIssuer: "https://b.example", Schema: &schemav1.PublicSchema{Type: "Passport"}},
			{CredentialIssuer: "https://a.example", Schema: &schemav1.PublicSchema{
				Type: "DriverLicence", Display: []*schemav1.Display{{Name: "Driver licence"}}}},
		}, nil
	})
	display := ports.DisplayOf(cat)
	got := display(context.Background(), "https://a.example", "driverlicence")
	if got.GetName() != "Driver licence" {
		t.Fatalf("display = %+v", got)
	}
	if display(context.Background(), "https://other.example", "DriverLicence") != nil {
		t.Fatal("want no display for another issuer")
	}
	if display(context.Background(), "", "Passport") != nil {
		t.Fatal("want no display when the catalogue has none")
	}
	if ports.DisplayOf(nil) != nil {
		t.Fatal("want no lookup without a catalogue")
	}
	down := ports.DisplayOf(ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) {
		return nil, errors.New("down")
	}))
	if down(context.Background(), "a", "b") != nil {
		t.Fatal("want no display after an error")
	}
}

func TestEligibility(t *testing.T) {
	yes := ports.StaticEligibility(true)
	if ok, err := yes(context.Background(), "ref", nil); err != nil || !ok {
		t.Fatalf("static = %v %v", ok, err)
	}
	if _, err := ports.HTTPEligibility("", nil); err == nil {
		t.Fatal("want a URL error")
	}
	if _, err := ports.HTTPEligibility("https://hook.example", nil); err == nil {
		t.Fatal("want a poster error")
	}
	var seen string
	hook, err := ports.HTTPEligibility("https://hook.example",
		func(_ context.Context, url string, body []byte) ([]byte, error) {
			if url != "https://hook.example" {
				t.Fatalf("url = %q", url)
			}
			seen = string(body)
			return []byte(`{"eligible":true}`), nil
		})
	if err != nil {
		t.Fatal(err)
	}
	offering := &walletportalv1.Offering{
		CredentialIssuer: "https://a.example",
		Schema:           &schemav1.PublicSchema{Id: "dl", Type: "DriverLicence"},
	}
	ok, err := hook(context.Background(), "ref-1", offering)
	if err != nil || !ok {
		t.Fatalf("hook = %v %v", ok, err)
	}
	for _, want := range []string{`"subject_ref":"ref-1"`, `"schema_id":"dl"`, `"type":"DriverLicence"`} {
		if !strings.Contains(seen, want) {
			t.Fatalf("body %s misses %s", seen, want)
		}
	}
	if strings.Contains(seen, "idp") {
		t.Fatal("the hook must not see the subject")
	}
	down, err := ports.HTTPEligibility("https://hook.example",
		func(context.Context, string, []byte) ([]byte, error) { return nil, errors.New("down") })
	if err != nil {
		t.Fatal(err)
	}
	if _, serr := down(context.Background(), "ref", offering); serr == nil {
		t.Fatal("want a hook error")
	}
	broken, err := ports.HTTPEligibility("https://hook.example",
		func(context.Context, string, []byte) ([]byte, error) { return []byte("{"), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken(context.Background(), "ref", offering); err == nil {
		t.Fatal("want a parse error")
	}
}

func TestSubjectRef(t *testing.T) {
	first := ports.SubjectRef("salt", "https://idp|abc")
	if first == "" || strings.Contains(first, "idp") {
		t.Fatalf("ref = %q", first)
	}
	if first != ports.SubjectRef("salt", "https://idp|abc") {
		t.Fatal("want a stable reference")
	}
	if first == ports.SubjectRef("other", "https://idp|abc") {
		t.Fatal("want another reference for another salt")
	}
}

// fakeTrust answers the trust lookup.
type fakeTrust struct {
	trustv1connect.TrustServiceClient
	seen *trustv1.TrustLookupRequest
	err  error
}

func (f *fakeTrust) TrustLookup(_ context.Context, req *connect.Request[trustv1.TrustLookupRequest],
) (*connect.Response[trustv1.TrustLookupResponse], error) {
	f.seen = req.Msg
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&trustv1.TrustLookupResponse{
		Outcome: trustv1.TrustLookupResponse_OUTCOME_TRUSTED,
		Entry:   &trustv1.TrustEntry{DisplayName: "Agency A"},
	}), nil
}

func TestTrust(t *testing.T) {
	if ports.Trust(nil, commonv1.Role_ROLE_ISSUER) != nil {
		t.Fatal("want no lookup without a client")
	}
	client := &fakeTrust{}
	lookup := ports.Trust(client, commonv1.Role_ROLE_ISSUER)
	got, err := lookup(context.Background(), "did:web:a.example", "DriverLicence")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Agency A" || got.Outcome != trustv1.TrustLookupResponse_OUTCOME_TRUSTED {
		t.Fatalf("trust = %+v", got)
	}
	if client.seen.GetIdentifier().GetDid() != "did:web:a.example" {
		t.Fatalf("identifier = %+v", client.seen.GetIdentifier())
	}
	if _, err := lookup(context.Background(), "https://a.example", ""); err != nil {
		t.Fatal(err)
	}
	if client.seen.GetIdentifier().GetX509Subject() != "https://a.example" {
		t.Fatalf("identifier = %+v", client.seen.GetIdentifier())
	}
	down := ports.Trust(&fakeTrust{err: errors.New("down")}, commonv1.Role_ROLE_VERIFIER)
	if _, err := down(context.Background(), "did:web:a", ""); err == nil {
		t.Fatal("want an error")
	}
}

func TestHTTPFetcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			mustWrite(t, w, []byte("document"))
		case "/big":
			mustWrite(t, w, []byte(strings.Repeat("a", 100)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	fetch := ports.HTTPFetcher(nil, 16)
	got, err := fetch(context.Background(), srv.URL+"/ok")
	if err != nil || string(got) != "document" {
		t.Fatalf("fetch = %q %v", got, err)
	}
	if _, err := fetch(context.Background(), srv.URL+"/big"); !errors.Is(err, ports.ErrTooLarge) {
		t.Fatalf("big: %v", err)
	}
	if _, err := fetch(context.Background(), srv.URL+"/missing"); err == nil {
		t.Fatal("want a status error")
	}
	if _, err := fetch(context.Background(), "file:///etc/passwd"); err == nil {
		t.Fatal("want a scheme error")
	}
	if _, err := fetch(context.Background(), "http://127.0.0.1:0/nope"); err == nil {
		t.Fatal("want a transport error")
	}
	if _, err := fetch(context.Background(), "http://%zz/"); err == nil {
		t.Fatal("want a request error")
	}
}

func TestHTTPPosterAndFormPoster(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil && r.PostForm.Get("vp_token") != "" {
			bodies = append(bodies, r.PostForm.Get("vp_token"))
			mustWrite(t, w, []byte(`{"redirect_uri":"https://done.example"}`))
			return
		}
		if r.URL.Path == "/bad" {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		mustWrite(t, w, []byte(`{"eligible":true}`))
	}))
	defer srv.Close()
	post := ports.HTTPPoster(nil, 0)
	got, err := post(context.Background(), srv.URL+"/hook", []byte(`{"a":1}`))
	if err != nil || !strings.Contains(string(got), "eligible") {
		t.Fatalf("post = %q %v", got, err)
	}
	if _, serr := post(context.Background(), srv.URL+"/bad", nil); serr == nil {
		t.Fatal("want a status error")
	}
	if _, serr := post(context.Background(), "http://%zz/", nil); serr == nil {
		t.Fatal("want a request error")
	}
	if _, serr := post(context.Background(), "http://127.0.0.1:0/", nil); serr == nil {
		t.Fatal("want a transport error")
	}
	form := ports.FormPoster(nil, 1<<10)
	answer, err := form(context.Background(), srv.URL+"/direct_post", url.Values{"vp_token": {"token"}})
	if err != nil || !strings.Contains(string(answer), "done.example") {
		t.Fatalf("form = %q %v", answer, err)
	}
	if len(bodies) != 1 || bodies[0] != "token" {
		t.Fatalf("bodies = %v", bodies)
	}
	if _, err := form(context.Background(), srv.URL+"/bad", nil); err == nil {
		t.Fatal("want a status error")
	}
	if _, err := form(context.Background(), "http://%zz/", nil); err == nil {
		t.Fatal("want a request error")
	}
	if _, err := form(context.Background(), "http://127.0.0.1:0/", nil); err == nil {
		t.Fatal("want a transport error")
	}
}

func TestCache(t *testing.T) {
	clock := time.Unix(1000, 0)
	c := ports.NewCache(time.Minute, 1, func() time.Time { return clock })
	calls := 0
	fetch := c.Wrap(func(_ context.Context, url string) ([]byte, error) {
		calls++
		if url == "bad" {
			return nil, errors.New("down")
		}
		return []byte(url), nil
	})
	for i := 0; i < 2; i++ {
		if _, err := fetch(context.Background(), "one"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	if _, err := fetch(context.Background(), "two"); err != nil {
		t.Fatal(err)
	}
	if _, err := fetch(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("calls after the eviction = %d", calls)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err := fetch(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("calls after the TTL = %d", calls)
	}
	if _, err := fetch(context.Background(), "bad"); err == nil {
		t.Fatal("want an error")
	}
	if ports.NewCache(time.Minute, 0, nil) == nil {
		t.Fatal("want a cache")
	}
}
