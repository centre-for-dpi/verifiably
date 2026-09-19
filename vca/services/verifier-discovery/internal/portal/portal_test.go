// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/catalog"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
	tmpl "github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// newPortal wires the portal over a service with one issuer.
func newPortal(t *testing.T) (*portal.Portal, *service.Service) {
	t.Helper()
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	issuer := catalog.Issuer{
		CredentialIssuer: "https://a.example", DID: "did:web:a", DisplayName: "Alpha",
		Trust: catalog.TrustTrusted, CrawledAt: time.Unix(1700000000, 0).UTC(),
		Types: []catalog.CredentialType{{
			Type: "https://a.example/pid", ConfigurationID: "pid", Format: "dc+sd-jwt",
			Display:    []catalog.Display{{Name: "Person ID"}},
			JSONSchema: `{"type":"object","properties":{"given_name":{"type":"string"}}}`,
			Fields: []catalog.Field{
				{Path: "given_name", Type: "string", Title: "Given name", Mandatory: true, SelectivelyDisclosable: true},
				{Path: "birth_date", Type: "string"},
			},
		}},
	}
	if serr := st.PutIssuer(context.Background(), issuer); serr != nil {
		t.Fatal(serr)
	}
	svc, err := service.New(service.Options{Store: st, PageSizeMax: 50})
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(portal.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	return p, svc
}

// serve returns a test server over the portal.
func serve(t *testing.T, p *portal.Portal) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	p.Register(mux)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// page fetches one path and returns the body.
func page(t *testing.T, s *httptest.Server, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

// post sends one form and returns the status and the location.
func post(t *testing.T, s *httptest.Server, path string, form url.Values) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	return resp.StatusCode, resp.Header.Get("Location")
}

func TestNewRejectsMissingClient(t *testing.T) {
	if _, err := portal.New(portal.Options{}); err == nil {
		t.Error("the portal needs a client")
	}
	p, err := portal.New(portal.Options{Client: &service.Service{}, Prefix: "verifier/"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Prefix() != "/verifier" {
		t.Errorf("prefix = %q", p.Prefix())
	}
}

func TestIssuerPage(t *testing.T) {
	p, _ := newPortal(t)
	s := serve(t, p)
	status, body := page(t, s, "/portal/?notice=crawled")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "Alpha") || !strings.Contains(body, "Trusted") {
		t.Errorf("the page lists the issuer, got %s", body)
	}
	if !strings.Contains(body, "The crawl finished") {
		t.Error("the notice shows a toast")
	}
}

func TestTypePage(t *testing.T) {
	p, _ := newPortal(t)
	s := serve(t, p)
	status, body := page(t, s, "/portal/types?q=person&format=dc%2Bsd-jwt&credential_issuer=https%3A%2F%2Fa.example")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "Person ID") {
		t.Errorf("the page lists the type, got %s", body)
	}
}

func TestFieldsPage(t *testing.T) {
	p, _ := newPortal(t)
	s := serve(t, p)
	status, body := page(t, s, "/portal/fields?credential_issuer=https%3A%2F%2Fa.example&type=https%3A%2F%2Fa.example%2Fpid")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "Given name") || !strings.Contains(body, "birth_date") {
		t.Errorf("the page lists the claims, got %s", body)
	}
	if !strings.Contains(body, "Save template") {
		t.Error("the page carries the save action")
	}
	status, _ = page(t, s, "/portal/fields?credential_issuer=https%3A%2F%2Fmissing.example&type=x")
	if status != http.StatusNotFound {
		t.Errorf("a missing type answers %d", status)
	}
}

func TestSaveAndReadTemplate(t *testing.T) {
	p, _ := newPortal(t)
	s := serve(t, p)
	status, location := post(t, s, "/portal/templates", url.Values{
		"display_name":      {"Age check"},
		"purpose":           {"Prove you are over 18"},
		"format":            {"dc+sd-jwt"},
		"credential_issuer": {"https://a.example"},
		"type":              {"https://a.example/pid"},
		"claim":             {"birth_date"},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(location, "/portal/templates/age-check") {
		t.Fatalf("location = %q", location)
	}
	listStatus, listBody := page(t, s, "/portal/templates")
	if listStatus != http.StatusOK {
		t.Fatalf("status = %d", listStatus)
	}
	a11ytest.AssertPage(t, listBody)
	if !strings.Contains(listBody, "Age check") {
		t.Errorf("the list shows the template, got %s", listBody)
	}
	detailStatus, detailBody := page(t, s, "/portal/templates/age-check?notice=saved&version=1")
	if detailStatus != http.StatusOK {
		t.Fatalf("status = %d", detailStatus)
	}
	a11ytest.AssertPage(t, detailBody)
	if !strings.Contains(detailBody, "DCQL query") || !strings.Contains(detailBody, "Presentation Exchange 2.0") {
		t.Errorf("the page shows both query languages, got %s", detailBody)
	}
	if !strings.Contains(detailBody, "birth_date") {
		t.Error("the page lists the claims of the request")
	}
	deleteStatus, deleteLocation := post(t, s, "/portal/templates/age-check/delete", nil)
	if deleteStatus != http.StatusSeeOther || !strings.Contains(deleteLocation, "notice=deleted") {
		t.Errorf("delete = %d, %q", deleteStatus, deleteLocation)
	}
	missing, _ := page(t, s, "/portal/templates/age-check")
	if missing != http.StatusNotFound {
		t.Errorf("a removed template answers %d", missing)
	}
}

func TestSaveTemplateRejects(t *testing.T) {
	p, _ := newPortal(t)
	s := serve(t, p)
	status, _ := post(t, s, "/portal/templates", url.Values{"type": {"A"}})
	if status != http.StatusBadRequest {
		t.Errorf("a template without a name answers %d", status)
	}
	deleteStatus, _ := post(t, s, "/portal/templates/missing/delete", nil)
	if deleteStatus != http.StatusNotFound {
		t.Errorf("a missing template answers %d", deleteStatus)
	}
}

func TestCrawlAction(t *testing.T) {
	p, _ := newPortal(t)
	s := serve(t, p)
	status, _ := post(t, s, "/portal/crawl", nil)
	if status != http.StatusBadRequest {
		t.Errorf("a crawl without a trust registry answers %d", status)
	}
}

func TestParseFormatAndTrustText(t *testing.T) {
	if portal.ParseFormat(" dc+sd-jwt ") != commonv1.Format_FORMAT_DC_SD_JWT {
		t.Error("the parser reads a known format")
	}
	if portal.ParseFormat("bogus") != commonv1.Format_FORMAT_UNSPECIFIED {
		t.Error("an unknown format is unspecified")
	}
	cases := map[trustv1.TrustLookupResponse_Outcome]string{
		trustv1.TrustLookupResponse_OUTCOME_TRUSTED:     "Trusted",
		trustv1.TrustLookupResponse_OUTCOME_UNTRUSTED:   "Not trusted",
		trustv1.TrustLookupResponse_OUTCOME_UNAVAILABLE: "Registry unavailable",
		trustv1.TrustLookupResponse_OUTCOME_UNKNOWN:     "Unknown",
	}
	for outcome, want := range cases {
		if got := portal.TrustText(outcome); got != want {
			t.Errorf("TrustText(%v) = %q, want %q", outcome, got, want)
		}
	}
}

func TestIssuerPageShowsCrawlError(t *testing.T) {
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	record := catalog.Issuer{CredentialIssuer: "https://b.example", LastError: "the host is down", Trust: catalog.TrustUnavailable}
	if serr := st.PutIssuer(context.Background(), record); serr != nil {
		t.Fatal(serr)
	}
	svc, err := service.New(service.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(portal.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, p)
	status, body := page(t, s, "/portal/")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "the host is down") || !strings.Contains(body, "Registry unavailable") {
		t.Errorf("the page names the crawl error, got %s", body)
	}
}

func TestTemplateDetailWithBrokenQuery(t *testing.T) {
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	created, err := svc.CreateTemplate(context.Background(), connect.NewRequest(&discoveryv1.CreateTemplateRequest{
		Template: &discoveryv1.PresentationTemplate{
			DisplayName: "Plain", Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
				Type: "A", Format: commonv1.Format_FORMAT_LDP_VC,
			}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(portal.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, p)
	status, body := page(t, s, "/portal/templates/"+created.Msg.GetTemplate().GetId())
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "asks for every claim") {
		t.Errorf("a request without claims says so, got %s", body)
	}
}

func TestIssuerAndTypeFallbacks(t *testing.T) {
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	record := catalog.Issuer{
		CredentialIssuer: "https://c.example", Trust: catalog.TrustUntrusted,
		Types: []catalog.CredentialType{{Type: "BareType", Format: "ldp_vc"}},
	}
	if serr := st.PutIssuer(context.Background(), record); serr != nil {
		t.Fatal(serr)
	}
	svc, err := service.New(service.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(portal.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, p)
	status, body := page(t, s, "/portal/")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "Never") || !strings.Contains(body, "Not trusted") {
		t.Errorf("an issuer without a crawl shows Never, got %s", body)
	}
	if !strings.Contains(body, "https://c.example") {
		t.Error("the URL stands in for a missing name")
	}
	typeStatus, typeBody := page(t, s, "/portal/types")
	if typeStatus != http.StatusOK {
		t.Fatalf("status = %d", typeStatus)
	}
	a11ytest.AssertPage(t, typeBody)
	if !strings.Contains(typeBody, "BareType") {
		t.Errorf("the type name stands in for a missing display name, got %s", typeBody)
	}
}

func TestTemplateDetailWithUnreadableQuery(t *testing.T) {
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	record := tmpl.Template{ID: "broken", Version: 1, DisplayName: "Broken", DCQL: "not json"}
	if serr := st.PutTemplate(context.Background(), record); serr != nil {
		t.Fatal(serr)
	}
	svc, err := service.New(service.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(portal.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, p)
	status, body := page(t, s, "/portal/templates/broken")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "cannot generate the older query language") {
		t.Errorf("the page says the generator failed, got %s", body)
	}
}

func TestFieldsPageWithoutSchema(t *testing.T) {
	st, err := store.New(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	record := catalog.Issuer{
		CredentialIssuer: "https://d.example",
		Types:            []catalog.CredentialType{{Type: "Plain", Format: "ldp_vc"}},
	}
	if serr := st.PutIssuer(context.Background(), record); serr != nil {
		t.Fatal(serr)
	}
	svc, err := service.New(service.Options{Store: st})
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(portal.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	s := serve(t, p)
	status, body := page(t, s, "/portal/fields?credential_issuer=https%3A%2F%2Fd.example&type=Plain&format=ldp_vc")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "Save template") {
		t.Error("a type without a schema still offers the save action")
	}
}
