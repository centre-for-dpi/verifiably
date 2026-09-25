// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/results"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// Stack names the adapters report. The tests hold no vendor name
// (ADR-001 decision 4).
const (
	firstStack  = "First stack"
	secondStack = "Second stack"
)

// fakeDiscovery answers the saved queries and the catalogue.
type fakeDiscovery struct {
	templates []*discoveryv1.PresentationTemplate
	types     []*discoveryv1.CredentialType
	fields    map[string][]*discoveryv1.Field
	err       error
}

func (f *fakeDiscovery) ListTemplates(context.Context, *connect.Request[discoveryv1.ListTemplatesRequest]) (*connect.Response[discoveryv1.ListTemplatesResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&discoveryv1.ListTemplatesResponse{Templates: f.templates,
		Page: &commonv1.PageResult{TotalSize: int64(len(f.templates))}}), nil
}

func (f *fakeDiscovery) ListCredentialTypes(context.Context, *connect.Request[discoveryv1.ListCredentialTypesRequest]) (*connect.Response[discoveryv1.ListCredentialTypesResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&discoveryv1.ListCredentialTypesResponse{Types: f.types}), nil
}

func (f *fakeDiscovery) GetFields(_ context.Context, req *connect.Request[discoveryv1.GetFieldsRequest]) (*connect.Response[discoveryv1.GetFieldsResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&discoveryv1.GetFieldsResponse{Fields: f.fields[req.Msg.GetType()]}), nil
}

// fakeRequests answers ListTransactions with a fixed list.
type fakeRequests struct {
	open int
	err  error
	seen []ingestv1.GetTransactionResponse_State
}

func (f *fakeRequests) ListTransactions(_ context.Context, req *connect.Request[ingestv1.ListTransactionsRequest]) (*connect.Response[ingestv1.ListTransactionsResponse], error) {
	f.seen = append(f.seen, req.Msg.GetState())
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(&ingestv1.ListTransactionsResponse{Page: &commonv1.PageResult{TotalSize: int64(f.open)}}), nil
}

// verifierPeer returns one verifier pair of the deployment.
func verifierPeer(dpg configv1.Dpg) topology.Peer {
	pair := topology.PairName(commonv1.Role_ROLE_VERIFIER, dpg)
	return topology.Peer{Pair: pair, Role: commonv1.Role_ROLE_VERIFIER, Dpg: dpg, PublicURL: "https://" + pair + ".labs.example",
		Services: map[string]string{"verifier-auth": "http://" + pair + "-auth:8081"}}
}

// shellFixture is a portal in the verifier frame of the first pair, with
// the second pair live and the third pair starting.
type shellFixture struct {
	portal    *Portal
	mux       *http.ServeMux
	store     *results.Store
	discovery *fakeDiscovery
	requests  *fakeRequests
}

// staff is the staff member of every request.
var staff = staffsession.Session{Subject: "kc|otieno", Name: "Akinyi Otieno", ID: "sid-1", CSRF: "csrf-1",
	Roles: []string{"verifier-operator"}}

func newShellFixture(t *testing.T) *shellFixture {
	t.Helper()
	first, second, third := verifierPeer(configv1.Dpg_DPG_WALTID), verifierPeer(configv1.Dpg_DPG_INJI), verifierPeer(configv1.Dpg_DPG_CREDEBL)
	snap := topology.Snapshot{Peers: []topology.Status{
		{Peer: first, State: topology.Live, Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: firstStack}}},
		{Peer: second, State: topology.Live, Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: secondStack}}},
		{Peer: third, State: topology.Starting},
	}}
	shell := staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_VERIFIER, Peers: []topology.Peer{first, second, third},
		Snapshot: func(context.Context) topology.Snapshot { return snap },
		JWKSURL:  first.Auth() + staffshell.JWKSPath, SignOut: DefaultPrefix + "/signout",
	})
	st := results.New(store.Memory(), nil)
	svc, err := service.New(service.Options{Store: st, Retention: time.Hour, RawRetention: time.Hour, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	f := &shellFixture{
		store: st,
		discovery: &fakeDiscovery{
			templates: []*discoveryv1.PresentationTemplate{
				{Id: "licence", DisplayName: "Driving licence check", Version: 1},
				{Id: "degree", DisplayName: "Degree check", Version: 2},
				{Id: "legacy", DisplayName: "Legacy check", Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_PE},
			},
			types: []*discoveryv1.CredentialType{
				{CredentialIssuer: "https://issuer.labs.example", Type: "DrivingLicence", Format: commonv1.Format_FORMAT_DC_SD_JWT},
				{CredentialIssuer: "https://university.labs.example", Type: "Degree", Format: commonv1.Format_FORMAT_LDP_VC},
			},
			fields: map[string][]*discoveryv1.Field{
				"DrivingLicence": {{Path: "given_name"}, {Path: "birth_date"}, {Path: "licence_class"}},
			},
		},
		requests: &fakeRequests{open: 3},
	}
	p, err := New(Options{Service: svc, Now: func() time.Time { return testNow }, Shell: shell,
		SignOut: http.NotFoundHandler(), Discovery: f.discovery, Requests: f.requests})
	if err != nil {
		t.Fatal(err)
	}
	f.portal = p
	f.mux = http.NewServeMux()
	p.Register(f.mux)
	for _, r := range []*resultsv1.VerificationResult{sample("one"), {
		Id: "two", Verdict: policyv1.EvaluateResponse_VERDICT_INVALID, TemplateId: "degree",
		EvaluatedAt: timestamppb.New(testNow.Add(time.Minute)),
		Credentials: []*resultsv1.CredentialSummary{{Title: "Degree", Issuer: "https://university.labs.example"}},
		Checks:      []*policyv1.CheckResult{{Name: "trust_chain", Outcome: policyv1.Outcome_OUTCOME_FAIL, Detail: "The issuer is not on the trust list."}},
	}} {
		if _, err := st.Put(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// get answers one GET as the staff member.
func (f *shellFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r = r.WithContext(staffsession.With(r.Context(), staff))
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, r)
	return rec
}

// ok returns the body of a 200 answer.
func ok(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// TestOverviewCards draws board Verifier-Portal at /portal/: the saved
// queries, the open requests from ListTransactions, the trust cache
// state, the schemas the catalogue offers, and the recent results.
func TestOverviewCards(t *testing.T) {
	f := newShellFixture(t)
	body := ok(t, f.get(t, DefaultPrefix+"/"))
	a11ytest.AssertPage(t, body)
	for _, want := range []string{
		"<h1", "Overview", "Queries you saved, requests in flight and recent results.",
		"New query", "New request",
		"Saved queries", "2 DCQL, 1 PE",
		"Open requests", "3 waiting", "QR or link shown, no presentation yet.",
		"Trust cache", "The policy service did not answer.",
		"Schemas to ask for", "DrivingLicence", "https://issuer.labs.example", "dc&#43;sd-jwt", "given_name, birth_date, licence_class",
		"Recent results", "Degree check", "Invalid", "The issuer is not on the trust list.", "Valid",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if len(f.requests.seen) != 1 || f.requests.seen[0] != ingestv1.GetTransactionResponse_STATE_PENDING {
		t.Errorf("the overview asked for %v, want the pending requests", f.requests.seen)
	}
	if strings.Contains(body, "Download CSV") {
		t.Error("the overview shows the result list")
	}
}

// TestOverviewWithoutServices shows every card when the discovery and
// the ingestion services do not answer.
func TestOverviewWithoutServices(t *testing.T) {
	f := newShellFixture(t)
	f.discovery.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	f.requests.err = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	body := ok(t, f.get(t, DefaultPrefix+"/"))
	a11ytest.AssertPage(t, body)
	if strings.Count(body, "Unknown now") < 2 {
		t.Errorf("want the unknown value on the query and request cards")
	}
}

// TestResultsListMoved serves the list at /portal/results/ and sends an
// old list URL with a query there, filters kept.
func TestResultsListMoved(t *testing.T) {
	f := newShellFixture(t)
	list := ok(t, f.get(t, DefaultPrefix+"/results/"))
	a11ytest.AssertPage(t, list)
	for _, want := range []string{"Download CSV", `action="/portal/results/"`, `href="/portal/results/one"`} {
		if !strings.Contains(list, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
	old := f.get(t, DefaultPrefix+"/?verdict=valid&issuer=did%3Aweb%3Aissuer")
	if old.Code != http.StatusMovedPermanently {
		t.Fatalf("old list URL: status %d, want 301", old.Code)
	}
	if loc := old.Header().Get("Location"); loc != "/portal/results/?verdict=valid&issuer=did%3Aweb%3Aissuer" {
		t.Errorf("old list URL goes to %q", loc)
	}
	detail := ok(t, f.get(t, DefaultPrefix+"/results/one"))
	if !strings.Contains(detail, `href="/portal/results/"`) {
		t.Error("the detail does not lead back to the moved list")
	}
}

// TestVerifierShellNav draws every staff page in the verifier frame:
// the role chip, the live stacks, the user menu with sign out, and the
// side navigation with the page marked.
func TestVerifierShellNav(t *testing.T) {
	f := newShellFixture(t)
	for path, current := range map[string]string{
		DefaultPrefix + "/":            "Overview",
		DefaultPrefix + "/results/":    "Results",
		DefaultPrefix + "/results/one": "Results",
		DefaultPrefix + "/cache/":      "Caching",
		DefaultPrefix + "/help/":       "Help",
	} {
		body := ok(t, f.get(t, path))
		a11ytest.AssertPage(t, body)
		for _, want := range []string{
			"Verifier", firstStack, secondStack, "Akinyi Otieno", `action="/portal/signout"`,
			"Discover schemas", "DCQL builder", "DIF PE queries", "Requests", "Caching",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", path, want)
			}
		}
		if !regexp.MustCompile(`aria-current="page"[^>]*>` + current + `</a>`).MatchString(body) {
			t.Errorf("%s: want %s marked current", path, current)
		}
	}
}

// TestCacheAndHelpPages say how the verifier checks trust today and what
// each verifier page does.
func TestCacheAndHelpPages(t *testing.T) {
	f := newShellFixture(t)
	cache := ok(t, f.get(t, DefaultPrefix+"/cache/"))
	for _, want := range []string{"No cache state now.", "The policy service did not answer."} {
		if !strings.Contains(cache, want) {
			t.Errorf("cache page lacks %q", want)
		}
	}
	help := ok(t, f.get(t, DefaultPrefix+"/help/"))
	for _, want := range []string{"verifier-results.md", "verifier-discovery.md", "verifier-ingest.md", "ListTransactions"} {
		if !strings.Contains(help, want) {
			t.Errorf("help page lacks %q", want)
		}
	}
}

// TestWordsOfVerdictsAndFormats names every verdict and format.
func TestWordsOfVerdictsAndFormats(t *testing.T) {
	for v, want := range map[policyv1.EvaluateResponse_Verdict]string{
		policyv1.EvaluateResponse_VERDICT_VALID: "ok", policyv1.EvaluateResponse_VERDICT_INVALID: "bad",
		policyv1.EvaluateResponse_VERDICT_INDETERMINATE: "warn", policyv1.EvaluateResponse_VERDICT_UNSPECIFIED: "info",
	} {
		if got := verdictStatus(v); got != want {
			t.Errorf("%s: status %q, want %q", v, got, want)
		}
		if verdictText(v) == "" {
			t.Errorf("%s: no word", v)
		}
	}
	for f, want := range map[commonv1.Format]string{
		commonv1.Format_FORMAT_VC_SD_JWT: "vc+sd-jwt", commonv1.Format_FORMAT_DC_SD_JWT: "dc+sd-jwt",
		commonv1.Format_FORMAT_JWT_VC_JSON: "jwt_vc_json", commonv1.Format_FORMAT_LDP_VC: "ldp_vc",
		commonv1.Format_FORMAT_MSO_MDOC: "mso_mdoc", commonv1.Format_FORMAT_UNSPECIFIED: "",
	} {
		if got := formatName(f); got != want {
			t.Errorf("%s: %q, want %q", f, got, want)
		}
	}
}

// TestOverviewWithoutShellOrNeighbours draws the overview with the plain
// navigation when the portal has no shell and no neighbour clients.
func TestOverviewWithoutShellOrNeighbours(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.get(t, DefaultPrefix+"/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	a11ytest.AssertPage(t, body)
	if strings.Count(body, "Unknown now") < 2 || !strings.Contains(body, "Citizen check") {
		t.Error("want the unknown cards and the plain navigation")
	}
	for _, path := range []string{DefaultPrefix + "/cache/", DefaultPrefix + "/help/"} {
		if rec := f.get(t, path); rec.Code != http.StatusOK {
			t.Errorf("%s: status %d", path, rec.Code)
		}
	}
}

// TestOverviewLimits caps the catalogue and the claims of the overview.
func TestOverviewLimits(t *testing.T) {
	f := newShellFixture(t)
	f.discovery.types = nil
	for i := 0; i < overviewSchemas+2; i++ {
		f.discovery.types = append(f.discovery.types, &discoveryv1.CredentialType{
			CredentialIssuer: "https://issuer.labs.example", Type: "DrivingLicence", Format: commonv1.Format_FORMAT_DC_SD_JWT,
		})
	}
	var many []*discoveryv1.Field
	for i := 0; i < overviewClaims+3; i++ {
		many = append(many, &discoveryv1.Field{Path: "claim_" + strconv.Itoa(i)})
	}
	f.discovery.fields["DrivingLicence"] = many
	for i := 0; i < overviewResults+2; i++ {
		if _, err := f.store.Put(context.Background(), sample("r"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	body := ok(t, f.get(t, DefaultPrefix+"/"))
	if strings.Count(body, "Build query") != overviewSchemas {
		t.Errorf("want %d catalogue rows", overviewSchemas)
	}
	if !strings.Contains(body, "and 3 more") {
		t.Error("want the claim list cut with a count")
	}
}
