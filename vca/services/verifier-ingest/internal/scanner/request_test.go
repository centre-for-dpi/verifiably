// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/scanner"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// licenceDCQL is the DCQL query of the saved licence check.
const licenceDCQL = `{"credentials":[{"id":"licence","format":"dc+sd-jwt","meta":{"vct_values":["https://example.test/pid"]},"claims":[{"id":"given_name","path":["given_name"]}]}],"credential_sets":[{"options":[["licence"]]}]}`

// badgePE is a PE query that loses a status directive in DCQL.
const badgePE = `{"id":"badge","input_descriptors":[{"id":"badge","format":{"jwt_vc_json":{}},"constraints":{"statuses":{"active":{"directive":"required"}},"fields":[{"path":["$.vc.credentialSubject.employee_id"]}]}}]}`

// sdjwtAnswer is an SD-JWT VC with the claims given_name Asha and
// licence_class B.
const sdjwtAnswer = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUudGVzdC9waWQiLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiZ2l2ZW5fbmFtZSI6IkFzaGEiLCJsaWNlbmNlX2NsYXNzIjoiQiJ9.c2ln~"

// templates serves the saved queries of the tests.
type templates struct {
	discoveryv1connect.UnimplementedDiscoveryServiceHandler
	list []*discoveryv1.PresentationTemplate
}

func (f *templates) ListTemplates(context.Context, *connect.Request[discoveryv1.ListTemplatesRequest]) (*connect.Response[discoveryv1.ListTemplatesResponse], error) {
	return connect.NewResponse(&discoveryv1.ListTemplatesResponse{Templates: f.list}), nil
}

func (f *templates) GetTemplate(_ context.Context, req *connect.Request[discoveryv1.GetTemplateRequest]) (*connect.Response[discoveryv1.GetTemplateResponse], error) {
	for _, t := range f.list {
		if t.GetId() == req.Msg.GetId() {
			return connect.NewResponse(&discoveryv1.GetTemplateResponse{Template: t}), nil
		}
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("no template"))
}

// savedQueries holds a DCQL query with a policy set, a DCQL query whose
// PE form loses its issuer rule, and a PE query without a DCQL form.
func savedQueries() *templates {
	lossy := strings.Replace(licenceDCQL, `"claims"`, `"trusted_authorities":[{"type":"etsi_tl","values":["https://issuer.example"]}],"claims"`, 1)
	return &templates{list: []*discoveryv1.PresentationTemplate{
		{Id: "licence-check", Version: 2, DisplayName: "Driving licence check", Purpose: "Check the licence.", Dcql: licenceDCQL,
			Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_DCQL, PolicySetId: "query-licence-check"},
		{Id: "issuer-check", Version: 1, DisplayName: "Issuer bound check", Dcql: lossy, Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_DCQL},
		{Id: "badge-check", Version: 1, DisplayName: "Staff badge", Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_PE, PresentationDefinition: badgePE},
	}}
}

// policy records every evaluation and answers valid.
type policy struct {
	mu   sync.Mutex
	seen []*policyv1.EvaluateRequest
}

func (f *policy) Evaluate(_ context.Context, req *connect.Request[policyv1.EvaluateRequest]) (*connect.Response[policyv1.EvaluateResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, req.Msg)
	return connect.NewResponse(&policyv1.EvaluateResponse{
		Verdict: policyv1.EvaluateResponse_VERDICT_VALID, PolicySetId: req.Msg.GetPolicySetId(), PolicySetVersion: 1,
		EvaluatedAt: timestamppb.New(time.Unix(1700000030, 0)),
		Checks: []*policyv1.CheckResult{
			{Name: "signature", Outcome: policyv1.Outcome_OUTCOME_PASS, Detail: "The signature is valid.", CredentialIndex: 0},
			{Name: "nonce", Outcome: policyv1.Outcome_OUTCOME_PASS, Detail: "The nonce matches.", CredentialIndex: -1},
		},
	}), nil
}

// results stores each result under the next id and reads it back.
type results struct {
	mu     sync.Mutex
	stored map[string]*resultsv1.VerificationResult
}

func (f *results) Store(_ context.Context, req *connect.Request[resultsv1.StoreRequest]) (*connect.Response[resultsv1.StoreResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := req.Msg.GetResult()
	r.Id = "res-" + string(rune('0'+len(f.stored)+1))
	f.stored[r.GetId()] = r
	return connect.NewResponse(&resultsv1.StoreResponse{Result: r}), nil
}

func (f *results) Get(_ context.Context, req *connect.Request[resultsv1.GetRequest]) (*connect.Response[resultsv1.GetResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.stored[req.Msg.GetId()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no result"))
	}
	return connect.NewResponse(&resultsv1.GetResponse{Result: r}), nil
}

// stackVerifier is the verifier of one adapter. It answers pending until
// the test sets an answer.
type stackVerifier struct {
	mu      sync.Mutex
	created []*backendv1.CreateRequestRequest
	polls   int
	answer  *backendv1.GetResultResponse
}

func (f *stackVerifier) CreateRequest(_ context.Context, req *connect.Request[backendv1.CreateRequestRequest]) (*connect.Response[backendv1.CreateRequestResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, req.Msg)
	return connect.NewResponse(&backendv1.CreateRequestResponse{
		RequestUri: "openid4vp://authorize?client_id=stack&request_uri=https%3A%2F%2Fstack.example%2Fr%2F1", State: "stack-state-1",
		ExpiresAt: timestamppb.New(time.Unix(1700000600, 0)),
	}), nil
}

func (f *stackVerifier) GetResult(_ context.Context, req *connect.Request[backendv1.GetResultRequest]) (*connect.Response[backendv1.GetResultResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	if req.Msg.GetState() != "stack-state-1" {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no state"))
	}
	if f.answer == nil {
		return connect.NewResponse(&backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_PENDING}), nil
	}
	return connect.NewResponse(f.answer), nil
}

// requestRig is the request pages over a service with fakes.
type requestRig struct {
	mux     *http.ServeMux
	svc     *service.Service
	store   *txn.Store
	policy  *policy
	results *results
	legacy  *stackVerifier
	modern  *stackVerifier
	now     *time.Time
}

// newRequestRig wires the pages in the verifier frame with two live
// stacks: one reads PE only, one reads DCQL.
func newRequestRig(t *testing.T) *requestRig {
	t.Helper()
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0).UTC()
	rig := &requestRig{store: store, now: &now, policy: &policy{}, results: &results{stored: map[string]*resultsv1.VerificationResult{}},
		legacy: &stackVerifier{}, modern: &stackVerifier{}}
	clock := func() time.Time { return *rig.now }
	stacks := func(context.Context) []service.Stack {
		return []service.Stack{
			{Pair: "verifier-waltid", Name: "Legacy stack", Adapter: "http://legacy:8080",
				Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP, backendv1.Protocol_PROTOCOL_OID4VP_PEX}},
			{Pair: "verifier-credebl", Name: "Modern stack", Adapter: "http://modern:8080",
				Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP, backendv1.Protocol_PROTOCOL_OID4VP_DCQL}},
		}
	}
	client := func(adapter string) service.StackVerifier {
		if adapter == "http://legacy:8080" {
			return rig.legacy
		}
		return rig.modern
	}
	discovery := savedQueries()
	rig.svc, err = service.New(service.Options{
		Store: store, SigningKey: key, BaseURL: "https://verify.example", ClientID: "https://verify.example",
		Discovery: discovery, Policy: rig.policy, Results: rig.results, Stacks: stacks, StackClient: client,
		RequestTTL: 5 * time.Minute, Now: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	pair := topology.Peer{Pair: "verifier-waltid", Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_WALTID,
		PublicURL: "https://verifier-waltid.labs.example", Services: map[string]string{"verifier-auth": "http://verifier-waltid-auth:8081"}}
	shell := staffshell.New(staffshell.Options{
		Role: commonv1.Role_ROLE_VERIFIER, Peers: []topology.Peer{pair},
		Snapshot: func(context.Context) topology.Snapshot {
			return topology.Snapshot{Peers: []topology.Status{{Peer: pair, State: topology.Live,
				Capabilities: &backendv1.GetCapabilitiesResponse{DpgInfo: &backendv1.DpgInfo{DisplayName: "Legacy stack"}}}}}
		},
		JWKSURL: pair.Auth() + staffshell.JWKSPath, SignOut: "/scan/signout",
	})
	page, err := scanner.New(scanner.Options{
		Client: rig.svc, Shell: shell, SignOut: http.NotFoundHandler(),
		Discovery: discovery, Results: rig.results, Stacks: stacks,
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.mux = http.NewServeMux()
	page.Register(rig.mux)
	return rig
}

// create posts the new request form and returns the path of the page.
func (rig *requestRig) create(t *testing.T, form url.Values) string {
	t.Helper()
	rec := staffDo(t, rig.mux, formPost("/scan/requests/", form))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Location")
}

// get answers one GET and checks the status.
func (rig *requestRig) get(t *testing.T, path string, hx bool) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if hx {
		r.Header.Set("HX-Request", "true")
	}
	rec := staffDo(t, rig.mux, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// idOf reads the transaction id of a request page path.
func idOf(t *testing.T, path string) string {
	t.Helper()
	m := regexp.MustCompile(`^/scan/requests/([A-Za-z0-9_-]+)`).FindStringSubmatch(path)
	if m == nil {
		t.Fatalf("no request id in %q", path)
	}
	return m[1]
}

// TestRequestShowsQRAndLink sends a saved query through the VCA
// verifier. The page shows the QR code, the link, the expiry, and a
// state that htmx polls every 2 s, with a refresh link for a page
// without JavaScript.
func TestRequestShowsQRAndLink(t *testing.T) {
	rig := newRequestRig(t)
	form := rig.get(t, "/scan/requests/new", false)
	a11ytest.AssertPage(t, form)
	for _, want := range []string{"Driving licence check", "Staff badge", `name="template"`, `name="through"`, `name="deliver"`, `name="expires"`} {
		if !strings.Contains(form, want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	path := rig.create(t, url.Values{"template": {"licence-check"}, "through": {"vca"}, "deliver": {"qr"}, "expires": {"300"}})
	if !strings.Contains(path, "as=qr") {
		t.Errorf("location %q", path)
	}
	page := rig.get(t, path, false)
	a11ytest.AssertPage(t, page)
	for _, want := range []string{
		`<img`, `alt="QR code of the presentation request."`, "openid4vp://authorize?", "Driving licence check",
		`hx-get="/scan/requests/` + idOf(t, path) + `/state"`, `hx-trigger="every 2s"`, "Refresh", "Waiting", "Expires at 22:18 UTC",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	link := rig.get(t, "/scan/requests/"+idOf(t, path)+"?as=link", false)
	if strings.Contains(link, `alt="QR code of the presentation request."`) || !strings.Contains(link, "Copy the link") {
		t.Error("the link view shows the QR code or lacks the link")
	}
	state := rig.get(t, "/scan/requests/"+idOf(t, path)+"/state", true)
	a11ytest.AssertFragment(t, state)
	if !strings.Contains(state, `hx-trigger="every 2s"`) {
		t.Error("a pending state stops the poll")
	}
	list := rig.get(t, "/scan/requests/", false)
	a11ytest.AssertPage(t, list)
	if !strings.Contains(list, "Driving licence check") || !strings.Contains(list, "VCA verifier") || !strings.Contains(list, "Waiting") {
		t.Errorf("the list lacks the request: %s", list)
	}
}

// TestStackVerifierOptionFollowsCapabilities offers each stack only for
// the queries its adapter reads: a DCQL query to a DCQL stack, a PE
// query to a PE stack, and a DCQL query to a PE stack only when its PE
// form loses nothing. The VCA verifier needs a DCQL form.
func TestStackVerifierOptionFollowsCapabilities(t *testing.T) {
	rig := newRequestRig(t)
	options := func(template string) string {
		rec := staffDo(t, rig.mux, formPost("/scan/requests/new/answerers", url.Values{"template": {template}}))
		if rec.Code != http.StatusOK {
			t.Fatalf("answerers: %d", rec.Code)
		}
		a11ytest.AssertFragment(t, rec.Body.String())
		var got []string
		for _, m := range regexp.MustCompile(`name="through" value="([^"]+)"`).FindAllStringSubmatch(rec.Body.String(), -1) {
			got = append(got, m[1])
		}
		return strings.Join(got, ",")
	}
	for template, want := range map[string]string{
		"licence-check": "vca,verifier-waltid,verifier-credebl",
		"issuer-check":  "vca,verifier-credebl",
		"badge-check":   "verifier-waltid",
	} {
		if got := options(template); got != want {
			t.Errorf("%s: answerers %q, want %q", template, got, want)
		}
	}
	ctx := context.Background()
	for _, c := range []struct{ template, stack string }{{"badge-check", ""}, {"badge-check", "verifier-credebl"}, {"licence-check", "verifier-inji"}} {
		_, err := rig.svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: c.template, Stack: c.stack}))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("%s through %q: %v", c.template, c.stack, err)
		}
	}
	refused := staffDo(t, rig.mux, formPost("/scan/requests/", url.Values{"template": {"badge-check"}, "through": {"vca"}}))
	if refused.Code != http.StatusBadRequest {
		t.Errorf("a PE query through the VCA verifier: %d", refused.Code)
	}
	a11ytest.AssertPage(t, refused.Body.String())
	// The PE stack gets the PE form of a lossless DCQL query.
	rig.create(t, url.Values{"template": {"licence-check"}, "through": {"verifier-waltid"}})
	if len(rig.legacy.created) != 1 || rig.legacy.created[0].GetPresentationDefinition() == "" || rig.legacy.created[0].GetDcql() != "" {
		t.Errorf("the PE stack got %+v", rig.legacy.created)
	}
	rig.create(t, url.Values{"template": {"licence-check"}, "through": {"verifier-credebl"}})
	if len(rig.modern.created) != 1 || rig.modern.created[0].GetDcql() != licenceDCQL {
		t.Errorf("the DCQL stack got %+v", rig.modern.created)
	}
}

// TestReceivedPresentationIsEvaluatedAndStored evaluates the answer of
// a wallet with the policy set of the query and stores the result. The
// page then shows the verdict card with the result id.
func TestReceivedPresentationIsEvaluatedAndStored(t *testing.T) {
	rig := newRequestRig(t)
	ctx := context.Background()
	path := rig.create(t, url.Values{"template": {"licence-check"}, "through": {"vca"}})
	record, err := rig.store.Get(ctx, idOf(t, path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rig.svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{State: record.StateParam, VpToken: sdjwtAnswer})); err != nil {
		t.Fatal(err)
	}
	if len(rig.policy.seen) != 1 || rig.policy.seen[0].GetPolicySetId() != "query-licence-check" || rig.policy.seen[0].GetNonce() != record.Nonce {
		t.Fatalf("evaluations %+v", rig.policy.seen)
	}
	stored := rig.results.stored["res-1"]
	if stored == nil || stored.GetTemplateId() != "licence-check" || stored.GetTemplateVersion() != 2 || stored.GetCarrier() != "oid4vp" ||
		len(stored.GetCredentials()) != 1 || len(stored.GetChecks()) != 1 {
		t.Fatalf("stored %+v", stored)
	}
	got, err := rig.svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: record.ID}))
	if err != nil || got.Msg.GetResultId() != "res-1" {
		t.Fatalf("transaction %+v %v", got, err)
	}
	state := rig.get(t, "/scan/requests/"+record.ID+"/state", true)
	a11ytest.AssertFragment(t, state)
	for _, want := range []string{"Verified", "Saved as result res-1", `href="/portal/results/res-1"`, "given_name", "Asha", "signature"} {
		if !strings.Contains(state, want) {
			t.Errorf("the verdict card lacks %q", want)
		}
	}
	if strings.Contains(state, "hx-trigger") {
		t.Error("a finished request keeps polling")
	}
	page := rig.get(t, path, false)
	a11ytest.AssertPage(t, page)
	if !strings.Contains(rig.get(t, "/scan/requests/", false), `href="/portal/results/res-1"`) {
		t.Error("the list does not link the result")
	}
}

// TestDpgRequestPathPollsGetResult sends a query through a stack
// verifier. Each state poll asks GetResult of the adapter. The answer
// is evaluated and stored like a direct post.
func TestDpgRequestPathPollsGetResult(t *testing.T) {
	rig := newRequestRig(t)
	path := rig.create(t, url.Values{"template": {"licence-check"}, "through": {"verifier-credebl"}, "deliver": {"link"}})
	id := idOf(t, path)
	page := rig.get(t, path, false)
	if !strings.Contains(page, "Modern stack") || !strings.Contains(page, "stack.example") {
		t.Errorf("the page lacks the stack request")
	}
	first := rig.get(t, "/scan/requests/"+id+"/state", true)
	if rig.modern.polls != 2 || !strings.Contains(first, "Waiting") {
		t.Fatalf("first poll: %d %s", rig.modern.polls, first)
	}
	rig.modern.answer = &backendv1.GetResultResponse{
		State:      backendv1.GetResultResponse_STATE_ACCEPTED,
		Presented:  []*commonv1.Credential{{Format: commonv1.Format_FORMAT_DC_SD_JWT, Payload: []byte(sdjwtAnswer)}},
		DpgChecks:  []*backendv1.GetResultResponse_DpgCheck{{Name: "signature", Passed: true}},
		ReceivedAt: timestamppb.New(time.Unix(1700000010, 0)),
	}
	second := rig.get(t, "/scan/requests/"+id+"/state", true)
	a11ytest.AssertFragment(t, second)
	if len(rig.policy.seen) != 1 || rig.policy.seen[0].GetPolicySetId() != "query-licence-check" {
		t.Fatalf("evaluations %+v", rig.policy.seen)
	}
	for _, want := range []string{"Saved as result res-1", "Checks of Modern stack", "Asha"} {
		if !strings.Contains(second, want) {
			t.Errorf("the verdict lacks %q: %s", want, second)
		}
	}
	rig.get(t, "/scan/requests/"+id+"/state", true)
	if rig.modern.polls != 3 || len(rig.policy.seen) != 1 {
		t.Errorf("a finished request polled again: %d polls, %d evaluations", rig.modern.polls, len(rig.policy.seen))
	}
}

// TestExpiredRequestState shows an expired request without a poll, and
// the expiry the staff member picked.
func TestExpiredRequestState(t *testing.T) {
	rig := newRequestRig(t)
	path := rig.create(t, url.Values{"template": {"licence-check"}, "through": {"vca"}, "expires": {"120"}})
	if !strings.Contains(rig.get(t, path, false), "Expires at 22:15 UTC") {
		t.Error("the page does not show the picked expiry")
	}
	*rig.now = rig.now.Add(3 * time.Minute)
	state := rig.get(t, "/scan/requests/"+idOf(t, path)+"/state", true)
	a11ytest.AssertFragment(t, state)
	if !strings.Contains(state, "Expired") || strings.Contains(state, "hx-trigger") {
		t.Errorf("expired state: %s", state)
	}
	page := rig.get(t, path, false)
	if strings.Contains(page, `alt="QR code of the presentation request."`) {
		t.Error("an expired request still shows its QR code")
	}
	if !strings.Contains(rig.get(t, "/scan/requests/", false), "Expired") {
		t.Error("the list does not show the expiry")
	}
}

// TestDocumentDeliveryIsPDF serves the request as a PDF document of
// core/pdf that carries the QR code.
func TestDocumentDeliveryIsPDF(t *testing.T) {
	rig := newRequestRig(t)
	path := rig.create(t, url.Values{"template": {"licence-check"}, "through": {"vca"}, "deliver": {"document"}})
	page := rig.get(t, path, false)
	docPath := "/scan/requests/" + idOf(t, path) + "/document.pdf"
	if !strings.Contains(page, `href="`+docPath+`"`) {
		t.Errorf("the document view lacks the download link")
	}
	rec := staffDo(t, rig.mux, httptest.NewRequest(http.MethodGet, docPath, nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/pdf" || !strings.HasPrefix(rec.Body.String(), "%PDF-") {
		t.Fatalf("document: %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") || !strings.Contains(rec.Body.String(), "/Subtype /Image") {
		t.Error("the document is not a download with the QR image")
	}
	if rec := staffDo(t, rig.mux, httptest.NewRequest(http.MethodGet, "/scan/requests/nothing/document.pdf", nil)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown request: %d", rec.Code)
	}
}

// TestRequestPagesWithoutLinks shows the empty form without a discovery
// service, and the refused, unchecked, and unknown requests.
func TestRequestPagesWithoutLinks(t *testing.T) {
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Options{Store: store, SigningKey: key, BaseURL: "https://verify.example"})
	if err != nil {
		t.Fatal(err)
	}
	page, err := scanner.New(scanner.Options{Client: svc})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	page.Register(mux)
	rig := &requestRig{mux: mux}
	form := rig.get(t, "/scan/requests/new", false)
	a11ytest.AssertPage(t, form)
	if !strings.Contains(form, "No saved query yet.") {
		t.Error("the form lacks the empty state")
	}
	ctx := context.Background()
	for _, tx := range []txn.Transaction{
		{ID: "refused", State: txn.StateRefused, Error: "access_denied", CreatedAt: time.Now(), TemplateID: "gone", Stack: "verifier-gone"},
		{ID: "unchecked", State: txn.StateReceived, CreatedAt: time.Now(), StackChecks: []txn.StackCheck{{Name: "signature"}}},
		{ID: "saved", State: txn.StateReceived, CreatedAt: time.Now(), ResultID: "res-5"},
	} {
		if err := store.Put(ctx, tx); err != nil {
			t.Fatal(err)
		}
	}
	refused := rig.get(t, "/scan/requests/refused", false)
	a11ytest.AssertPage(t, refused)
	if !strings.Contains(refused, "access_denied") || !strings.Contains(refused, "verifier-gone") || !strings.Contains(refused, "Send it again") {
		t.Errorf("refused page: %s", refused)
	}
	if !strings.Contains(rig.get(t, "/scan/requests/unchecked/state", true), "did not check it") {
		t.Error("the unchecked answer lacks its sentence")
	}
	if !strings.Contains(rig.get(t, "/scan/requests/saved/state", true), "The results service did not answer.") {
		t.Error("a result without the results service lacks its sentence")
	}
	list := rig.get(t, "/scan/requests/", false)
	if !strings.Contains(list, "Query without a name") || !strings.Contains(list, "Refused") {
		t.Errorf("list: %s", list)
	}
	for _, path := range []string{"/scan/requests/nothing", "/scan/requests/nothing/state"} {
		if rec := staffDo(t, mux, httptest.NewRequest(http.MethodGet, path, nil)); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	answerers := staffDo(t, mux, formPost("/scan/requests/new/answerers", url.Values{"template": {"x"}}))
	if !strings.Contains(answerers.Body.String(), "No live verifier reads this query.") {
		t.Errorf("answerers: %s", answerers.Body.String())
	}
}
