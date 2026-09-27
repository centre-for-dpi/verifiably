// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	shared "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/scanner"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// P6-C6: the request page offers a DIDComm proof request through a
// stack that asks over DIDComm (ADR-061 decision 5).

// invitation is the out of band invitation a DIDComm stack answers with.
const invitation = "https://agent.credebl.example?oob=eyJAdHlwZSI6Imh0dHBzOi8vZGlkY29tbS5vcmcvb3V0LW9mLWJhbmQvMS4xL2ludml0YXRpb24ifQ"

// didcommVerifier is the verifier of a CREDEBL adapter.
type didcommVerifier struct {
	mu      sync.Mutex
	created []*backendv1.CreateRequestRequest
	answer  *backendv1.GetResultResponse
}

func (f *didcommVerifier) CreateRequest(_ context.Context, req *connect.Request[backendv1.CreateRequestRequest]) (*connect.Response[backendv1.CreateRequestResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, req.Msg)
	out := &backendv1.CreateRequestResponse{State: "didcomm-proof:p-1", ExpiresAt: timestamppb.New(time.Unix(1700000600, 0))}
	if req.Msg.GetConnectionId() == "" {
		out.RequestUri = invitation
	}
	return connect.NewResponse(out), nil
}

func (f *didcommVerifier) GetResult(context.Context, *connect.Request[backendv1.GetResultRequest]) (*connect.Response[backendv1.GetResultResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.answer == nil {
		return connect.NewResponse(&backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_PENDING}), nil
	}
	return connect.NewResponse(f.answer), nil
}

func (f *didcommVerifier) SubmitBrowserAnswer(context.Context, *connect.Request[backendv1.SubmitBrowserAnswerRequest]) (*connect.Response[backendv1.SubmitBrowserAnswerResponse], error) {
	return connect.NewResponse(&backendv1.SubmitBrowserAnswerResponse{}), nil
}

func (f *didcommVerifier) ListVerifierConnections(context.Context, *connect.Request[backendv1.ListVerifierConnectionsRequest]) (*connect.Response[backendv1.ListVerifierConnectionsResponse], error) {
	return connect.NewResponse(&backendv1.ListVerifierConnectionsResponse{Connections: []*backendv1.DidcommConnection{
		{Id: "conn-1", Label: "Wanjiku mobile wallet", State: "completed"},
	}}), nil
}

func (f *didcommVerifier) ListProofRequests(context.Context, *connect.Request[backendv1.ListProofRequestsRequest]) (*connect.Response[backendv1.ListProofRequestsResponse], error) {
	return connect.NewResponse(&backendv1.ListProofRequestsResponse{Requests: []*backendv1.ProofRequest{
		{Id: "p-1", ConnectionLabel: "Wanjiku mobile wallet", State: "done", CreatedAt: timestamppb.New(time.Unix(1700000100, 0))},
		{Id: "p-0", State: "abandoned", Error: "abandoned: The holder declined the request", CreatedAt: timestamppb.New(time.Unix(1700000000, 0))},
	}}), nil
}

// farmerQuery is a saved AnonCreds query.
func farmerQuery() *discoveryv1.PresentationTemplate {
	r := &discoveryv1.AnonCredsRequest_Restriction{SchemaId: "did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/SCHEMA/Farmer/1.0"}
	return &discoveryv1.PresentationTemplate{Id: "farmer-check", Version: 1, DisplayName: "Farmer check", Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_NATIVE,
		Anoncreds: &discoveryv1.AnonCredsRequest{Name: "Farmer check", Version: "1.0",
			Attributes: []*discoveryv1.AnonCredsRequest_Attribute{{Names: []string{"fullName"}, Restriction: r}},
			Predicates: []*discoveryv1.AnonCredsRequest_Predicate{{Name: "acres", Op: ">=", Value: 10, Restriction: r}}}}
}

// didcommRig is the request pages with one live CREDEBL stack.
type didcommRig struct {
	mux   *http.ServeMux
	stack *didcommVerifier
}

func newDidcommRig(t *testing.T) *didcommRig {
	t.Helper()
	store, err := txn.NewStore(shared.Memory())
	if err != nil {
		t.Fatal(err)
	}
	key, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	rig := &didcommRig{stack: &didcommVerifier{}}
	stacks := func(context.Context) []service.Stack {
		return []service.Stack{{Pair: "verifier-credebl", Name: "CREDEBL", Adapter: "http://credebl:8080",
			Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP_DCQL, backendv1.Protocol_PROTOCOL_DIDCOMM_PRESENT_V2},
			Features:  []backendv1.Feature{backendv1.Feature_FEATURE_ANONCREDS_PROOF}}}
	}
	discovery := savedQueries()
	discovery.list = append([]*discoveryv1.PresentationTemplate{farmerQuery()}, discovery.list...)
	res := &results{stored: map[string]*resultsv1.VerificationResult{}}
	svc, err := service.New(service.Options{
		Store: store, SigningKey: key, BaseURL: "https://verify.example", ClientID: "https://verify.example",
		Discovery: discovery, Policy: &policy{}, Results: res, Stacks: stacks,
		StackClient: func(string) service.StackVerifier { return rig.stack },
		RequestTTL:  5 * time.Minute, Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := scanner.New(scanner.Options{
		Client: svc, Discovery: discovery, Results: res, Stacks: stacks,
		Didcomm: func(string) scanner.DidcommVerifier { return rig.stack },
	})
	if err != nil {
		t.Fatal(err)
	}
	rig.mux = http.NewServeMux()
	page.Register(rig.mux)
	return rig
}

func (rig *didcommRig) get(t *testing.T, path string) string {
	t.Helper()
	rec := staffDo(t, rig.mux, httptestGet(path))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

// TestRequestPageOffersDidcommProofRequest is P6-C6: the form offers
// "CREDEBL, DIDComm proof request" for an AnonCreds query, and no VCA
// verifier. A DCQL query gets the OID4VP choice beside it. The form
// offers the wallets that connected to the stack.
func TestRequestPageOffersDidcommProofRequest(t *testing.T) {
	rig := newDidcommRig(t)
	form := html.UnescapeString(rig.get(t, "/scan/requests/new?template=farmer-check"))
	a11ytest.AssertPage(t, form)
	for _, want := range []string{
		"Farmer check, AnonCreds", `value="verifier-credebl|didcomm"`, "CREDEBL, DIDComm proof request",
		`value="connection"`, "Connected wallet", `name="connection"`, "Wanjiku mobile wallet, CREDEBL",
	} {
		if !strings.Contains(form, want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	if strings.Contains(form, `value="vca"`) {
		t.Error("the VCA verifier answers an AnonCreds query")
	}
	rec := staffDo(t, rig.mux, formPost("/scan/requests/new/answerers", url.Values{"template": {"licence-check"}}))
	frag := html.UnescapeString(rec.Body.String())
	a11ytest.AssertFragment(t, rec.Body.String())
	if !strings.Contains(frag, `value="verifier-credebl"`) || !strings.Contains(frag, `value="verifier-credebl|didcomm"`) || !strings.Contains(frag, `value="vca"`) {
		t.Errorf("the choice of a DCQL query = %s", frag)
	}
}

// TestDidcommOobRequestShowsInvitation: an out of band request shows the
// invitation of the stack as a QR code and a link.
func TestDidcommOobRequestShowsInvitation(t *testing.T) {
	rig := newDidcommRig(t)
	rec := staffDo(t, rig.mux, formPost("/scan/requests/", url.Values{
		"template": {"farmer-check"}, "through": {"verifier-credebl|didcomm"}, "deliver": {"qr"}, "expires": {"300"},
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	sent := rig.stack.created[0]
	if !sent.GetDidcomm() || !strings.Contains(sent.GetAnoncredsRequest(), `"acres"`) {
		t.Fatalf("sent %+v", sent)
	}
	page := html.UnescapeString(rig.get(t, rec.Header().Get("Location")))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{"data:image/svg+xml;base64,", invitation, "CREDEBL, DIDComm", "AnonCreds"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
}

// TestDidcommConnectionRequest: a request to a connected wallet goes
// over the connection. The page has no QR code and says where the
// request went.
func TestDidcommConnectionRequest(t *testing.T) {
	rig := newDidcommRig(t)
	rec := staffDo(t, rig.mux, formPost("/scan/requests/", url.Values{
		"template": {"licence-check"}, "through": {"verifier-credebl|didcomm"}, "deliver": {"connection"}, "connection": {"conn-1"}, "expires": {"300"},
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	sent := rig.stack.created[0]
	if sent.GetConnectionId() != "conn-1" || !sent.GetDidcomm() || sent.GetPresentationDefinition() == "" {
		t.Fatalf("sent %+v", sent)
	}
	page := html.UnescapeString(rig.get(t, rec.Header().Get("Location")))
	a11ytest.AssertPage(t, page)
	if strings.Contains(page, "data:image/svg+xml") || !strings.Contains(page, "The stack sent the request to the connected wallet.") {
		t.Errorf("the page of a connection request = %s", page)
	}
	for name, form := range map[string]url.Values{
		"no connection": {"template": {"licence-check"}, "through": {"verifier-credebl|didcomm"}, "deliver": {"connection"}},
		"not didcomm":   {"template": {"licence-check"}, "through": {"verifier-credebl"}, "deliver": {"connection"}, "connection": {"conn-1"}},
	} {
		bad := staffDo(t, rig.mux, formPost("/scan/requests/", form))
		if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "Pick a wallet connection") {
			t.Errorf("%s: %d", name, bad.Code)
		}
		a11ytest.AssertPage(t, bad.Body.String())
	}
}

// TestDidcommResultShowsRevealedValues: the verdict card of an answered
// request shows the check of the stack and the revealed values, with the
// predicate and not the number of the holder.
func TestDidcommResultShowsRevealedValues(t *testing.T) {
	rig := newDidcommRig(t)
	rec := staffDo(t, rig.mux, formPost("/scan/requests/", url.Values{
		"template": {"farmer-check"}, "through": {"verifier-credebl|didcomm"}, "deliver": {"link"},
	}))
	path := rec.Header().Get("Location")
	rig.stack.answer = &backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_ACCEPTED,
		Presented: []*commonv1.Credential{{Format: commonv1.Format_FORMAT_ANONCREDS,
			Payload: []byte(`{"type":["Farmer"],"issuer":"did:indy:bcovrin:testnet:Ra8F","credentialSubject":{"fullName":"Wanjiku Kamau","acres":">=10"}}`)}},
		DpgChecks: []*backendv1.GetResultResponse_DpgCheck{{Name: "credebl-proof-verified", Passed: true}}}
	state := staffDo(t, rig.mux, httptestGet(strings.Split(path, "?")[0]+"/state"))
	body := html.UnescapeString(state.Body.String())
	a11ytest.AssertFragment(t, state.Body.String())
	for _, want := range []string{"credebl-proof-verified", "Wanjiku Kamau", ">=10", "acres"} {
		if !strings.Contains(body, want) {
			t.Errorf("the verdict lacks %q: %s", want, body)
		}
	}
}

// TestRequestListShowsStackProofRequests: the request list shows the
// proof requests of each stack that asks over DIDComm.
func TestRequestListShowsStackProofRequests(t *testing.T) {
	rig := newDidcommRig(t)
	page := html.UnescapeString(rig.get(t, "/scan/requests/"))
	a11ytest.AssertPage(t, page)
	for _, want := range []string{"Proof requests in CREDEBL", "Wanjiku mobile wallet", "done", "The holder declined the request"} {
		if !strings.Contains(page, want) {
			t.Errorf("the list lacks %q", want)
		}
	}
}

// TestDidcommChoicesOnlyWithTheProtocol is ADR-034 decision 5: without a
// stack that asks over DIDComm, the pages offer no DIDComm request, no
// connected wallet, and no proof request list.
func TestDidcommChoicesOnlyWithTheProtocol(t *testing.T) {
	rig := newRequestRig(t)
	form := rig.get(t, "/scan/requests/new", false)
	list := rig.get(t, "/scan/requests/", false)
	for _, page := range []string{form, list} {
		for _, bad := range []string{"|didcomm", "Connected wallet", "Proof requests in"} {
			if strings.Contains(page, bad) {
				t.Errorf("a page without DIDComm shows %q", bad)
			}
		}
	}
}

// httptestGet builds one GET request.
func httptestGet(path string) *http.Request {
	return httptest.NewRequest(http.MethodGet, path, nil)
}
