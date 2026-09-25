// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/txn"
)

// answer is an SD-JWT VC with the plain claim given_name.
const answer = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRjK3NkLWp3dCJ9.eyJ2Y3QiOiJodHRwczovL2V4YW1wbGUudGVzdC9waWQiLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwiZ2l2ZW5fbmFtZSI6IkFzaGEiLCJsaWNlbmNlX2NsYXNzIjoiQiJ9.c2ln~"

// templateOf serves one template.
type templateOf struct {
	discoveryv1connect.UnimplementedDiscoveryServiceHandler
	t *discoveryv1.PresentationTemplate
}

func (f templateOf) GetTemplate(context.Context, *connect.Request[discoveryv1.GetTemplateRequest]) (*connect.Response[discoveryv1.GetTemplateResponse], error) {
	return connect.NewResponse(&discoveryv1.GetTemplateResponse{Template: f.t}), nil
}

// evaluator answers valid or an error.
type evaluator struct {
	err  error
	sets []string
}

func (f *evaluator) Evaluate(_ context.Context, req *connect.Request[policyv1.EvaluateRequest]) (*connect.Response[policyv1.EvaluateResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	f.sets = append(f.sets, req.Msg.GetPolicySetId())
	return connect.NewResponse(&policyv1.EvaluateResponse{Verdict: policyv1.EvaluateResponse_VERDICT_VALID, Checks: []*policyv1.CheckResult{
		{Name: "nonce", CredentialIndex: -1}, {Name: "signature", CredentialIndex: 0},
	}, MaterialAge: durationpb.New(3 * time.Hour), MaterialStale: true}), nil
}

// keeper stores a result or fails.
type keeper struct {
	err  error
	kept *resultsv1.VerificationResult
}

func (f *keeper) Store(_ context.Context, req *connect.Request[resultsv1.StoreRequest]) (*connect.Response[resultsv1.StoreResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	f.kept = req.Msg.GetResult()
	f.kept.Id = "res-7"
	return connect.NewResponse(&resultsv1.StoreResponse{Result: f.kept}), nil
}

// adapter is the verifier of one stack.
type adapter struct {
	createErr error
	getErr    error
	submitErr error
	answer    *backendv1.GetResultResponse
	expires   *timestamppb.Timestamp
	created   []*backendv1.CreateRequestRequest
	submitted []*backendv1.SubmitBrowserAnswerRequest
}

func (f *adapter) SubmitBrowserAnswer(_ context.Context, req *connect.Request[backendv1.SubmitBrowserAnswerRequest]) (*connect.Response[backendv1.SubmitBrowserAnswerResponse], error) {
	if f.submitErr != nil {
		return nil, f.submitErr
	}
	f.submitted = append(f.submitted, req.Msg)
	return connect.NewResponse(&backendv1.SubmitBrowserAnswerResponse{}), nil
}

func (f *adapter) CreateRequest(_ context.Context, req *connect.Request[backendv1.CreateRequestRequest]) (*connect.Response[backendv1.CreateRequestResponse], error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.created = append(f.created, req.Msg)
	out := &backendv1.CreateRequestResponse{RequestUri: "openid4vp://stack", State: "s", ExpiresAt: f.expires}
	if req.Msg.GetDcApi() {
		out.DcApiRequest = `{"protocol":"openid4vp-v1-unsigned","data":{}}`
	}
	return connect.NewResponse(out), nil
}

func (f *adapter) GetResult(context.Context, *connect.Request[backendv1.GetResultRequest]) (*connect.Response[backendv1.GetResultResponse], error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.answer == nil {
		return connect.NewResponse(&backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_PENDING}), nil
	}
	return connect.NewResponse(f.answer), nil
}

var (
	dcqlStack = service.Stack{Pair: "verifier-credebl", Name: "DCQL stack", Adapter: "http://dcql",
		Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP_DCQL}}
	dcAPIStack = service.Stack{Pair: "verifier-waltid", Name: "DC API stack", Adapter: "http://dcapi",
		Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP_DCQL, backendv1.Protocol_PROTOCOL_DC_API},
		Features:  []backendv1.Feature{backendv1.Feature_FEATURE_DC_API_VERIFY}}
	peStack = service.Stack{Pair: "verifier-waltid", Name: "PE stack", Adapter: "http://pe",
		Protocols: []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP_PEX}}
)

// stackService wires a service with one template, the two stacks, and
// one adapter behind both.
func stackService(t *testing.T, tpl *discoveryv1.PresentationTemplate, a *adapter, pol service.Evaluator, res service.ResultStore) (*service.Service, *txn.Store) {
	t.Helper()
	return build(t, service.Options{
		Discovery: templateOf{t: tpl}, Policy: pol, Results: res, RequestTTL: time.Minute,
		Stacks: func(context.Context) []service.Stack {
			return []service.Stack{dcqlStack, peStack, {Pair: "verifier-inji"}}
		},
		StackClient: func(string) service.StackVerifier { return a },
	})
}

func licenceTemplate() *discoveryv1.PresentationTemplate {
	return &discoveryv1.PresentationTemplate{Id: "pid", Version: 4, Dcql: query, PolicySetId: "query-pid"}
}

// TestQueryForReadsTheProtocols sends DCQL to a DCQL stack, the stored
// definition of a PE query to a PE stack, and the PE form of a DCQL
// query only when it loses nothing.
func TestQueryForReadsTheProtocols(t *testing.T) {
	pe := &discoveryv1.PresentationTemplate{Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_PE, PresentationDefinition: `{"id":"x"}`}
	both := []backendv1.Protocol{backendv1.Protocol_PROTOCOL_OID4VP, backendv1.Protocol_PROTOCOL_OID4VP_DCQL, backendv1.Protocol_PROTOCOL_OID4VP_PEX}
	lossy := &discoveryv1.PresentationTemplate{Dcql: strings.Replace(query, `"format"`, `"multiple":true,"format"`, 1)}
	cases := []struct {
		name      string
		t         *discoveryv1.PresentationTemplate
		protocols []backendv1.Protocol
		dcql, pe  bool
	}{
		{"dcql to dcql", licenceTemplate(), dcqlStack.Protocols, true, false},
		{"dcql to pe", licenceTemplate(), peStack.Protocols, false, true},
		{"lossy dcql to pe", lossy, peStack.Protocols, false, false},
		{"pe to pe", pe, peStack.Protocols, false, true},
		{"pe to dcql", pe, dcqlStack.Protocols, false, false},
		{"empty pe", &discoveryv1.PresentationTemplate{Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_PE}, peStack.Protocols, false, false},
		{"bad dcql", &discoveryv1.PresentationTemplate{Dcql: "{"}, peStack.Protocols, false, false},
		// A stack with two verifiers, one per query language, gets the
		// DCQL query as written and the stored definition of a PE query.
		{"dcql to both", licenceTemplate(), both, true, false},
		{"pe to both", pe, both, false, true},
	}
	for _, c := range cases {
		d, p, ok := service.QueryFor(c.t, c.protocols)
		if (d != "") != c.dcql || (p != "") != c.pe || ok != (c.dcql || c.pe) {
			t.Errorf("%s: dcql %q pe %q ok %v", c.name, d, p, ok)
		}
	}
	if _, p, _ := service.QueryFor(&discoveryv1.PresentationTemplate{Dcql: query}, peStack.Protocols); !strings.Contains(p, `"id":"presentation-request"`) {
		t.Errorf("a query without an id: %s", p)
	}
}

// TestStackRequestLifecycle creates a request through a stack, polls a
// pending, then an accepted answer, and evaluates and stores it once.
func TestStackRequestLifecycle(t *testing.T) {
	ctx := context.Background()
	a := &adapter{expires: timestamppb.New(clock.Add(10 * time.Minute))}
	pol, res := &evaluator{}, &keeper{}
	svc, store := stackService(t, licenceTemplate(), a, pol, res)
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid", Stack: "verifier-credebl"}))
	if err != nil {
		t.Fatal(err)
	}
	if created.Msg.GetQrPayload() != "openid4vp://stack" || !created.Msg.GetExpiresAt().AsTime().Equal(clock.Add(10*time.Minute)) {
		t.Errorf("created %+v", created.Msg)
	}
	id := created.Msg.GetTransactionId()
	get := func() *ingestv1.GetTransactionResponse {
		resp, gerr := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: id}))
		if gerr != nil {
			t.Fatal(gerr)
		}
		return resp.Msg
	}
	if got := get(); got.GetState() != ingestv1.GetTransactionResponse_STATE_PENDING || got.GetStack() != "verifier-credebl" {
		t.Fatalf("pending %+v", got)
	}
	a.getErr = errors.New("down")
	if got := get(); got.GetState() != ingestv1.GetTransactionResponse_STATE_PENDING {
		t.Fatalf("a failed poll changed the state: %v", got.GetState())
	}
	a.getErr = nil
	a.answer = &backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_ACCEPTED,
		Presented: []*commonv1.Credential{{Format: commonv1.Format_FORMAT_DC_SD_JWT, Payload: []byte(answer)}},
		DpgChecks: []*backendv1.GetResultResponse_DpgCheck{{Name: "signature", Passed: false, Reason: "bad"}}}
	got := get()
	if got.GetResultId() != "res-7" || len(got.GetStackChecks()) != 1 || got.GetStackChecks()[0].GetReason() != "bad" {
		t.Fatalf("answered %+v", got)
	}
	if res.kept.GetTemplateVersion() != 4 || res.kept.GetCarrier() != service.CarrierName || len(res.kept.GetChecks()) != 1 || len(pol.sets) != 1 || pol.sets[0] != "query-pid" ||
		res.kept.GetMaterialAge().AsDuration() != 3*time.Hour || !res.kept.GetMaterialStale() {
		t.Errorf("kept %+v sets %v", res.kept, pol.sets)
	}
	record, err := store.Get(ctx, id)
	if err != nil || record.Presentation.Format != "dc+sd-jwt" {
		t.Errorf("record %+v %v", record.Presentation, err)
	}
	get()
	if len(pol.sets) != 1 {
		t.Error("a second poll evaluated again")
	}
	if res.kept.GetStack() != "DCQL stack" || len(res.kept.GetStackChecks()) != 1 || res.kept.GetStackChecks()[0].GetReason() != "bad" {
		t.Errorf("kept stack checks %+v", res.kept)
	}
	list, err := svc.ListTransactions(ctx, connect.NewRequest(&ingestv1.ListTransactionsRequest{}))
	if err != nil || list.Msg.GetTransactions()[0].GetResultId() != "res-7" || list.Msg.GetTransactions()[0].GetStack() != "verifier-credebl" ||
		list.Msg.GetTransactions()[0].GetVerdict() != commonv1.Verdict_VERDICT_VALID {
		t.Errorf("list %+v %v", list, err)
	}
}

// TestStackAnswerStates maps the expired and the rejected answers of a
// stack, and keeps the expiry of the service when the stack sets none.
func TestStackAnswerStates(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		answer *backendv1.GetResultResponse
		want   ingestv1.GetTransactionResponse_State
	}{
		"expired":  {&backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_EXPIRED}, ingestv1.GetTransactionResponse_STATE_EXPIRED},
		"rejected": {&backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_REJECTED, ReceivedAt: timestamppb.New(clock)}, ingestv1.GetTransactionResponse_STATE_REFUSED},
		"unknown":  {&backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_UNSPECIFIED}, ingestv1.GetTransactionResponse_STATE_PENDING},
	} {
		a := &adapter{answer: c.answer}
		svc, _ := stackService(t, licenceTemplate(), a, nil, nil)
		created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid", Stack: "verifier-waltid"}))
		if err != nil {
			t.Fatal(err)
		}
		if !created.Msg.GetExpiresAt().AsTime().Equal(clock.Add(time.Minute)) {
			t.Errorf("%s: expiry %v", name, created.Msg.GetExpiresAt().AsTime())
		}
		got, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: created.Msg.GetTransactionId()}))
		if err != nil || got.Msg.GetState() != c.want {
			t.Errorf("%s: %v %v", name, got.Msg.GetState(), err)
		}
	}
}

// TestStackRequestRefusals refuses a stack that is not live, a stack
// that reads no form of the query, a failed create at the adapter, and
// a PE query through the VCA verifier.
func TestStackRequestRefusals(t *testing.T) {
	ctx := context.Background()
	pe := &discoveryv1.PresentationTemplate{Id: "badge", Kind: discoveryv1.TemplateKind_TEMPLATE_KIND_PE, PresentationDefinition: `{"id":"b"}`}
	for name, c := range map[string]struct {
		tpl   *discoveryv1.PresentationTemplate
		stack string
		a     *adapter
		code  connect.Code
	}{
		"not live":     {licenceTemplate(), "verifier-other", &adapter{}, connect.CodeFailedPrecondition},
		"no adapter":   {licenceTemplate(), "verifier-inji", &adapter{}, connect.CodeFailedPrecondition},
		"no form":      {pe, "verifier-credebl", &adapter{}, connect.CodeFailedPrecondition},
		"create fails": {licenceTemplate(), "verifier-credebl", &adapter{createErr: errors.New("down")}, connect.CodeUnavailable},
		"pe via vca":   {pe, "", &adapter{}, connect.CodeFailedPrecondition},
	} {
		svc, _ := stackService(t, c.tpl, c.a, nil, nil)
		_, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: "x", Stack: c.stack}))
		if connect.CodeOf(err) != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	svc, _ := build(t, service.Options{})
	if _, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query, Stack: "verifier-credebl"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a stack without stacks: %v", err)
	}
	if _, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query, ExpiresInSeconds: -1})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("a negative expiry: %v", err)
	}
	long, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{Dcql: query, ExpiresInSeconds: 86400}))
	if err != nil || !long.Msg.GetExpiresAt().AsTime().Equal(clock.Add(service.MaxRequestTTL)) {
		t.Errorf("a long expiry is not capped: %v", err)
	}
	if _, err := service.New(service.Options{Store: &txn.Store{}, SigningKey: struct{}{}, Stacks: func(context.Context) []service.Stack { return nil }}); err == nil {
		t.Error("stacks without a client want an error")
	}
}

// TestEvaluateFailuresKeepTheAnswer keeps a direct post answer when the
// policy service or the results service fails, and names the failure.
func TestEvaluateFailuresKeepTheAnswer(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		pol  service.Evaluator
		res  service.ResultStore
		want string
	}{
		"policy fails":  {&evaluator{err: errors.New("down")}, &keeper{}, "the policy service did not evaluate the answer"},
		"results fails": {&evaluator{}, &keeper{err: errors.New("down")}, "the results service did not store the result"},
		"no results":    {&evaluator{}, nil, ""},
	} {
		svc, store := stackService(t, licenceTemplate(), &adapter{}, c.pol, c.res)
		created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid"}))
		if err != nil {
			t.Fatal(err)
		}
		record, err := store.Get(ctx, created.Msg.GetTransactionId())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{State: record.StateParam, VpToken: answer})); err != nil {
			t.Fatal(err)
		}
		got, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: record.ID}))
		if err != nil || got.Msg.GetState() != ingestv1.GetTransactionResponse_STATE_RECEIVED || got.Msg.GetResultId() != "" ||
			!strings.HasPrefix(got.Msg.GetError(), c.want) {
			t.Errorf("%s: %+v %v", name, got.Msg, err)
		}
	}
}

// TestDcApiRequestThroughAStack sends a Digital Credentials API request
// only through a stack that lists the feature, with the origin of the
// service, and hands the answer of the browser to that stack.
func TestDcApiRequestThroughAStack(t *testing.T) {
	ctx := context.Background()
	a := &adapter{}
	svc, _ := build(t, service.Options{
		Discovery: templateOf{t: licenceTemplate()}, RequestTTL: time.Minute,
		Stacks:      func(context.Context) []service.Stack { return []service.Stack{dcqlStack, dcAPIStack} },
		StackClient: func(string) service.StackVerifier { return a },
	})
	for _, stack := range []string{"", "verifier-credebl"} {
		_, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid", Stack: stack, DcApi: true}))
		if connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("DC API through %q: %v", stack, err)
		}
	}
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid", Stack: "verifier-waltid", DcApi: true}))
	if err != nil {
		t.Fatal(err)
	}
	if created.Msg.GetDcApiRequest() == "" || len(a.created) != 1 || !a.created[0].GetDcApi() || a.created[0].GetDcql() == "" {
		t.Fatalf("created %+v, the stack got %+v", created.Msg, a.created)
	}
	if got := a.created[0].GetExpectedOrigins(); len(got) != 1 || got[0] != "https://verify.example" {
		t.Errorf("origins = %v", got)
	}
	id := created.Msg.GetTransactionId()
	tx, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: id}))
	if err != nil || tx.Msg.GetDcApiRequest() != created.Msg.GetDcApiRequest() {
		t.Fatalf("transaction %+v %v", tx, err)
	}
	submit := func(id, response string) error {
		_, serr := svc.SubmitBrowserAnswer(ctx, connect.NewRequest(&ingestv1.SubmitBrowserAnswerRequest{TransactionId: id, Response: response}))
		return serr
	}
	if connect.CodeOf(submit(id, " ")) != connect.CodeInvalidArgument {
		t.Error("an empty answer was taken")
	}
	if connect.CodeOf(submit("missing", "{}")) != connect.CodeNotFound {
		t.Error("an unknown request took an answer")
	}
	a.submitErr = errors.New("down")
	if connect.CodeOf(submit(id, "{}")) != connect.CodeUnavailable {
		t.Error("a failed stack call was hidden")
	}
	a.submitErr = nil
	if serr := submit(id, `{"protocol":"p"}`); serr != nil {
		t.Fatal(serr)
	}
	if len(a.submitted) != 1 || a.submitted[0].GetState() != "s" || a.submitted[0].GetResponse() != `{"protocol":"p"}` {
		t.Errorf("the stack got %+v", a.submitted)
	}
	plain, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(&ingestv1.CreateOid4VpRequestRequest{TemplateId: "pid", Stack: "verifier-waltid"}))
	if err != nil {
		t.Fatal(err)
	}
	if connect.CodeOf(submit(plain.Msg.GetTransactionId(), "{}")) != connect.CodeFailedPrecondition {
		t.Error("a QR request took a DC API answer")
	}
}
