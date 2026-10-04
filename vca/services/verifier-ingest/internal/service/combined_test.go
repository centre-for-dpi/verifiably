// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/service"
)

// mergedQuery is the query BuildDcql of the fake answers: two
// credentials that both must come.
const mergedQuery = `{"credentials":[{"id":"subject","format":"dc+sd-jwt","meta":{"vct_values":["https://a.example/pid"]}},` +
	`{"id":"delegation","format":"dc+sd-jwt","meta":{"vct_values":["https://a.example/guardian"]}}],` +
	`"credential_sets":[{"options":[["subject","delegation"]]}]}`

// combined is the combined service of the tests.
type combined struct {
	getErr, buildErr, evalErr error
	built, evaluated          []string
	presented                 *ingestv1.RawPresentation
}

func (f *combined) Get(_ context.Context, req *connect.Request[combinedv1.GetRequest]) (*connect.Response[combinedv1.GetResponse], error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return connect.NewResponse(&combinedv1.GetResponse{Template: &combinedv1.CombinedTemplate{
		Id: req.Msg.GetId(), DisplayName: "Guardian pair", PolicySetId: "strict",
		Members: []*combinedv1.CombinedTemplate_Member{{TemplateId: "pid"}},
	}}), nil
}

func (f *combined) BuildDcql(_ context.Context, req *connect.Request[combinedv1.BuildDcqlRequest]) (*connect.Response[combinedv1.BuildDcqlResponse], error) {
	if f.buildErr != nil {
		return nil, f.buildErr
	}
	f.built = append(f.built, req.Msg.GetTemplateId())
	return connect.NewResponse(&combinedv1.BuildDcqlResponse{Dcql: mergedQuery}), nil
}

func (f *combined) EvaluateCombined(_ context.Context, req *connect.Request[combinedv1.EvaluateCombinedRequest]) (*connect.Response[combinedv1.EvaluateCombinedResponse], error) {
	if f.evalErr != nil {
		return nil, f.evalErr
	}
	f.evaluated = append(f.evaluated, req.Msg.GetTemplateId())
	f.presented = req.Msg.GetPresentation()
	return connect.NewResponse(&combinedv1.EvaluateCombinedResponse{Result: &resultsv1.VerificationResult{
		Id: "combined-res-1", Verdict: policyv1.EvaluateResponse_VERDICT_VALID,
	}}), nil
}

// combinedRequest is a request that names a combined template.
func combinedRequest(stack string) *ingestv1.CreateOid4VpRequestRequest {
	return &ingestv1.CreateOid4VpRequestRequest{TemplateId: "guardian-pair", Stack: stack,
		TemplateKind: discoveryv1.TemplateKind_TEMPLATE_KIND_COMBINED}
}

// TestACombinedRequestSendsTheMergedQueryAndEvaluatesTheCombination is
// ADR-079 decision 2: the VCA verifier asks with the query of BuildDcql,
// and the answer goes to EvaluateCombined, which stores the result.
func TestACombinedRequestSendsTheMergedQueryAndEvaluatesTheCombination(t *testing.T) {
	ctx := context.Background()
	comb, pol, res := &combined{}, &evaluator{}, &keeper{}
	svc, store := build(t, service.Options{Combined: comb, Policy: pol, Results: res, RequestTTL: time.Minute})
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(combinedRequest("")))
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(ctx, created.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	if record.DCQL != mergedQuery || record.TemplateID != "guardian-pair" || len(comb.built) != 1 || comb.built[0] != "guardian-pair" {
		t.Fatalf("the request did not carry the merged query: %+v, built %v", record, comb.built)
	}
	if _, perr := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{
		State: record.StateParam, VpToken: sdjwtSample,
	})); perr != nil {
		t.Fatal(perr)
	}
	if len(comb.evaluated) != 1 || comb.evaluated[0] != "guardian-pair" || len(comb.presented.GetCredentials()) != 1 ||
		comb.presented.GetNonce() != record.Nonce {
		t.Fatalf("EvaluateCombined got %v with %+v", comb.evaluated, comb.presented)
	}
	if len(pol.sets) != 0 || res.kept != nil {
		t.Errorf("the single policy run or its store ran too: sets %v, kept %+v", pol.sets, res.kept)
	}
	state, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: record.ID}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetResultId() != "combined-res-1" || state.Msg.GetTemplateKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_COMBINED {
		t.Errorf("state %+v", state.Msg)
	}
	list, err := svc.ListTransactions(ctx, connect.NewRequest(&ingestv1.ListTransactionsRequest{}))
	if err != nil || list.Msg.GetTransactions()[0].GetVerdict() != commonv1.Verdict_VERDICT_VALID ||
		list.Msg.GetTransactions()[0].GetTemplateKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_COMBINED {
		t.Errorf("list %+v %v", list, err)
	}
}

// TestACombinedRequestThroughAStack sends the merged query to a stack
// that reads DCQL, and evaluates the answer the stack took with
// EvaluateCombined.
func TestACombinedRequestThroughAStack(t *testing.T) {
	ctx := context.Background()
	comb, a := &combined{}, &adapter{}
	svc, _ := build(t, service.Options{
		Combined: comb, Discovery: templateOf{t: licenceTemplate()}, RequestTTL: time.Minute,
		Policy: &evaluator{}, Results: &keeper{},
		Stacks:      func(context.Context) []service.Stack { return []service.Stack{dcqlStack} },
		StackClient: func(string) service.StackVerifier { return a },
	})
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(combinedRequest(dcqlStack.Pair)))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.created) != 1 || a.created[0].GetDcql() != mergedQuery {
		t.Fatalf("the stack got %+v", a.created)
	}
	a.answer = &backendv1.GetResultResponse{State: backendv1.GetResultResponse_STATE_ACCEPTED,
		Presented: []*commonv1.Credential{{Format: commonv1.Format_FORMAT_DC_SD_JWT, Payload: []byte(answer)}}}
	state, err := svc.GetTransaction(ctx, connect.NewRequest(&ingestv1.GetTransactionRequest{TransactionId: created.Msg.GetTransactionId()}))
	if err != nil {
		t.Fatal(err)
	}
	if state.Msg.GetResultId() != "combined-res-1" || len(comb.evaluated) != 1 {
		t.Errorf("state %+v, evaluated %v", state.Msg, comb.evaluated)
	}
}

// TestACombinedRequestRefusals covers a missing combined service, a
// missing template, a failed merge, and a failed evaluation.
func TestACombinedRequestRefusals(t *testing.T) {
	ctx := context.Background()
	svc, _ := build(t, service.Options{RequestTTL: time.Minute})
	if _, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(combinedRequest(""))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("no combined service: %v", err)
	}
	for name, comb := range map[string]*combined{
		"missing": {getErr: connect.NewError(connect.CodeNotFound, errors.New("no such template"))},
		"merge":   {buildErr: errors.New("a member has no query")},
	} {
		refusing, _ := build(t, service.Options{Combined: comb, RequestTTL: time.Minute})
		if _, err := refusing.CreateOid4VpRequest(ctx, connect.NewRequest(combinedRequest(""))); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("%s: %v", name, err)
		}
	}
	comb := &combined{evalErr: errors.New("policy down")}
	svc, store := build(t, service.Options{Combined: comb, Policy: &evaluator{}, RequestTTL: time.Minute})
	created, err := svc.CreateOid4VpRequest(ctx, connect.NewRequest(combinedRequest("")))
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.Get(ctx, created.Msg.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	if _, perr := svc.ReceiveDirectPost(ctx, connect.NewRequest(&ingestv1.ReceiveDirectPostRequest{State: record.StateParam, VpToken: sdjwtSample})); perr != nil {
		t.Fatal(perr)
	}
	record, err = store.Get(ctx, record.ID)
	if err != nil || record.Error == "" || record.ResultID != "" || record.Presentation == nil {
		t.Errorf("a failed evaluation must keep the answer and name the failure: %+v %v", record, err)
	}
}
