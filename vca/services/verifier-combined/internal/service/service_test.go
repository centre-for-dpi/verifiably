// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/delegation"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/combos"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/rules"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// fakePolicy answers Evaluate with a verdict per credential type.
type fakePolicy struct {
	policyv1connect.PolicyServiceClient
	verdict policyv1.EvaluateResponse_Verdict
	err     error
	calls   int
}

func (f *fakePolicy) Evaluate(_ context.Context, req *connect.Request[policyv1.EvaluateRequest]) (
	*connect.Response[policyv1.EvaluateResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	f.calls++
	if got := len(req.Msg.GetPresentation().GetCredentials()); got != 1 {
		return nil, errors.New("want one credential per call")
	}
	return connect.NewResponse(&policyv1.EvaluateResponse{
		Verdict:          f.verdict,
		EvaluatedAt:      timestamppb.New(testNow),
		PolicySetId:      "strict",
		PolicySetVersion: 2,
		Checks: []*policyv1.CheckResult{
			{Name: policy.NameSignature, Outcome: policyv1.Outcome_OUTCOME_PASS, CredentialIndex: 0},
			{Name: policy.NameTrustChain, Outcome: policyv1.Outcome_OUTCOME_PASS, CredentialIndex: 0,
				Evidence: map[string]string{"issuer_name": "Ministry"}},
		},
	}), nil
}

// fakeDiscovery answers GetTemplate from a map.
type fakeDiscovery struct {
	discoveryv1connect.DiscoveryServiceClient
	templates map[string]*discoveryv1.PresentationTemplate
	err       error
}

func (f fakeDiscovery) GetTemplate(_ context.Context, req *connect.Request[discoveryv1.GetTemplateRequest]) (
	*connect.Response[discoveryv1.GetTemplateResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	t, ok := f.templates[req.Msg.GetId()]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such template"))
	}
	return connect.NewResponse(&discoveryv1.GetTemplateResponse{Template: t}), nil
}

// fakeResults answers Store with the result and a new id.
type fakeResults struct {
	resultsv1connect.ResultsServiceClient
	err   error
	saved *resultsv1.VerificationResult
}

func (f *fakeResults) Store(_ context.Context, req *connect.Request[resultsv1.StoreRequest]) (
	*connect.Response[resultsv1.StoreResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	f.saved = req.Msg.GetResult()
	out := req.Msg.GetResult()
	out.Id = "stored-1"
	return connect.NewResponse(&resultsv1.StoreResponse{Result: out}), nil
}

// fixture holds a service and its fakes.
type fixture struct {
	svc       *Service
	policy    *fakePolicy
	results   *fakeResults
	discovery fakeDiscovery
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pol := &fakePolicy{verdict: policyv1.EvaluateResponse_VERDICT_VALID}
	res := &fakeResults{}
	disc := fakeDiscovery{templates: map[string]*discoveryv1.PresentationTemplate{
		"identity": {Id: "identity", Version: 1, Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
			QueryId: "subject", Type: "IdentityCredential",
			Format: commonv1.Format_FORMAT_LDP_VC, Claims: []string{"given_name"},
			Issuers: []string{"https://issuer.example"},
		}}},
		"guardian": {Id: "guardian", Version: 1, Queries: []*discoveryv1.PresentationTemplate_CredentialQuery{{
			QueryId: "delegation", Type: "DelegatedAccessCredential",
			Format: commonv1.Format_FORMAT_DC_SD_JWT,
		}}},
		"plain":  {Id: "plain", Dcql: `{"credentials":[{"id":"plain-0","format":"ldp_vc"}]}`},
		"broken": {Id: "broken", Dcql: "{oops"},
	}}
	svc, err := New(Options{
		Templates: combos.New(store.Memory(), nil),
		Policy:    pol,
		Discovery: disc,
		Results:   res,
		Now:       func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{svc: svc, policy: pol, results: res, discovery: disc}
}

// pair returns a combined template with two members and three rules.
func pair() *combinedv1.CombinedTemplate {
	return &combinedv1.CombinedTemplate{
		Id: "guardian-pair", DisplayName: "Guardian pair", PolicySetId: "strict",
		Members: []*combinedv1.CombinedTemplate_Member{
			{TemplateId: "identity", TemplateVersion: 1},
			{TemplateId: "guardian", TemplateVersion: 1},
		},
		Rules: []*combinedv1.CombinedTemplate_Rule{
			{Kind: combinedv1.CrossRule_CROSS_RULE_DELEGATION_LINK, DisplayName: "Guardian link",
				Params: map[string]string{rules.ParamSubject: "subject", rules.ParamDelegation: "delegation"}},
		},
	}
}

// create stores a template through the RPC.
func (f fixture) create(t *testing.T, in *combinedv1.CombinedTemplate) *combinedv1.CombinedTemplate {
	t.Helper()
	resp, err := f.svc.Create(context.Background(), connect.NewRequest(&combinedv1.CreateRequest{Template: in}))
	if err != nil {
		t.Fatal(err)
	}
	return resp.Msg.GetTemplate()
}

// presentation returns a delegated pair as a RawPresentation.
func presentation(t *testing.T, onBehalfOf string) *ingestv1.RawPresentation {
	t.Helper()
	subject := delegation.BuildSubjectCredential(delegation.SubjectSpec{
		Issuer: "did:web:issuer", SubjectDID: "did:key:owner", SubjectRef: "urn:person:1",
		Claims: map[string]string{"given_name": "Ada"},
	})
	deleg := delegation.BuildDelegationCredential(delegation.DelegationSpec{
		Issuer: "did:web:issuer", OnBehalfOf: onBehalfOf, DelegateID: "did:key:agent",
		AllowedAction: []string{"present"},
	})
	return &ingestv1.RawPresentation{
		Ref: "raw-1", Carrier: ingestv1.Carrier_CARRIER_OID4VP, Nonce: "n1",
		ReceivedAt: timestamppb.New(testNow),
		Credentials: []*commonv1.Credential{
			{Format: commonv1.Format_FORMAT_LDP_VC, Payload: jsonBytes(t, subject)},
			{Format: commonv1.Format_FORMAT_LDP_VC, Payload: jsonBytes(t, deleg)},
		},
	}
}

func jsonBytes(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNewRequiresStore(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("want an error without a store")
	}
	svc, err := New(Options{Templates: combos.New(store.Memory(), nil)})
	if err != nil || !svc.Ready() {
		t.Fatalf("want a ready service, got %v", err)
	}
}

func TestTemplateLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	created := f.create(t, pair())
	if created.GetId() != "guardian-pair" || created.GetCreatedAt() == nil {
		t.Fatalf("unexpected template: %+v", created)
	}
	got, err := f.svc.Get(ctx, connect.NewRequest(&combinedv1.GetRequest{Id: "guardian-pair"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Msg.GetTemplate().GetMembers()) != 2 {
		t.Fatalf("unexpected members: %+v", got.Msg.GetTemplate())
	}
	list, err := f.svc.List(ctx, connect.NewRequest(&combinedv1.ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetTemplates()) != 1 {
		t.Fatalf("want one template, got %d", len(list.Msg.GetTemplates()))
	}
	if _, err := f.svc.Delete(ctx, connect.NewRequest(&combinedv1.DeleteRequest{Id: "guardian-pair"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, connect.NewRequest(&combinedv1.GetRequest{Id: "guardian-pair"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestTemplateErrors(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := f.svc.Create(ctx, connect.NewRequest(&combinedv1.CreateRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an invalid argument error, got %v", err)
	}
	if _, err := f.svc.Create(ctx, connect.NewRequest(&combinedv1.CreateRequest{
		Template: &combinedv1.CombinedTemplate{Id: "empty"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an error for a template without members, got %v", err)
	}
	if _, err := f.svc.Create(ctx, connect.NewRequest(&combinedv1.CreateRequest{
		Template: &combinedv1.CombinedTemplate{Id: "bad", Members: []*combinedv1.CombinedTemplate_Member{{}}},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an error for a member without a template id, got %v", err)
	}
	if _, err := f.svc.Create(ctx, connect.NewRequest(&combinedv1.CreateRequest{
		Template: &combinedv1.CombinedTemplate{
			Id: "rule", Members: []*combinedv1.CombinedTemplate_Member{{TemplateId: "identity"}},
			Rules: []*combinedv1.CombinedTemplate_Rule{{}},
		},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an error for a rule without a kind, got %v", err)
	}
	f.create(t, pair())
	if _, err := f.svc.Create(ctx, connect.NewRequest(&combinedv1.CreateRequest{Template: pair()})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an error for a template that exists, got %v", err)
	}
	if _, err := f.svc.Get(ctx, connect.NewRequest(&combinedv1.GetRequest{Id: "bad id"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad id error, got %v", err)
	}
	if _, err := f.svc.Delete(ctx, connect.NewRequest(&combinedv1.DeleteRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
	if _, err := f.svc.Delete(ctx, connect.NewRequest(&combinedv1.DeleteRequest{Id: "bad id"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad id error, got %v", err)
	}
}

func TestListPaging(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.opts.PageSizeMax = 1
	for _, id := range []string{"a", "b"} {
		one := pair()
		one.Id = id
		f.create(t, one)
	}
	first, err := f.svc.List(ctx, connect.NewRequest(&combinedv1.ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if first.Msg.GetPage().GetNextPageToken() != "1" {
		t.Fatalf("want a next page token, got %q", first.Msg.GetPage().GetNextPageToken())
	}
	last, err := f.svc.List(ctx, connect.NewRequest(&combinedv1.ListRequest{
		Page: &commonv1.Pagination{PageToken: "1", PageSize: 10},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(last.Msg.GetTemplates()) != 1 || last.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("unexpected last page: %+v", last.Msg)
	}
	far, err := f.svc.List(ctx, connect.NewRequest(&combinedv1.ListRequest{
		Page: &commonv1.Pagination{PageToken: "9"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(far.Msg.GetTemplates()) != 0 {
		t.Fatal("want no templates past the end")
	}
	if _, err := f.svc.List(ctx, connect.NewRequest(&combinedv1.ListRequest{
		Page: &commonv1.Pagination{PageToken: "x"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad token error, got %v", err)
	}
}

func TestBuildDcql(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.create(t, pair())
	got, err := f.svc.BuildDcql(ctx, connect.NewRequest(&combinedv1.BuildDcqlRequest{TemplateId: "guardian-pair"}))
	if err != nil {
		t.Fatal(err)
	}
	raw := got.Msg.GetDcql()
	for _, want := range []string{"credential_sets", `"id":"subject"`, `"id":"delegation"`,
		"type_values", "vct_values", "trusted_authorities"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("want %q in %s", want, raw)
		}
	}
}

func TestBuildDcqlAlternatives(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	alt := pair()
	alt.Id = "either"
	alt.Members = []*combinedv1.CombinedTemplate_Member{
		{TemplateId: "identity", AlternativeGroup: "id"},
		{TemplateId: "guardian", AlternativeGroup: "id"},
	}
	f.create(t, alt)
	got, err := f.svc.BuildDcql(ctx, connect.NewRequest(&combinedv1.BuildDcqlRequest{TemplateId: "either"}))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(got.Msg.GetDcql()), &doc); err != nil {
		t.Fatal(err)
	}
	sets := doc["credential_sets"].([]any)
	if len(sets) != 1 {
		t.Fatalf("want one set, got %v", sets)
	}
	options := sets[0].(map[string]any)["options"].([]any)
	if len(options) != 2 {
		t.Fatalf("want two options, got %v", options)
	}
}

func TestBuildDcqlProblems(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := f.svc.BuildDcql(ctx, connect.NewRequest(&combinedv1.BuildDcqlRequest{
		TemplateId: "missing",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
	f.create(t, pair())
	f.svc.opts.Discovery = nil
	if _, err := f.svc.BuildDcql(ctx, connect.NewRequest(&combinedv1.BuildDcqlRequest{
		TemplateId: "guardian-pair",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want a failed precondition, got %v", err)
	}
	f.svc.opts.Discovery = fakeDiscovery{err: errors.New("offline")}
	if _, err := f.svc.BuildDcql(ctx, connect.NewRequest(&combinedv1.BuildDcqlRequest{
		TemplateId: "guardian-pair",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want a failed precondition, got %v", err)
	}
}

func TestBuildDcqlFromStoredQuery(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	plain := pair()
	plain.Id = "plain-combo"
	plain.Members = []*combinedv1.CombinedTemplate_Member{{TemplateId: "plain"}}
	plain.Rules = nil
	f.create(t, plain)
	got, err := f.svc.BuildDcql(ctx, connect.NewRequest(&combinedv1.BuildDcqlRequest{TemplateId: "plain-combo"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Msg.GetDcql(), "plain-0") {
		t.Fatalf("want the stored query, got %s", got.Msg.GetDcql())
	}

	broken := pair()
	broken.Id = "broken-combo"
	broken.Members = []*combinedv1.CombinedTemplate_Member{{TemplateId: "broken"}}
	broken.Rules = nil
	f.create(t, broken)
	if _, err := f.svc.BuildDcql(ctx, connect.NewRequest(&combinedv1.BuildDcqlRequest{
		TemplateId: "broken-combo",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want a failed precondition for a template with no query, got %v", err)
	}
}

func TestEvaluateCombinedPass(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.create(t, pair())
	got, err := f.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:1"),
		TemplateId:   "guardian-pair",
		QueryIds:     []string{"subject", "delegation"},
		At:           timestamppb.New(testNow),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if f.policy.calls != 2 {
		t.Fatalf("want one policy call per credential, got %d", f.policy.calls)
	}
	result := got.Msg.GetResult()
	if result.GetId() != "stored-1" {
		t.Fatalf("want the stored result, got %+v", result)
	}
	if result.GetVerdict() != policyv1.EvaluateResponse_VERDICT_VALID {
		t.Fatalf("want VALID, got %s", result.GetVerdict())
	}
	if len(result.GetCredentials()) != 2 {
		t.Fatalf("want one card per credential, got %d", len(result.GetCredentials()))
	}
	if result.GetCredentials()[0].GetIssuerName() != "Ministry" {
		t.Fatalf("unexpected card: %+v", result.GetCredentials()[0])
	}
	if result.GetCredentials()[1].GetRole() != RoleDelegation {
		t.Fatalf("want the delegation role, got %q", result.GetCredentials()[1].GetRole())
	}
	if len(got.Msg.GetCrossChecks()) != 1 || got.Msg.GetCrossChecks()[0].GetName() != "Guardian link" {
		t.Fatalf("unexpected cross checks: %+v", got.Msg.GetCrossChecks())
	}
	if got.Msg.GetCredentialVerdicts()["subject"] != policyv1.EvaluateResponse_VERDICT_VALID {
		t.Fatalf("unexpected per credential verdicts: %+v", got.Msg.GetCredentialVerdicts())
	}
	if result.GetPolicySetId() != "strict" || result.GetPolicySetVersion() != 2 {
		t.Fatalf("want the policy set version, got %s %d", result.GetPolicySetId(), result.GetPolicySetVersion())
	}
}

func TestEvaluateCombinedCrossRuleFails(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.create(t, pair())
	got, err := f.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:other"),
		TemplateId:   "guardian-pair",
		QueryIds:     []string{"subject", "delegation"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetResult().GetVerdict() != policyv1.EvaluateResponse_VERDICT_INVALID {
		t.Fatalf("want INVALID from the cross rule, got %s", got.Msg.GetResult().GetVerdict())
	}
}

func TestEvaluateCombinedCredentialFails(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.policy.verdict = policyv1.EvaluateResponse_VERDICT_INVALID
	f.create(t, pair())
	got, err := f.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:1"),
		TemplateId:   "guardian-pair",
		QueryIds:     []string{"subject", "delegation"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetResult().GetVerdict() != policyv1.EvaluateResponse_VERDICT_INVALID {
		t.Fatal("want a weak credential to fail the whole presentation")
	}
}

func TestEvaluateCombinedMatchesQueriesByType(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.create(t, pair())
	got, err := f.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:1"),
		TemplateId:   "guardian-pair",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Msg.GetCredentialVerdicts()["delegation"]; !ok {
		t.Fatalf("want the delegation query matched by type, got %+v", got.Msg.GetCredentialVerdicts())
	}
}

func TestEvaluateCombinedWithoutResultsClient(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.opts.Results = nil
	f.create(t, pair())
	got, err := f.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:1"),
		TemplateId:   "guardian-pair",
		QueryIds:     []string{"subject", "delegation"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetResult().GetId() != "" {
		t.Fatal("want no stored id without a results client")
	}
}

func TestEvaluateCombinedProblems(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.create(t, pair())
	if _, err := f.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		TemplateId: "guardian-pair",
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an invalid argument error, got %v", err)
	}
	if _, err := f.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:1"), TemplateId: "missing",
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}

	noPolicy := newFixture(t)
	noPolicy.svc.opts.Policy = nil
	noPolicy.create(t, pair())
	if _, err := noPolicy.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:1"), TemplateId: "guardian-pair",
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want a failed precondition, got %v", err)
	}

	brokenPolicy := newFixture(t)
	brokenPolicy.policy.err = errors.New("offline")
	brokenPolicy.create(t, pair())
	if _, err := brokenPolicy.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:1"), TemplateId: "guardian-pair",
		QueryIds: []string{"subject", "delegation"},
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want a failed precondition, got %v", err)
	}

	brokenResults := newFixture(t)
	brokenResults.results.err = errors.New("offline")
	brokenResults.create(t, pair())
	if _, err := brokenResults.svc.EvaluateCombined(ctx, connect.NewRequest(&combinedv1.EvaluateCombinedRequest{
		Presentation: presentation(t, "urn:person:1"), TemplateId: "guardian-pair",
		QueryIds: []string{"subject", "delegation"},
	})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("want a failed precondition, got %v", err)
	}
}

// brokenKV fails every list.
type brokenKV struct{ store.KeyValue }

func (brokenKV) List(context.Context, string) ([]string, error) { return nil, errors.New("broken") }

func TestListBackendError(t *testing.T) {
	svc, err := New(Options{Templates: combos.New(brokenKV{store.Memory()}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.List(context.Background(),
		connect.NewRequest(&combinedv1.ListRequest{})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
}
