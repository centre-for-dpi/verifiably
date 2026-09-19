// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	ingestv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/ingest/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/sets"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// fixture holds a service and the keys of its test issuer.
type fixture struct {
	svc       *Service
	issuerKey any
	holderKey any
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	ik, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	hk, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(ik, "issuer-key")
	if err != nil {
		t.Fatal(err)
	}
	set := jose.JWKS{Keys: []jose.JWK{pub}}
	svc, err := New(Options{
		Sets: sets.New(store.Memory(), nil),
		Ports: policy.Context{
			Keys: func(context.Context, string, string) (jose.JWKS, error) { return set, nil },
			Trust: func(context.Context, string, string) (policy.Trust, error) {
				return policy.Trust{Trusted: true, DisplayName: "Ministry"}, nil
			},
		},
		Audience: "verifier",
		Now:      func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{svc: svc, issuerKey: ik, holderKey: hk}
}

// presentation builds a signed SD-JWT presentation message.
func (f fixture) presentation(t *testing.T, aud, nonce string) *ingestv1.RawPresentation {
	t.Helper()
	pubHolder, err := jose.PublicJWK(f.holderKey, "")
	if err != nil {
		t.Fatal(err)
	}
	cnf, err := jose.JWKToMap(pubHolder)
	if err != nil {
		t.Fatal(err)
	}
	payload, discs, err := sdjwt.Conceal(map[string]any{
		"iss": "did:web:issuer", "sub": "did:key:holder", "vct": "TestCredential",
		"given_name": "Ada", "cnf": map[string]any{"jwk": cnf},
	}, []string{"given_name"})
	if err != nil {
		t.Fatal(err)
	}
	issuerJWT, err := jose.Sign(f.issuerKey, "issuer-key", string(vc.FormatSDJWT), payload)
	if err != nil {
		t.Fatal(err)
	}
	p := sdjwt.Presentation{IssuerJWT: issuerJWT, Disclosures: discs}
	kb, err := sdjwt.KeyBinding(p, f.holderKey, sdjwt.DefaultAlg, aud, nonce, testNow.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	p.KeyBindingJWT = kb
	return &ingestv1.RawPresentation{
		Carrier: ingestv1.Carrier_CARRIER_OID4VP, //nolint:staticcheck // SA1019: the service still reads the old carrier value
		Nonce:   nonce,
		Credentials: []*commonv1.Credential{{
			Format: commonv1.Format_FORMAT_DC_SD_JWT, Payload: []byte(sdjwt.Serialize(p)),
		}},
	}
}

func TestNewRequiresStore(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("want an error without a store")
	}
	s, err := New(Options{Sets: sets.New(store.Memory(), nil)})
	if err != nil || !s.Ready() {
		t.Fatalf("want a ready service, got %v", err)
	}
}

func TestEvaluateValid(t *testing.T) {
	f := newFixture(t)
	resp, err := f.svc.Evaluate(context.Background(), connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: f.presentation(t, "verifier", "n1"),
		Nonce:        "n1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetVerdict() != policyv1.EvaluateResponse_VERDICT_VALID {
		t.Fatalf("want VALID, got %s: %+v", resp.Msg.GetVerdict(), resp.Msg.GetChecks())
	}
	if resp.Msg.GetPolicySetId() != BuiltInSetID {
		t.Fatalf("want the built in set, got %q", resp.Msg.GetPolicySetId())
	}
	if !resp.Msg.GetEvaluatedAt().AsTime().Equal(testNow) {
		t.Fatal("want the evaluation time")
	}
}

func TestEvaluateWrongAudience(t *testing.T) {
	f := newFixture(t)
	resp, err := f.svc.Evaluate(context.Background(), connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: f.presentation(t, "other", "n1"),
		Audience:     "verifier",
		Nonce:        "n1",
		At:           timestamppb.New(testNow),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetVerdict() != policyv1.EvaluateResponse_VERDICT_INVALID {
		t.Fatalf("want INVALID, got %s", resp.Msg.GetVerdict())
	}
}

func TestEvaluateNoPresentation(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Evaluate(context.Background(), connect.NewRequest(&policyv1.EvaluateRequest{}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an invalid argument error, got %v", err)
	}
}

func TestEvaluateWithStoredSet(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	created, err := f.svc.CreatePolicySet(ctx, connect.NewRequest(&policyv1.CreatePolicySetRequest{
		PolicySet: &policyv1.PolicySet{
			Id: "strict", DisplayName: "Strict",
			Checks: []*policyv1.PolicySet_Check{{Name: policy.NameTrustChain, Blocking: true}},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if created.Msg.GetPolicySet().GetVersion() != 1 {
		t.Fatalf("want version 1, got %d", created.Msg.GetPolicySet().GetVersion())
	}
	resp, err := f.svc.Evaluate(ctx, connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation:     f.presentation(t, "verifier", "n1"),
		PolicySetId:      "strict",
		Nonce:            "n1",
		PolicySetVersion: 1,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetPolicySetVersion() != 1 || resp.Msg.GetPolicySetId() != "strict" {
		t.Fatalf("want the stored set, got %s %d", resp.Msg.GetPolicySetId(), resp.Msg.GetPolicySetVersion())
	}
}

func TestEvaluateUnknownSet(t *testing.T) {
	f := newFixture(t)
	_, err := f.svc.Evaluate(context.Background(), connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: f.presentation(t, "verifier", "n1"),
		PolicySetId:  "missing",
	}))
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
	_, err = f.svc.Evaluate(context.Background(), connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: f.presentation(t, "verifier", "n1"),
		PolicySetId:  "bad id",
	}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error for a bad id, got %v", err)
	}
}

func TestEvaluateDefaultSetID(t *testing.T) {
	f := newFixture(t)
	f.svc.opts.DefaultSetID = BuiltInSetID
	resp, err := f.svc.Evaluate(context.Background(), connect.NewRequest(&policyv1.EvaluateRequest{
		Presentation: f.presentation(t, "verifier", "n1"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetPolicySetId() != BuiltInSetID {
		t.Fatalf("want the built in set, got %q", resp.Msg.GetPolicySetId())
	}
}

func TestListChecks(t *testing.T) {
	f := newFixture(t)
	resp, err := f.svc.ListChecks(context.Background(), connect.NewRequest(&policyv1.ListChecksRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.GetChecks()) != len(policy.Checks()) {
		t.Fatalf("want every check, got %d", len(resp.Msg.GetChecks()))
	}
}

func TestPolicySetLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := f.svc.CreatePolicySet(ctx, connect.NewRequest(&policyv1.CreatePolicySetRequest{
		PolicySet: &policyv1.PolicySet{Id: "one", TenantId: "t1"},
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.UpdatePolicySet(ctx, connect.NewRequest(&policyv1.UpdatePolicySetRequest{
		PolicySet: &policyv1.PolicySet{Id: "one", TenantId: "t1", DisplayName: "Two"},
	})); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.GetPolicySet(ctx, connect.NewRequest(&policyv1.GetPolicySetRequest{Id: "one"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Msg.GetPolicySet().GetVersion() != 2 {
		t.Fatalf("want version 2, got %d", got.Msg.GetPolicySet().GetVersion())
	}
	list, err := f.svc.ListPolicySets(ctx, connect.NewRequest(&policyv1.ListPolicySetsRequest{TenantId: "t1"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Msg.GetPolicySets()) != 1 {
		t.Fatalf("want one set, got %d", len(list.Msg.GetPolicySets()))
	}
	if _, err := f.svc.DeletePolicySet(ctx, connect.NewRequest(&policyv1.DeletePolicySetRequest{Id: "one"})); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.GetPolicySet(ctx, connect.NewRequest(&policyv1.GetPolicySetRequest{Id: "one"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestPolicySetErrors(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := f.svc.CreatePolicySet(ctx, connect.NewRequest(&policyv1.CreatePolicySetRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an invalid argument error, got %v", err)
	}
	if _, err := f.svc.CreatePolicySet(ctx, connect.NewRequest(&policyv1.CreatePolicySetRequest{
		PolicySet: &policyv1.PolicySet{Checks: []*policyv1.PolicySet_Check{{Name: "nothing"}}},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want an unknown check error, got %v", err)
	}
	if _, err := f.svc.CreatePolicySet(ctx, connect.NewRequest(&policyv1.CreatePolicySetRequest{
		PolicySet: &policyv1.PolicySet{Id: "bad id"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad id error, got %v", err)
	}
	if _, err := f.svc.UpdatePolicySet(ctx, connect.NewRequest(&policyv1.UpdatePolicySetRequest{
		PolicySet: &policyv1.PolicySet{},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a missing id error, got %v", err)
	}
	if _, err := f.svc.UpdatePolicySet(ctx, connect.NewRequest(&policyv1.UpdatePolicySetRequest{
		PolicySet: &policyv1.PolicySet{Id: "missing"},
	})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
	if _, err := f.svc.GetPolicySet(ctx, connect.NewRequest(&policyv1.GetPolicySetRequest{Id: "bad id"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad id error, got %v", err)
	}
	if _, err := f.svc.DeletePolicySet(ctx, connect.NewRequest(&policyv1.DeletePolicySetRequest{Id: "bad id"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad id error, got %v", err)
	}
	if _, err := f.svc.DeletePolicySet(ctx, connect.NewRequest(&policyv1.DeletePolicySetRequest{Id: "missing"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("want not found, got %v", err)
	}
}

func TestListPaging(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.svc.opts.PageSizeMax = 1
	for _, id := range []string{"a", "b"} {
		if _, err := f.svc.CreatePolicySet(ctx, connect.NewRequest(&policyv1.CreatePolicySetRequest{
			PolicySet: &policyv1.PolicySet{Id: id},
		})); err != nil {
			t.Fatal(err)
		}
	}
	first, err := f.svc.ListPolicySets(ctx, connect.NewRequest(&policyv1.ListPolicySetsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if first.Msg.GetPage().GetNextPageToken() != "1" {
		t.Fatalf("want a next page token, got %q", first.Msg.GetPage().GetNextPageToken())
	}
	second, err := f.svc.ListPolicySets(ctx, connect.NewRequest(&policyv1.ListPolicySetsRequest{
		Page: &commonv1.Pagination{PageToken: "1", PageSize: 10},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.GetPolicySets()) != 1 || second.Msg.GetPage().GetNextPageToken() != "" {
		t.Fatalf("want the last page, got %+v", second.Msg)
	}
	far, err := f.svc.ListPolicySets(ctx, connect.NewRequest(&policyv1.ListPolicySetsRequest{
		Page: &commonv1.Pagination{PageToken: "9"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(far.Msg.GetPolicySets()) != 0 {
		t.Fatal("want no sets past the end")
	}
	if _, err := f.svc.ListPolicySets(ctx, connect.NewRequest(&policyv1.ListPolicySetsRequest{
		Page: &commonv1.Pagination{PageToken: "x"},
	})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("want a bad token error, got %v", err)
	}
}

// brokenSets fails every list.
type brokenSets struct{ store.KeyValue }

func (brokenSets) List(context.Context, string) ([]string, error) {
	return nil, errors.New("broken")
}

func TestListBackendError(t *testing.T) {
	svc, err := New(Options{Sets: sets.New(brokenSets{store.Memory()}, nil)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListPolicySets(context.Background(),
		connect.NewRequest(&policyv1.ListPolicySetsRequest{})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
	if _, err := svc.GetPolicySet(context.Background(),
		connect.NewRequest(&policyv1.GetPolicySetRequest{Id: "a"})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
	if _, err := svc.DeletePolicySet(context.Background(),
		connect.NewRequest(&policyv1.DeletePolicySetRequest{Id: "a"})); connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
}
