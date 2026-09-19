// SPDX-License-Identifier: Apache-2.0

package check

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

const credentialJSON = `{"@context":["https://www.w3.org/ns/credentials/v2"],
"type":["VerifiableCredential","Passport"],"issuer":"did:web:issuer",
"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z",
"credentialSubject":{"id":"did:key:holder","given_name":"Ada"}}`

// fakePolicy answers Evaluate with a fixed response.
type fakePolicy struct {
	policyv1connect.PolicyServiceClient
	resp *policyv1.EvaluateResponse
	err  error
}

func (f fakePolicy) Evaluate(context.Context, *connect.Request[policyv1.EvaluateRequest]) (
	*connect.Response[policyv1.EvaluateResponse], error) {
	if f.err != nil {
		return nil, f.err
	}
	return connect.NewResponse(f.resp), nil
}

func response() *policyv1.EvaluateResponse {
	return &policyv1.EvaluateResponse{
		Verdict:          policyv1.EvaluateResponse_VERDICT_VALID,
		EvaluatedAt:      timestamppb.New(testNow),
		PolicySetId:      "built-in",
		PolicySetVersion: 1,
		Checks: []*policyv1.CheckResult{
			{Name: policy.NameAudience, Outcome: policyv1.Outcome_OUTCOME_SKIP, CredentialIndex: -1},
			{Name: policy.NameSignature, Outcome: policyv1.Outcome_OUTCOME_PASS, CredentialIndex: 0},
			{Name: policy.NameTrustChain, Outcome: policyv1.Outcome_OUTCOME_PASS, CredentialIndex: 0,
				Evidence: map[string]string{"issuer_name": "Ministry"}},
		},
	}
}

func TestEvaluate(t *testing.T) {
	got, err := Evaluate(context.Background(), Options{
		Client: fakePolicy{resp: response()}, Now: func() time.Time { return testNow },
	}, []byte(credentialJSON))
	if err != nil {
		t.Fatal(err)
	}
	if got.GetVerdict() != policyv1.EvaluateResponse_VERDICT_VALID {
		t.Fatalf("want VALID, got %s", got.GetVerdict())
	}
	if len(got.GetChecks()) != 1 || len(got.GetCredentials()) != 1 {
		t.Fatalf("unexpected result: %+v", got)
	}
	card := got.GetCredentials()[0]
	if card.GetType() != "Passport" || card.GetIssuer() != "did:web:issuer" {
		t.Fatalf("unexpected card: %+v", card)
	}
	if card.GetTrust() != "trusted" || card.GetIssuerName() != "Ministry" {
		t.Fatalf("want a trusted issuer with a name, got %+v", card)
	}
	if card.GetDisplayFields()["given_name"] != "Ada" {
		t.Fatalf("want the display fields, got %v", card.GetDisplayFields())
	}
	if card.GetValidity().GetValidUntil() == nil {
		t.Fatal("want the validity window")
	}
	if !strings.Contains(card.GetDecodedJson(), "Passport") {
		t.Fatal("want the decoded JSON")
	}
}

func TestEvaluateProblems(t *testing.T) {
	if _, err := Evaluate(context.Background(), Options{}, nil); err == nil {
		t.Fatal("want an error without a client")
	}
	if _, err := Evaluate(context.Background(), Options{
		Client: fakePolicy{err: errors.New("offline")},
	}, []byte(credentialJSON)); err == nil {
		t.Fatal("want the client error")
	}
}

func TestRawOfFormats(t *testing.T) {
	cases := map[string]commonv1.Format{
		credentialJSON:                commonv1.Format_FORMAT_LDP_VC,
		"eyJhIjoxfQ.eyJiIjoyfQ.c2ln":  commonv1.Format_FORMAT_JWT_VC_JSON,
		"eyJhIjoxfQ.eyJiIjoyfQ.c2ln~": commonv1.Format_FORMAT_DC_SD_JWT,
		"{}":                          commonv1.Format_FORMAT_UNSPECIFIED,
	}
	for payload, want := range cases {
		if got := RawOf([]byte(payload), testNow).GetFormat(); got != want {
			t.Fatalf("%q: want %s, got %s", payload, want, got)
		}
	}
	if got := protoFormat(vc.FormatMdoc); got != commonv1.Format_FORMAT_MSO_MDOC {
		t.Fatalf("want the mdoc format, got %s", got)
	}
}

func TestSummaryOfBrokenCredential(t *testing.T) {
	got := Summary(0, &commonv1.Credential{Payload: []byte("nope")}, nil)
	if got.GetType() != "" || got.GetTrust() != "unknown" {
		t.Fatalf("unexpected card: %+v", got)
	}
}

func TestTrustWords(t *testing.T) {
	cases := map[policyv1.Outcome]string{
		policyv1.Outcome_OUTCOME_PASS:        "trusted",
		policyv1.Outcome_OUTCOME_FAIL:        "untrusted",
		policyv1.Outcome_OUTCOME_ERROR:       "unavailable",
		policyv1.Outcome_OUTCOME_SKIP:        "unknown",
		policyv1.Outcome_OUTCOME_UNSPECIFIED: "unknown",
	}
	for in, want := range cases {
		if got := trustWord(&policyv1.CheckResult{Outcome: in}); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestDisplayFieldsCap(t *testing.T) {
	if got := displayFields(vc.Credential{}); got != nil {
		t.Fatalf("want no fields, got %v", got)
	}
	claims := map[string]string{}
	for i := 0; i < MaxDisplayFields+5; i++ {
		claims[string(rune('a'+i))] = "v"
	}
	if got := displayFields(vc.Credential{Claims: claims}); len(got) != MaxDisplayFields {
		t.Fatalf("want the cap, got %d", len(got))
	}
}

func TestValidityAndDecoded(t *testing.T) {
	if got := validity(vc.Credential{Raw: map[string]any{}}); got != nil {
		t.Fatalf("want no window, got %+v", got)
	}
	only := validity(vc.Credential{Raw: map[string]any{"validFrom": "2026-01-01T00:00:00Z"}})
	if only.GetValidFrom() == nil || only.GetValidUntil() != nil {
		t.Fatalf("want only a start, got %+v", only)
	}
	if got := decoded(vc.Credential{Raw: map[string]any{"a": make(chan int)}}); got != "" {
		t.Fatalf("want an empty string for a value that does not encode, got %q", got)
	}
}
