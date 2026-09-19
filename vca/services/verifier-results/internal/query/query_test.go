// SPDX-License-Identifier: Apache-2.0

package query

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
)

var at = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func sample() *resultsv1.VerificationResult {
	return &resultsv1.VerificationResult{
		Id:          "one",
		Verdict:     policyv1.EvaluateResponse_VERDICT_VALID,
		EvaluatedAt: timestamppb.New(at),
		TemplateId:  "age",
		TenantId:    "t1",
		Credentials: []*resultsv1.CredentialSummary{{Issuer: "did:web:issuer"}},
	}
}

func TestMatchNilFilter(t *testing.T) {
	if !Match(nil, sample()) {
		t.Fatal("want every result to match a nil filter")
	}
}

func TestMatchFields(t *testing.T) {
	cases := []struct {
		name   string
		filter *resultsv1.Filter
		want   bool
	}{
		{"empty", &resultsv1.Filter{}, true},
		{"from before", &resultsv1.Filter{From: timestamppb.New(at.Add(-time.Hour))}, true},
		{"from after", &resultsv1.Filter{From: timestamppb.New(at.Add(time.Hour))}, false},
		{"to after", &resultsv1.Filter{To: timestamppb.New(at.Add(time.Hour))}, true},
		{"to before", &resultsv1.Filter{To: timestamppb.New(at.Add(-time.Hour))}, false},
		{"verdict match", &resultsv1.Filter{Verdict: policyv1.EvaluateResponse_VERDICT_VALID}, true},
		{"verdict other", &resultsv1.Filter{Verdict: policyv1.EvaluateResponse_VERDICT_INVALID}, false},
		{"template match", &resultsv1.Filter{TemplateId: "age"}, true},
		{"template other", &resultsv1.Filter{TemplateId: "other"}, false},
		{"tenant match", &resultsv1.Filter{TenantId: "t1"}, true},
		{"tenant other", &resultsv1.Filter{TenantId: "t2"}, false},
		{"issuer match", &resultsv1.Filter{Issuer: "did:web:issuer"}, true},
		{"issuer other", &resultsv1.Filter{Issuer: "did:web:other"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Match(tc.filter, sample()); got != tc.want {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}

func TestApply(t *testing.T) {
	other := sample()
	other.Id = "two"
	other.TemplateId = "other"
	got := Apply(&resultsv1.Filter{TemplateId: "age"}, []*resultsv1.VerificationResult{sample(), other})
	if len(got) != 1 || got[0].GetId() != "one" {
		t.Fatalf("unexpected results: %+v", got)
	}
}
