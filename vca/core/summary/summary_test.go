// SPDX-License-Identifier: Apache-2.0

package summary_test

import (
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/summary"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
)

const sampleVCDoc = `{"@context":["https://www.w3.org/ns/credentials/v2"],
"type":["VerifiableCredential","Passport"],"issuer":"did:web:issuer",
"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z",
"credentialSubject":{"id":"did:key:holder","given_name":"Ada"}}`

func credential() *commonv1.Credential {
	return &commonv1.Credential{
		Format:  commonv1.Format_FORMAT_LDP_VC,
		Payload: []byte(sampleVCDoc),
	}
}

func checks() []*policyv1.CheckResult {
	return []*policyv1.CheckResult{
		{Name: policy.NameAudience, Outcome: policyv1.Outcome_OUTCOME_SKIP, CredentialIndex: -1},
		{Name: policy.NameSignature, Outcome: policyv1.Outcome_OUTCOME_PASS, CredentialIndex: 0},
		{Name: policy.NameTrustChain, Outcome: policyv1.Outcome_OUTCOME_PASS, CredentialIndex: 0,
			Evidence: map[string]string{"issuer_name": "Ministry"}},
		{Name: policy.NameSignature, Outcome: policyv1.Outcome_OUTCOME_FAIL, CredentialIndex: 1},
	}
}

func TestBuildByIndex(t *testing.T) {
	card := summary.Build(credential(), checks(), summary.Options{Index: 0})
	if card.GetType() != "Passport" || card.GetTitle() != "Passport" || card.GetIssuer() != "did:web:issuer" {
		t.Fatalf("card = %+v", card)
	}
	if card.GetTrust() != summary.TrustTrusted || card.GetIssuerName() != "Ministry" {
		t.Fatalf("trust = %+v", card)
	}
	if len(card.GetChecks()) != 2 {
		t.Fatalf("checks = %d", len(card.GetChecks()))
	}
	if card.GetDisplayFields()["given_name"] != "Ada" {
		t.Fatalf("fields = %v", card.GetDisplayFields())
	}
	if card.GetValidity().GetValidFrom() == nil || card.GetValidity().GetValidUntil() == nil {
		t.Fatalf("validity = %+v", card.GetValidity())
	}
	if !strings.Contains(card.GetDecodedJson(), "Passport") {
		t.Fatal("want the decoded JSON")
	}
	if card.GetRole() != "" {
		t.Fatalf("role = %q", card.GetRole())
	}
}

func TestBuildEveryCheck(t *testing.T) {
	card := summary.Build(credential(), checks(), summary.Options{Index: -1, Role: "holder"})
	if len(card.GetChecks()) != 4 || card.GetRole() != "holder" {
		t.Fatalf("card = %+v", card)
	}
}

func TestBuildBrokenCredential(t *testing.T) {
	card := summary.Build(&commonv1.Credential{Payload: []byte("nope")}, nil, summary.Options{Index: 0})
	if card.GetType() != "" || card.GetTitle() != "" || card.GetTrust() != summary.TrustUnknown {
		t.Fatalf("card = %+v", card)
	}
}

func TestTitleFallback(t *testing.T) {
	if got := summary.Title(vc.Credential{}, "Credential"); got != "Credential" {
		t.Fatalf("title = %q", got)
	}
	if got := summary.Title(vc.Credential{Types: []string{"VerifiableCredential", "Passport"}}, "x"); got != "Passport" {
		t.Fatalf("title = %q", got)
	}
}

func TestTrustWord(t *testing.T) {
	cases := map[policyv1.Outcome]string{
		policyv1.Outcome_OUTCOME_PASS:        summary.TrustTrusted,
		policyv1.Outcome_OUTCOME_FAIL:        summary.TrustUntrusted,
		policyv1.Outcome_OUTCOME_ERROR:       summary.TrustUnavailable,
		policyv1.Outcome_OUTCOME_SKIP:        summary.TrustUnknown,
		policyv1.Outcome_OUTCOME_UNSPECIFIED: summary.TrustUnknown,
	}
	for in, want := range cases {
		if got := summary.TrustWord(&policyv1.CheckResult{Outcome: in}); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestDisplayFieldsCap(t *testing.T) {
	if got := summary.DisplayFields(vc.Credential{}); got != nil {
		t.Fatalf("fields = %v", got)
	}
	claims := map[string]string{}
	for i := 0; i < summary.MaxDisplayFields+5; i++ {
		claims[string(rune('a'+i))] = "v"
	}
	if got := summary.DisplayFields(vc.Credential{Claims: claims}); len(got) != summary.MaxDisplayFields {
		t.Fatalf("cap = %d", len(got))
	}
}

func TestValidityAndDecoded(t *testing.T) {
	if got := summary.Validity(vc.Credential{Raw: map[string]any{}}); got != nil {
		t.Fatalf("window = %+v", got)
	}
	only := summary.Validity(vc.Credential{Raw: map[string]any{"validFrom": "2026-01-01T00:00:00Z"}})
	if only.GetValidFrom() == nil || only.GetValidUntil() != nil {
		t.Fatalf("window = %+v", only)
	}
	until := summary.Validity(vc.Credential{Raw: map[string]any{"validUntil": "2027-01-01T00:00:00Z"}})
	if until.GetValidFrom() != nil || until.GetValidUntil() == nil {
		t.Fatalf("window = %+v", until)
	}
	if got := summary.Decoded(vc.Credential{Raw: map[string]any{"a": make(chan int)}}); got != "" {
		t.Fatalf("decoded = %q", got)
	}
}
