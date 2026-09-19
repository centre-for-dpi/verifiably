// SPDX-License-Identifier: Apache-2.0

package service

import (
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/rules"
)

func TestFormatName(t *testing.T) {
	cases := map[commonv1.Format]string{
		commonv1.Format_FORMAT_VC_SD_JWT:   "vc+sd-jwt",
		commonv1.Format_FORMAT_DC_SD_JWT:   "dc+sd-jwt",
		commonv1.Format_FORMAT_JWT_VC_JSON: "jwt_vc_json",
		commonv1.Format_FORMAT_LDP_VC:      "ldp_vc",
		commonv1.Format_FORMAT_LDP_VC_BBS:  "ldp_vc",
		commonv1.Format_FORMAT_MSO_MDOC:    "mso_mdoc",
		commonv1.Format_FORMAT_UNSPECIFIED: "dc+sd-jwt",
	}
	for in, want := range cases {
		if got := formatName(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestCoreFormat(t *testing.T) {
	cases := map[commonv1.Format]vc.Format{
		commonv1.Format_FORMAT_VC_SD_JWT:   vc.FormatSDJWT,
		commonv1.Format_FORMAT_DC_SD_JWT:   vc.FormatSDJWT,
		commonv1.Format_FORMAT_JWT_VC_JSON: vc.FormatJWT,
		commonv1.Format_FORMAT_LDP_VC:      vc.FormatJSONLD,
		commonv1.Format_FORMAT_LDP_VC_BBS:  vc.FormatJSONLD,
		commonv1.Format_FORMAT_MSO_MDOC:    vc.FormatMdoc,
		commonv1.Format_FORMAT_UNSPECIFIED: vc.FormatUnknown,
	}
	for in, want := range cases {
		if got := coreFormat(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestToDcqlCredential(t *testing.T) {
	sd := toDcqlCredential(&discoveryv1.PresentationTemplate_CredentialQuery{
		QueryId: "a", Type: "Passport", Format: commonv1.Format_FORMAT_DC_SD_JWT,
		Claims: []string{"given_name"},
	})
	if len(sd.Meta.VctValues) != 1 || len(sd.Claims) != 1 {
		t.Fatalf("unexpected SD-JWT query: %+v", sd)
	}
	ldp := toDcqlCredential(&discoveryv1.PresentationTemplate_CredentialQuery{
		QueryId: "b", Type: "Passport", Format: commonv1.Format_FORMAT_LDP_VC,
		Issuers: []string{"https://issuer.example"},
	})
	if len(ldp.Meta.TypeValues) != 1 || len(ldp.TrustedAuthorities) != 1 {
		t.Fatalf("unexpected JSON-LD query: %+v", ldp)
	}
	plain := toDcqlCredential(&discoveryv1.PresentationTemplate_CredentialQuery{QueryId: "c"})
	if plain.Meta != nil {
		t.Fatalf("want no meta without a type, got %+v", plain.Meta)
	}
	if !isSDJWT(commonv1.Format_FORMAT_VC_SD_JWT) || isSDJWT(commonv1.Format_FORMAT_LDP_VC) {
		t.Fatal("unexpected SD-JWT test")
	}
}

func TestKindName(t *testing.T) {
	cases := map[combinedv1.CrossRule]string{
		combinedv1.CrossRule_CROSS_RULE_SAME_SUBJECT:    rules.KindSameSubject,
		combinedv1.CrossRule_CROSS_RULE_DELEGATION_LINK: rules.KindDelegationLink,
		combinedv1.CrossRule_CROSS_RULE_DATE_ORDER:      rules.KindDateOrder,
		combinedv1.CrossRule_CROSS_RULE_UNSPECIFIED:     "UNSPECIFIED",
	}
	for in, want := range cases {
		if got := kindName(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestToRulesAndCheckResults(t *testing.T) {
	mapped := toRules(&combinedv1.CombinedTemplate{Rules: []*combinedv1.CombinedTemplate_Rule{{
		Kind: combinedv1.CrossRule_CROSS_RULE_SAME_SUBJECT, DisplayName: "Same person",
		Params: map[string]string{rules.ParamLeft: "a"},
	}}})
	if len(mapped) != 1 || mapped[0].Kind != rules.KindSameSubject || mapped[0].DisplayName != "Same person" {
		t.Fatalf("unexpected rules: %+v", mapped)
	}
	checks := toCheckResults([]rules.Result{{
		Name: "Same person", Outcome: policy.Fail, Detail: "different subjects",
		Evidence: map[string]string{"left": "a"},
	}})
	if len(checks) != 1 || checks[0].GetCredentialIndex() != -1 {
		t.Fatalf("unexpected checks: %+v", checks)
	}
	if checks[0].GetOutcome() != policyv1.Outcome_OUTCOME_FAIL {
		t.Fatalf("unexpected outcome: %s", checks[0].GetOutcome())
	}
}

func TestOutcomeOf(t *testing.T) {
	cases := map[policy.Outcome]policyv1.Outcome{
		policy.Pass:             policyv1.Outcome_OUTCOME_PASS,
		policy.Fail:             policyv1.Outcome_OUTCOME_FAIL,
		policy.Skip:             policyv1.Outcome_OUTCOME_SKIP,
		policy.Error:            policyv1.Outcome_OUTCOME_ERROR,
		policy.Outcome("other"): policyv1.Outcome_OUTCOME_UNSPECIFIED,
	}
	for in, want := range cases {
		if got := outcomeOf(in); got != want {
			t.Fatalf("%s: want %s, got %s", in, want, got)
		}
	}
}

func TestSummaryOfBrokenCredential(t *testing.T) {
	got := summary("q1", "", &commonv1.Credential{Payload: []byte("nope")}, nil)
	if got.GetType() != "" || got.GetTrust() != "unknown" {
		t.Fatalf("unexpected card: %+v", got)
	}
	if got := summary("", "holder", &commonv1.Credential{Payload: []byte("nope")}, nil); got.GetRole() != "holder" {
		t.Fatalf("unexpected card: %+v", got)
	}
}

func TestWorstVerdict(t *testing.T) {
	cases := []struct {
		name     string
		verdicts []policyv1.EvaluateResponse_Verdict
		cross    policy.Outcome
		want     policyv1.EvaluateResponse_Verdict
	}{
		{"all valid", []policyv1.EvaluateResponse_Verdict{policyv1.EvaluateResponse_VERDICT_VALID},
			policy.Pass, policyv1.EvaluateResponse_VERDICT_VALID},
		{"one invalid", []policyv1.EvaluateResponse_Verdict{policyv1.EvaluateResponse_VERDICT_INVALID},
			policy.Pass, policyv1.EvaluateResponse_VERDICT_INVALID},
		{"one indeterminate", []policyv1.EvaluateResponse_Verdict{policyv1.EvaluateResponse_VERDICT_INDETERMINATE},
			policy.Pass, policyv1.EvaluateResponse_VERDICT_INDETERMINATE},
		{"unspecified", []policyv1.EvaluateResponse_Verdict{policyv1.EvaluateResponse_VERDICT_UNSPECIFIED},
			policy.Pass, policyv1.EvaluateResponse_VERDICT_INDETERMINATE},
		{"cross fail", []policyv1.EvaluateResponse_Verdict{policyv1.EvaluateResponse_VERDICT_VALID},
			policy.Fail, policyv1.EvaluateResponse_VERDICT_INVALID},
		{"cross error", []policyv1.EvaluateResponse_Verdict{policyv1.EvaluateResponse_VERDICT_VALID},
			policy.Error, policyv1.EvaluateResponse_VERDICT_INDETERMINATE},
		{"cross skip", nil, policy.Skip, policyv1.EvaluateResponse_VERDICT_VALID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := worst(tc.verdicts, tc.cross); got != tc.want {
				t.Fatalf("want %s, got %s", tc.want, got)
			}
		})
	}
}

func TestTypeMatchesAndRole(t *testing.T) {
	parsed := vc.Credential{Types: []string{"VerifiableCredential", "Passport"}}
	if typeMatches(parsed, "") || typeMatches(parsed, "VerifiableCredential") {
		t.Fatal("want no match on the base type")
	}
	if !typeMatches(parsed, "passport") {
		t.Fatal("want a case insensitive match")
	}
	if got := roleOf(vc.Credential{}); got != "" {
		t.Fatalf("want no role, got %q", got)
	}
	if got := roleOf(vc.Credential{SubjectID: "did:key:a"}); got != RoleSubject {
		t.Fatalf("want the subject role, got %q", got)
	}
}
