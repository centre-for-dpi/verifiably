// SPDX-License-Identifier: Apache-2.0

package service

import (
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	summarypkg "github.com/centre-for-dpi/vc-adapters/core/summary"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
	combinedv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/dcql"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/rules"
)

// formatName maps a proto format to the DCQL format identifier.
func formatName(f commonv1.Format) string {
	switch f {
	case commonv1.Format_FORMAT_VC_SD_JWT:
		return "vc+sd-jwt"
	case commonv1.Format_FORMAT_DC_SD_JWT:
		return "dc+sd-jwt"
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return "jwt_vc_json"
	case commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_LDP_VC_BBS:
		return "ldp_vc"
	case commonv1.Format_FORMAT_MSO_MDOC:
		return "mso_mdoc"
	case commonv1.Format_FORMAT_UNSPECIFIED:
	}
	return "dc+sd-jwt"
}

// coreFormat maps a proto format to the core format.
func coreFormat(f commonv1.Format) vc.Format {
	switch f {
	case commonv1.Format_FORMAT_VC_SD_JWT, commonv1.Format_FORMAT_DC_SD_JWT:
		return vc.FormatSDJWT
	case commonv1.Format_FORMAT_JWT_VC_JSON:
		return vc.FormatJWT
	case commonv1.Format_FORMAT_LDP_VC, commonv1.Format_FORMAT_LDP_VC_BBS:
		return vc.FormatJSONLD
	case commonv1.Format_FORMAT_MSO_MDOC:
		return vc.FormatMdoc
	case commonv1.Format_FORMAT_UNSPECIFIED:
	}
	return vc.FormatUnknown
}

// isSDJWT reports whether the format is an SD-JWT VC.
func isSDJWT(f commonv1.Format) bool {
	return f == commonv1.Format_FORMAT_VC_SD_JWT || f == commonv1.Format_FORMAT_DC_SD_JWT
}

// toDcqlCredential maps one discovery credential query to DCQL.
func toDcqlCredential(q *discoveryv1.PresentationTemplate_CredentialQuery) dcql.Credential {
	out := dcql.Credential{ID: q.GetQueryId(), Format: formatName(q.GetFormat())}
	if t := q.GetType(); t != "" {
		if isSDJWT(q.GetFormat()) || q.GetFormat() == commonv1.Format_FORMAT_UNSPECIFIED {
			out.Meta = &dcql.Meta{VctValues: []string{t}}
		} else {
			out.Meta = &dcql.Meta{TypeValues: [][]string{{"VerifiableCredential", t}}}
		}
	}
	for _, claim := range q.GetClaims() {
		out.Claims = append(out.Claims, dcql.Claim{Path: []string{claim}})
	}
	if issuers := q.GetIssuers(); len(issuers) > 0 {
		out.TrustedAuthorities = []dcql.Authority{{Type: "openid_federation", Values: issuers}}
	}
	return out
}

// toRules maps the rules of a combined template to the pure rule type.
func toRules(t *combinedv1.CombinedTemplate) []rules.Rule {
	out := make([]rules.Rule, 0, len(t.GetRules()))
	for _, r := range t.GetRules() {
		out = append(out, rules.Rule{
			Kind: kindName(r.GetKind()), DisplayName: r.GetDisplayName(), Params: r.GetParams(),
		})
	}
	return out
}

// kindName maps a proto rule kind to the pure rule kind.
func kindName(k combinedv1.CrossRule) string {
	switch k {
	case combinedv1.CrossRule_CROSS_RULE_SAME_SUBJECT:
		return rules.KindSameSubject
	case combinedv1.CrossRule_CROSS_RULE_DELEGATION_LINK:
		return rules.KindDelegationLink
	case combinedv1.CrossRule_CROSS_RULE_DATE_ORDER:
		return rules.KindDateOrder
	case combinedv1.CrossRule_CROSS_RULE_UNSPECIFIED:
	}
	return "UNSPECIFIED"
}

// toCheckResults maps the rule results to check results, so the summary
// card of the results service renders them (ADR-026 decision 4).
func toCheckResults(list []rules.Result) []*policyv1.CheckResult {
	out := make([]*policyv1.CheckResult, 0, len(list))
	for _, r := range list {
		out = append(out, &policyv1.CheckResult{
			Name: r.Name, Outcome: outcomeOf(r.Outcome), Detail: r.Detail,
			Evidence: r.Evidence, CredentialIndex: -1,
		})
	}
	return out
}

// outcomeOf maps a core outcome to proto.
func outcomeOf(o policy.Outcome) policyv1.Outcome {
	switch o {
	case policy.Pass:
		return policyv1.Outcome_OUTCOME_PASS
	case policy.Fail:
		return policyv1.Outcome_OUTCOME_FAIL
	case policy.Skip:
		return policyv1.Outcome_OUTCOME_SKIP
	case policy.Error:
		return policyv1.Outcome_OUTCOME_ERROR
	}
	return policyv1.Outcome_OUTCOME_UNSPECIFIED
}

// summary builds the card of one credential.
func summary(queryID, role string, cred *commonv1.Credential, resp *policyv1.EvaluateResponse) *resultsv1.CredentialSummary {
	fallback := queryID
	if fallback == "" {
		fallback = "Credential"
	}
	return summarypkg.Build(cred, resp.GetChecks(), summarypkg.Options{
		Index: -1, Role: role, FallbackTitle: fallback,
	})
}

// worst folds the per credential verdicts and the cross rule outcome
// into one verdict (ADR-026 decision 3).
func worst(verdicts []policyv1.EvaluateResponse_Verdict, cross policy.Outcome) policyv1.EvaluateResponse_Verdict {
	out := policyv1.EvaluateResponse_VERDICT_VALID
	for _, v := range verdicts {
		switch v {
		case policyv1.EvaluateResponse_VERDICT_INVALID:
			return policyv1.EvaluateResponse_VERDICT_INVALID
		case policyv1.EvaluateResponse_VERDICT_INDETERMINATE, policyv1.EvaluateResponse_VERDICT_UNSPECIFIED:
			out = policyv1.EvaluateResponse_VERDICT_INDETERMINATE
		case policyv1.EvaluateResponse_VERDICT_VALID:
		}
	}
	switch cross {
	case policy.Fail:
		return policyv1.EvaluateResponse_VERDICT_INVALID
	case policy.Error:
		return policyv1.EvaluateResponse_VERDICT_INDETERMINATE
	case policy.Pass, policy.Skip:
	}
	return out
}
