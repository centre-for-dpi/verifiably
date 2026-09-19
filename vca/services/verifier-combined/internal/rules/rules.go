// SPDX-License-Identifier: Apache-2.0

// Package rules holds the cross credential rules of ADR-026 decisions 2
// and 5. Each rule is a pure function over the credentials of one
// presentation, keyed by DCQL query id.
//
// The delegation rule lifts the legacy delegated access evaluator
// through core/delegation (ADR-026 decision 5).
package rules

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/delegation"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// The rule kinds this package knows.
const (
	KindSameSubject    = "SAME_SUBJECT"
	KindDelegationLink = "DELEGATION_LINK"
	KindDateOrder      = "DATE_ORDER"
)

// The parameter names of the rules.
const (
	ParamLeft        = "left"
	ParamRight       = "right"
	ParamClaim       = "claim"
	ParamSubject     = "subject"
	ParamDelegation  = "delegation"
	ParamBeforeQuery = "before_query"
	ParamBeforeClaim = "before_claim"
	ParamAfterQuery  = "after_query"
	ParamAfterClaim  = "after_claim"
	ParamAction      = "action"
	ParamFailClosed  = "fail_closed"
)

// Credential is one credential of the presentation with its query id.
type Credential struct {
	// QueryID is the DCQL query id the wallet answered.
	QueryID string
	// VC is the decoded credential.
	VC vc.Credential
}

// Rule is one cross credential rule with its parameters.
type Rule struct {
	// Kind is the rule kind.
	Kind string
	// DisplayName is the name on the summary card.
	DisplayName string
	// Params are the parameters of the rule.
	Params map[string]string
}

// Result is the outcome of one rule. It uses the outcome names of
// core/policy, so the summary card renders it like a check.
type Result struct {
	// Name is the rule kind, or the display name when the template has
	// one.
	Name string
	// Outcome is PASS, FAIL, SKIP, or ERROR.
	Outcome policy.Outcome
	// Detail says why, in Simplified Technical English.
	Detail string
	// Evidence holds what the rule looked at. It never holds a name or
	// another personal attribute.
	Evidence map[string]string
}

// Run evaluates every rule in order.
func Run(ctx context.Context, list []Rule, creds []Credential) []Result {
	byID := index(creds)
	out := make([]Result, 0, len(list))
	for _, r := range list {
		out = append(out, one(ctx, r, byID, creds))
	}
	return out
}

// one evaluates a single rule.
func one(ctx context.Context, r Rule, byID map[string]Credential, creds []Credential) Result {
	var got Result
	switch r.Kind {
	case KindSameSubject:
		got = sameSubject(r.Params, byID)
	case KindDelegationLink:
		got = delegationLink(ctx, r.Params, byID, creds)
	case KindDateOrder:
		got = dateOrder(r.Params, byID)
	default:
		got = Result{Name: r.Kind, Outcome: policy.Error, Detail: "the service does not know this rule"}
	}
	if r.DisplayName != "" {
		got.Name = r.DisplayName
	}
	return got
}

// index keys the credentials by query id. A credential without a query
// id gets its position as the key.
func index(creds []Credential) map[string]Credential {
	out := make(map[string]Credential, len(creds))
	for i, c := range creds {
		id := c.QueryID
		if id == "" {
			id = position(i)
		}
		out[id] = c
	}
	return out
}

// position returns the fallback query id of a credential.
func position(i int) string {
	return "credential-" + strconv.Itoa(i)
}

// sameSubject checks that two credentials name the same subject
// (ADR-026 decision 2).
func sameSubject(params map[string]string, byID map[string]Credential) Result {
	left, right, missing := pair(params[ParamLeft], params[ParamRight], byID)
	if missing != "" {
		return skip(KindSameSubject, missing)
	}
	claim := params[ParamClaim]
	leftValue, rightValue := subjectValue(left, claim), subjectValue(right, claim)
	ev := map[string]string{"left": params[ParamLeft], "right": params[ParamRight]}
	if claim != "" {
		ev["claim"] = claim
	}
	switch {
	case leftValue == "" || rightValue == "":
		return Result{Name: KindSameSubject, Outcome: policy.Skip, Evidence: ev,
			Detail: "a credential carries no subject identifier"}
	case leftValue == rightValue:
		return Result{Name: KindSameSubject, Outcome: policy.Pass, Evidence: ev,
			Detail: "both credentials name the same subject"}
	default:
		return Result{Name: KindSameSubject, Outcome: policy.Fail, Evidence: ev,
			Detail: "the credentials name different subjects"}
	}
}

// subjectValue returns the value the subject rule compares.
func subjectValue(c Credential, claim string) string {
	if claim == "" {
		return c.VC.SubjectID
	}
	if v := c.VC.Claims[claim]; v != "" {
		return v
	}
	if cs, ok := c.VC.Raw["credentialSubject"].(map[string]any); ok {
		if v, ok := cs[claim].(string); ok {
			return v
		}
	}
	return ""
}

// delegationLink checks that the delegation credential names the holder
// as the delegate of the subject credential (ADR-026 decisions 2 and 5).
func delegationLink(ctx context.Context, params map[string]string,
	byID map[string]Credential, creds []Credential) Result {
	subject, deleg, missing := pair(params[ParamSubject], params[ParamDelegation], byID)
	if missing != "" {
		return skip(KindDelegationLink, missing)
	}
	ev := map[string]string{"subject": params[ParamSubject], "delegation": params[ParamDelegation]}
	verdict := delegation.Evaluate(ctx, []vc.Credential{subject.VC, deleg.VC}, holderOf(creds),
		delegation.Options{RequestedAction: params[ParamAction],
			FailClosed: strings.EqualFold(params[ParamFailClosed], "true")})
	if !verdict.Evaluated {
		return Result{Name: KindDelegationLink, Outcome: policy.Skip, Evidence: ev,
			Detail: "the presentation carries no delegation credential"}
	}
	ev["linkage"] = yesNo(verdict.Linkage)
	ev["capability"] = yesNo(verdict.Capability)
	ev["invocation"] = yesNo(verdict.Invocation)
	if !verdict.Authorized {
		return Result{Name: KindDelegationLink, Outcome: policy.Fail, Evidence: ev, Detail: verdict.Reason}
	}
	return Result{Name: KindDelegationLink, Outcome: policy.Pass, Evidence: ev, Detail: verdict.Reason}
}

// holderOf returns the holder binding of the presentation, when any
// credential carries one.
func holderOf(creds []Credential) *vc.HolderBinding {
	for _, c := range creds {
		if c.VC.SubjectID != "" {
			return &vc.HolderBinding{ID: c.VC.SubjectID}
		}
	}
	return nil
}

// dateOrder checks that one date claim is not after another
// (ADR-026 decision 2).
func dateOrder(params map[string]string, byID map[string]Credential) Result {
	before, after, missing := pair(params[ParamBeforeQuery], params[ParamAfterQuery], byID)
	if missing != "" {
		return skip(KindDateOrder, missing)
	}
	ev := map[string]string{
		"before_query": params[ParamBeforeQuery], "before_claim": params[ParamBeforeClaim],
		"after_query": params[ParamAfterQuery], "after_claim": params[ParamAfterClaim],
	}
	first, firstOK := claimTime(before, params[ParamBeforeClaim])
	second, secondOK := claimTime(after, params[ParamAfterClaim])
	if !firstOK || !secondOK {
		return Result{Name: KindDateOrder, Outcome: policy.Skip, Evidence: ev,
			Detail: "a credential carries no date in the named claim"}
	}
	if first.After(second) {
		return Result{Name: KindDateOrder, Outcome: policy.Fail, Evidence: ev,
			Detail: "the first date is after the second date"}
	}
	return Result{Name: KindDateOrder, Outcome: policy.Pass, Evidence: ev,
		Detail: "the dates are in the expected order"}
}

// dateLayouts are the forms a date claim can take.
var dateLayouts = []string{time.RFC3339, "2006-01-02T15:04:05Z0700", time.DateOnly}

// claimTime reads a date claim of a credential.
func claimTime(c Credential, claim string) (time.Time, bool) {
	raw := c.VC.Claims[claim]
	if raw == "" {
		if v, ok := c.VC.Raw[claim].(string); ok {
			raw = v
		}
	}
	if raw == "" {
		if cs, ok := c.VC.Raw["credentialSubject"].(map[string]any); ok {
			if v, ok := cs[claim].(string); ok {
				raw = v
			}
		}
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// pair looks two query ids up. It returns the name of the first id that
// the presentation does not hold.
func pair(leftID, rightID string, byID map[string]Credential) (Credential, Credential, string) {
	left, ok := byID[leftID]
	if !ok {
		return Credential{}, Credential{}, leftID
	}
	right, ok := byID[rightID]
	if !ok {
		return Credential{}, Credential{}, rightID
	}
	return left, right, ""
}

// skip returns the SKIP result of a rule whose credential is absent.
func skip(kind, missing string) Result {
	name := missing
	if name == "" {
		name = "a credential"
	}
	return Result{Name: kind, Outcome: policy.Skip,
		Detail:   "the presentation has no credential for a named query",
		Evidence: map[string]string{"missing": name}}
}

// yesNo returns the text of a boolean.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

// Kinds returns the rule kinds this package knows, sorted.
func Kinds() []string {
	out := []string{KindDateOrder, KindDelegationLink, KindSameSubject}
	sort.Strings(out)
	return out
}

// Verdict folds the rule results into one outcome. A FAIL wins over an
// ERROR, and an ERROR wins over a PASS (ADR-026 decision 3).
func Verdict(list []Result) policy.Outcome {
	worst := policy.Pass
	for _, r := range list {
		switch r.Outcome {
		case policy.Fail:
			return policy.Fail
		case policy.Error:
			worst = policy.Error
		case policy.Pass, policy.Skip:
		}
	}
	return worst
}
