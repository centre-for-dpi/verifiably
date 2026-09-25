// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// NameClaimPredicate is the check of a claim rule that DCQL cannot hold,
// for example a date range (ADR-042 decision 3).
const NameClaimPredicate = "claim_predicate"

// The operators of the claim predicate check.
const (
	// OpBefore passes when the claim date is before the value date.
	OpBefore = "before"
	// OpAfter passes when the claim date is after the value date.
	OpAfter = "after"
	// OpAtLeastYears passes when the claim date is at least value years
	// before the time of evaluation, for example an age of 18 or more.
	OpAtLeastYears = "at_least_years"
	// OpAtMostYears passes when the claim date is at most value years
	// before the time of evaluation.
	OpAtMostYears = "at_most_years"
)

// predicate is one parsed rule.
type predicate struct {
	path  string
	op    string
	value string
	kind  string
	date  time.Time
	years int
}

// evidence returns what a result shows of the rule. It never holds the
// value of the claim.
func (p predicate) evidence() map[string]string {
	ev := map[string]string{"path": p.path, "op": p.op, "value": p.value}
	if p.kind != "" {
		ev["type"] = p.kind
	}
	return ev
}

// readPredicate reads the parameters of the check.
func readPredicate(pc Context) (predicate, error) {
	p := predicate{path: pc.Param("path", ""), op: pc.Param("op", ""), value: pc.Param("value", ""), kind: pc.Param("type", "")}
	if p.path == "" {
		return p, fmt.Errorf("the rule names no claim path")
	}
	switch p.op {
	case OpBefore, OpAfter:
		d, err := parseDate(p.value)
		if err != nil {
			return p, fmt.Errorf("the rule value is not a date")
		}
		p.date = d
	case OpAtLeastYears, OpAtMostYears:
		n, err := strconv.Atoi(p.value)
		if err != nil || n < 0 {
			return p, fmt.Errorf("the rule value is not a whole number of years")
		}
		p.years = n
	default:
		return p, fmt.Errorf("the rule has the unknown operator %q", p.op)
	}
	return p, nil
}

// claimPredicate checks one claim of every credential against a rule.
// A credential outside the type of the rule, or without the claim when
// the rule names no type, does not apply. The check fails when no
// credential carries the claim.
func claimPredicate(_ context.Context, pres Presentation, pc Context) []CheckResult {
	if len(pres.Credentials) == 0 {
		return noCredentials(NameClaimPredicate)
	}
	p, err := readPredicate(pc)
	if err != nil {
		return []CheckResult{result(NameClaimPredicate, Error, WholePresentation, err.Error(), p.evidence())}
	}
	out := make([]CheckResult, 0, len(pres.Credentials))
	carried := false
	for i, c := range pres.Credentials {
		if p.kind != "" && !slices.Contains(c.VC.Types, p.kind) {
			out = append(out, result(NameClaimPredicate, Skip, i, "the credential is not of the type of the rule", p.evidence()))
			continue
		}
		raw, ok := claimAt(c.VC.Claims, p.path)
		if !ok {
			if p.kind != "" {
				carried = true
				out = append(out, result(NameClaimPredicate, Fail, i, "the credential does not carry the claim of the rule", p.evidence()))
				continue
			}
			out = append(out, result(NameClaimPredicate, Skip, i, "the credential does not carry the claim of the rule", p.evidence()))
			continue
		}
		carried = true
		out = append(out, p.judge(i, raw, pc.At()))
	}
	if !carried {
		return []CheckResult{result(NameClaimPredicate, Fail, WholePresentation, "no credential carries the claim of the rule", p.evidence())}
	}
	return out
}

// judge checks one claim value.
func (p predicate) judge(index int, raw string, at time.Time) CheckResult {
	d, err := parseDate(raw)
	if err != nil {
		return result(NameClaimPredicate, Fail, index, "the claim is not a date", p.evidence())
	}
	var ok bool
	switch p.op {
	case OpBefore:
		ok = d.Before(p.date)
	case OpAfter:
		ok = d.After(p.date)
	case OpAtLeastYears:
		ok = !day(d).After(day(at).AddDate(-p.years, 0, 0))
	default:
		ok = !day(d).Before(day(at).AddDate(-p.years, 0, 0))
	}
	if !ok {
		return result(NameClaimPredicate, Fail, index, "the claim does not meet the rule", p.evidence())
	}
	return result(NameClaimPredicate, Pass, index, "the claim meets the rule", p.evidence())
}

// day returns the start of the UTC day of t.
func day(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// parseDate reads a full date or a date and time.
func parseDate(text string) (time.Time, error) {
	text = strings.TrimSpace(text)
	for _, layout := range []string{time.DateOnly, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, text); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("policy: %q is not a date", text)
}

// claimAt returns the text of the claim at a dotted path. A top level
// claim holds a nested value as JSON, so the walk decodes it.
func claimAt(claims map[string]string, path string) (string, bool) {
	if v, ok := claims[path]; ok {
		return v, true
	}
	head, rest, nested := strings.Cut(path, ".")
	raw, ok := claims[head]
	if !nested || !ok {
		return "", false
	}
	var v any
	if json.Unmarshal([]byte(raw), &v) != nil {
		return "", false
	}
	for _, part := range strings.Split(rest, ".") {
		m, isMap := v.(map[string]any)
		if !isMap {
			return "", false
		}
		if v, ok = m[part]; !ok {
			return "", false
		}
	}
	if s, isText := v.(string); isText {
		return s, true
	}
	return fmt.Sprint(v), true
}
