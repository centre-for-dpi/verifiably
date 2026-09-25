// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// predicatePresentation holds one licence with a birth date and one
// degree without it.
func predicatePresentation(birth string) Presentation {
	return Presentation{Credentials: []Credential{
		{VC: vc.Credential{Types: []string{"VerifiableCredential", "DrivingLicence"},
			Claims: map[string]string{"birth_date": birth, "address": `{"moved_in":"2020-02-01","county":"Nyeri","floor":3}`, "points": "3", "note": "plain"}}},
		{VC: vc.Credential{Types: []string{"Degree"}, Claims: map[string]string{"degree": "BSc"}}},
	}}
}

// run evaluates the check with params at testNow.
func run(p Presentation, params map[string]string) []CheckResult {
	return claimPredicate(context.Background(), p, Context{Now: testNow, Params: params})
}

// TestClaimPredicateCheck enforces a date rule that DCQL cannot hold
// (ADR-042 decision 3): before and after a fixed date, and at least or
// at most a number of years before the evaluation time. The evidence
// names the rule, never the claim value.
func TestClaimPredicateCheck(t *testing.T) {
	check, ok := Find(NameClaimPredicate)
	if !ok || check.Mandatory || check.Params["op"] == "" {
		t.Fatalf("the check is not registered with its parameters: %+v", check)
	}
	cases := []struct {
		name   string
		birth  string
		params map[string]string
		want   []Outcome
	}{
		{"adult", "2000-01-15", map[string]string{"path": "birth_date", "op": OpAtLeastYears, "value": "18", "type": "DrivingLicence"}, []Outcome{Pass, Skip}},
		{"minor", "2010-01-15", map[string]string{"path": "birth_date", "op": OpAtLeastYears, "value": "18", "type": "DrivingLicence"}, []Outcome{Fail, Skip}},
		{"birthday today", "2008-06-01", map[string]string{"path": "birth_date", "op": OpAtLeastYears, "value": "18"}, []Outcome{Pass, Skip}},
		{"young enough", "2000-01-15", map[string]string{"path": "birth_date", "op": OpAtMostYears, "value": "30"}, []Outcome{Pass, Skip}},
		{"too old", "1980-01-15", map[string]string{"path": "birth_date", "op": OpAtMostYears, "value": "30"}, []Outcome{Fail, Skip}},
		{"before", "1999-12-31", map[string]string{"path": "birth_date", "op": OpBefore, "value": "2000-01-01"}, []Outcome{Pass, Skip}},
		{"not before", "2000-06-01", map[string]string{"path": "birth_date", "op": OpBefore, "value": "2000-01-01"}, []Outcome{Fail, Skip}},
		{"after", "2000-01-02T08:00:00Z", map[string]string{"path": "birth_date", "op": OpAfter, "value": "2000-01-01"}, []Outcome{Pass, Skip}},
		{"not after", "1999-01-02", map[string]string{"path": "birth_date", "op": OpAfter, "value": "2000-01-01"}, []Outcome{Fail, Skip}},
		{"nested", "2000-01-01", map[string]string{"path": "address.moved_in", "op": OpAfter, "value": "2019-12-31"}, []Outcome{Pass, Skip}},
		{"not a date", "soon", map[string]string{"path": "birth_date", "op": OpBefore, "value": "2000-01-01"}, []Outcome{Fail, Skip}},
		{"number claim", "1999-05-05", map[string]string{"path": "points", "op": OpBefore, "value": "2000-01-01"}, []Outcome{Fail, Skip}},
		{"wrong type", "2000-01-01", map[string]string{"path": "birth_date", "op": OpBefore, "value": "2001-01-01", "type": "Passport"}, []Outcome{Fail}},
		{"no path", "2000-01-01", map[string]string{"op": OpBefore, "value": "2001-01-01"}, []Outcome{Error}},
		{"bad op", "2000-01-01", map[string]string{"path": "birth_date", "op": "near", "value": "2001-01-01"}, []Outcome{Error}},
		{"bad date", "2000-01-01", map[string]string{"path": "birth_date", "op": OpBefore, "value": "tomorrow"}, []Outcome{Error}},
		{"bad years", "2000-01-01", map[string]string{"path": "birth_date", "op": OpAtLeastYears, "value": "-2"}, []Outcome{Error}},
		{"missing claim", "2000-01-01", map[string]string{"path": "nationality", "op": OpBefore, "value": "2001-01-01"}, []Outcome{Fail}},
		{"missing nested", "2000-01-01", map[string]string{"path": "address.street.number", "op": OpBefore, "value": "2001-01-01"}, []Outcome{Fail}},
		{"nested number", "1999-05-05", map[string]string{"path": "address.floor", "op": OpBefore, "value": "2000-01-01"}, []Outcome{Fail, Skip}},
		{"text is not an object", "1999-05-05", map[string]string{"path": "note.x", "op": OpBefore, "value": "2000-01-01"}, []Outcome{Fail}},
		{"through a text", "1999-05-05", map[string]string{"path": "address.county.code", "op": OpBefore, "value": "2000-01-01"}, []Outcome{Fail}},
		{"lacks in type", "2000-01-01", map[string]string{"path": "nationality", "op": OpBefore, "value": "2001-01-01", "type": "DrivingLicence"}, []Outcome{Fail, Skip}},
	}
	for _, tc := range cases {
		got := run(predicatePresentation(tc.birth), tc.params)
		if len(got) != len(tc.want) {
			t.Errorf("%s: %d results, want %d: %+v", tc.name, len(got), len(tc.want), got)
			continue
		}
		for i, r := range got {
			if r.Result != tc.want[i] || r.Name != NameClaimPredicate {
				t.Errorf("%s: result %d = %s %q, want %s", tc.name, i, r.Result, r.Detail, tc.want[i])
			}
			for k, v := range r.Evidence {
				if v == tc.birth {
					t.Errorf("%s: the evidence %s holds the claim value", tc.name, k)
				}
			}
		}
	}
	if got := run(Presentation{}, map[string]string{"path": "birth_date", "op": OpBefore, "value": "2000-01-01"}); len(got) != 1 || got[0].Result != Skip {
		t.Errorf("an empty presentation: %+v", got)
	}
}

// TestClaimPredicateInASet makes a blocking predicate decide the verdict.
func TestClaimPredicateInASet(t *testing.T) {
	set := Set{ID: "licence", Settings: []Setting{{Name: NameClaimPredicate, Blocking: true,
		Params: map[string]string{"path": "birth_date", "op": OpAtLeastYears, "value": "18"}}}}
	report := Evaluate(context.Background(), predicatePresentation("2012-03-04"), Context{Now: testNow}, set)
	for _, r := range report.Results {
		if r.Name == NameClaimPredicate && r.CredentialIndex == 0 && r.Result != Fail {
			t.Errorf("predicate result %s", r.Result)
		}
	}
	if report.Verdict != Invalid {
		t.Errorf("verdict %s, want invalid", report.Verdict)
	}
}
