// SPDX-License-Identifier: Apache-2.0

package template_test

import (
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/policy"
	discoveryv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/template"
)

// licence is a template with values, a claim set, a date rule, and both
// trust flags (ADR-042 decisions 1 to 3).
func licence() template.Template {
	return template.Template{
		DisplayName: "Driving licence check", Purpose: "Check the licence.",
		Queries: []template.Query{{
			QueryID: "licence", Type: "https://ntsa.example/licence", Format: "dc+sd-jwt",
			Claims:    []string{"given_name", "birth_date", "licence_class"},
			Values:    []template.ClaimValues{{Path: "licence_class", Values: []string{"B", "C"}}},
			ClaimSets: [][]string{{"birth_date", "licence_class"}},
		}},
		Predicates:           []template.Predicate{{QueryID: "licence", Path: "birth_date", Op: template.OpAtLeastYears, Value: "18"}},
		RequireTrustedIssuer: true, RequireStatus: true,
	}
}

func TestBuildKeepsValuesClaimSetsAndRules(t *testing.T) {
	out, err := template.Build(licence())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"values":["B","C"]`, `"claim_sets":[["birth_date","licence_class"]]`} {
		if !strings.Contains(out.DCQL, want) {
			t.Errorf("the DCQL lacks %s: %s", want, out.DCQL)
		}
	}
	if out.Kind != template.KindDCQL {
		t.Errorf("kind = %q", out.Kind)
	}
	q := out.Queries[0]
	if len(q.Values) != 1 || q.Values[0].Path != "licence_class" || len(q.ClaimSets) != 1 {
		t.Errorf("structured view = %+v", q)
	}
	checks := out.PolicyChecks()
	names := []string{}
	for _, c := range checks {
		names = append(names, c.GetName())
		if !c.GetBlocking() {
			t.Errorf("the rule %s is not blocking", c.GetName())
		}
	}
	if strings.Join(names, ",") != strings.Join([]string{policy.NameTrustChain, policy.NameStatus, policy.NameClaimPredicate}, ",") {
		t.Fatalf("policy checks = %v", names)
	}
	p := checks[2].GetParams()
	if p["path"] != "birth_date" || p["op"] != policy.OpAtLeastYears || p["value"] != "18" || p["type"] != "https://ntsa.example/licence" {
		t.Errorf("predicate params = %v", p)
	}
	if checks[1].GetParams()["fail_mode"] != "closed" {
		t.Errorf("status params = %v", checks[1].GetParams())
	}
	if !out.HasRules() || (template.Template{}).HasRules() {
		t.Error("HasRules is wrong")
	}
	// The proto form keeps every part.
	back := template.FromProto(out.ToProto())
	if back.Kind != template.KindDCQL || len(back.Predicates) != 1 || back.Predicates[0].Op != template.OpAtLeastYears ||
		!back.RequireStatus || !back.RequireTrustedIssuer || len(back.Queries[0].Values) != 1 || len(back.Queries[0].ClaimSets) != 1 {
		t.Errorf("proto round trip = %+v", back)
	}
	if out.ToProto().GetKind() != discoveryv1.TemplateKind_TEMPLATE_KIND_DCQL {
		t.Error("the proto kind is not DCQL")
	}
}

func TestBuildRejectsBadRules(t *testing.T) {
	cases := map[string]func(t *template.Template){
		"unknown query":   func(t *template.Template) { t.Predicates[0].QueryID = "passport" },
		"claim not asked": func(t *template.Template) { t.Predicates[0].Path = "nationality" },
		"bad op":          func(t *template.Template) { t.Predicates[0].Op = "near" },
		"bad years":       func(t *template.Template) { t.Predicates[0].Value = "many" },
		"bad date":        func(t *template.Template) { t.Predicates[0].Op, t.Predicates[0].Value = template.OpBefore, "soon" },
		"value of no claim": func(t *template.Template) {
			t.Queries[0].Values = []template.ClaimValues{{Path: "points", Values: []string{"1"}}}
		},
		"pe kind": func(t *template.Template) { t.Kind = template.KindPE },
	}
	for name, change := range cases {
		tpl := licence()
		change(&tpl)
		if _, err := template.Build(tpl); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	date := licence()
	date.Predicates[0].Op, date.Predicates[0].Value = template.OpBefore, "2008-01-31"
	if _, err := template.Build(date); err != nil {
		t.Errorf("a date rule: %v", err)
	}
}

func TestPredicateOpsMapToProto(t *testing.T) {
	for _, op := range []string{template.OpBefore, template.OpAfter, template.OpAtLeastYears, template.OpAtMostYears, ""} {
		tpl := template.Template{Predicates: []template.Predicate{{Op: op}}}
		if got := template.FromProto(tpl.ToProto()).Predicates[0].Op; got != op {
			t.Errorf("op %q came back as %q", op, got)
		}
	}
	for _, k := range []string{template.KindDCQL, template.KindPE, template.KindNative, ""} {
		if got := template.FromProto(template.Template{Kind: k}.ToProto()).Kind; got != k {
			t.Errorf("kind %q came back as %q", k, got)
		}
	}
}
