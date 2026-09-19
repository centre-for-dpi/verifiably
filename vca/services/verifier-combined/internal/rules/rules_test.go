// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/delegation"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/core/vc"
)

// cred builds one credential with a query id and a raw object.
func cred(queryID string, raw map[string]any) Credential {
	return Credential{QueryID: queryID, VC: vc.FromObject(raw)}
}

func subjectCredential(id string) map[string]any {
	return map[string]any{
		"type":              []any{"VerifiableCredential", "Passport"},
		"issuer":            "did:web:issuer",
		"credentialSubject": map[string]any{"id": id, "birth_date": "1990-01-01", "national_id": "NID-1"},
	}
}

func TestSameSubjectPass(t *testing.T) {
	creds := []Credential{
		cred("a", subjectCredential("did:key:holder")),
		cred("b", subjectCredential("did:key:holder")),
	}
	got := Run(context.Background(), []Rule{{
		Kind: KindSameSubject, Params: map[string]string{ParamLeft: "a", ParamRight: "b"},
	}}, creds)
	if len(got) != 1 || got[0].Outcome != policy.Pass {
		t.Fatalf("want a pass, got %+v", got)
	}
}

func TestSameSubjectFailAndClaim(t *testing.T) {
	creds := []Credential{
		cred("a", subjectCredential("did:key:one")),
		cred("b", subjectCredential("did:key:two")),
	}
	got := sameSubject(map[string]string{ParamLeft: "a", ParamRight: "b"}, index(creds))
	if got.Outcome != policy.Fail {
		t.Fatalf("want a fail, got %+v", got)
	}
	byClaim := sameSubject(map[string]string{
		ParamLeft: "a", ParamRight: "b", ParamClaim: "national_id",
	}, index(creds))
	if byClaim.Outcome != policy.Pass || byClaim.Evidence["claim"] != "national_id" {
		t.Fatalf("want a pass on the claim, got %+v", byClaim)
	}
}

func TestSameSubjectSkips(t *testing.T) {
	creds := []Credential{cred("a", map[string]any{}), cred("b", map[string]any{})}
	got := sameSubject(map[string]string{ParamLeft: "a", ParamRight: "b"}, index(creds))
	if got.Outcome != policy.Skip {
		t.Fatalf("want a skip without a subject, got %+v", got)
	}
	missing := sameSubject(map[string]string{ParamLeft: "a", ParamRight: "z"}, index(creds))
	if missing.Outcome != policy.Skip || missing.Evidence["missing"] != "z" {
		t.Fatalf("want a skip for the missing query, got %+v", missing)
	}
	none := sameSubject(map[string]string{ParamLeft: "z"}, index(creds))
	if none.Evidence["missing"] != "z" {
		t.Fatalf("want the missing id, got %+v", none)
	}
}

func TestSubjectValueFromRaw(t *testing.T) {
	c := cred("a", map[string]any{"credentialSubject": map[string]any{"ref": "R-1"}})
	if got := subjectValue(c, "ref"); got != "R-1" {
		t.Fatalf("want the raw claim, got %q", got)
	}
	if got := subjectValue(c, "absent"); got != "" {
		t.Fatalf("want no value, got %q", got)
	}
}

func TestDelegationLink(t *testing.T) {
	ctx := context.Background()
	subject := delegation.BuildSubjectCredential(delegation.SubjectSpec{
		Issuer: "did:web:issuer", SubjectDID: "did:key:owner", SubjectRef: "urn:person:1",
	})
	deleg := delegation.BuildDelegationCredential(delegation.DelegationSpec{
		Issuer: "did:web:issuer", OnBehalfOf: "urn:person:1", DelegateID: "did:key:agent",
		AllowedAction: []string{"present"},
	})
	creds := []Credential{
		{QueryID: "subject", VC: vc.FromObject(subject)},
		{QueryID: "delegation", VC: vc.FromObject(deleg)},
	}
	got := Run(ctx, []Rule{{
		Kind: KindDelegationLink, DisplayName: "Guardian link",
		Params: map[string]string{ParamSubject: "subject", ParamDelegation: "delegation", ParamAction: "present"},
	}}, creds)
	if len(got) != 1 {
		t.Fatalf("want one result, got %d", len(got))
	}
	if got[0].Name != "Guardian link" {
		t.Fatalf("want the display name, got %q", got[0].Name)
	}
	if got[0].Outcome != policy.Pass {
		t.Fatalf("want a pass, got %+v", got[0])
	}
	if got[0].Evidence["linkage"] != "yes" {
		t.Fatalf("want the linkage evidence, got %v", got[0].Evidence)
	}
}

func TestDelegationLinkFails(t *testing.T) {
	ctx := context.Background()
	subject := delegation.BuildSubjectCredential(delegation.SubjectSpec{
		Issuer: "did:web:issuer", SubjectDID: "did:key:owner", SubjectRef: "urn:person:1",
	})
	deleg := delegation.BuildDelegationCredential(delegation.DelegationSpec{
		Issuer: "did:web:issuer", OnBehalfOf: "urn:person:other", DelegateID: "did:key:agent",
		AllowedAction: []string{"present"},
	})
	creds := []Credential{
		{QueryID: "subject", VC: vc.FromObject(subject)},
		{QueryID: "delegation", VC: vc.FromObject(deleg)},
	}
	got := delegationLink(ctx, map[string]string{
		ParamSubject: "subject", ParamDelegation: "delegation", ParamFailClosed: "true",
	}, index(creds), creds)
	if got.Outcome != policy.Fail {
		t.Fatalf("want a fail, got %+v", got)
	}
}

func TestDelegationLinkSkips(t *testing.T) {
	ctx := context.Background()
	creds := []Credential{cred("a", subjectCredential("did:key:one")), cred("b", subjectCredential("did:key:two"))}
	got := delegationLink(ctx, map[string]string{ParamSubject: "a", ParamDelegation: "b"}, index(creds), creds)
	if got.Outcome != policy.Skip {
		t.Fatalf("want a skip without a delegation credential, got %+v", got)
	}
	missing := delegationLink(ctx, map[string]string{ParamSubject: "z"}, index(creds), creds)
	if missing.Outcome != policy.Skip {
		t.Fatalf("want a skip for the missing query, got %+v", missing)
	}
}

func TestDateOrder(t *testing.T) {
	creds := []Credential{
		cred("a", map[string]any{"credentialSubject": map[string]any{"id": "x", "issued": "2026-01-01"}}),
		cred("b", map[string]any{"credentialSubject": map[string]any{"id": "x", "expires": "2026-06-01T00:00:00Z"}}),
	}
	params := map[string]string{
		ParamBeforeQuery: "a", ParamBeforeClaim: "issued",
		ParamAfterQuery: "b", ParamAfterClaim: "expires",
	}
	if got := dateOrder(params, index(creds)); got.Outcome != policy.Pass {
		t.Fatalf("want a pass, got %+v", got)
	}
	swapped := map[string]string{
		ParamBeforeQuery: "b", ParamBeforeClaim: "expires",
		ParamAfterQuery: "a", ParamAfterClaim: "issued",
	}
	if got := dateOrder(swapped, index(creds)); got.Outcome != policy.Fail {
		t.Fatalf("want a fail, got %+v", got)
	}
}

func TestDateOrderSkips(t *testing.T) {
	creds := []Credential{cred("a", map[string]any{}), cred("b", map[string]any{})}
	got := dateOrder(map[string]string{ParamBeforeQuery: "a", ParamAfterQuery: "b"}, index(creds))
	if got.Outcome != policy.Skip {
		t.Fatalf("want a skip without dates, got %+v", got)
	}
	missing := dateOrder(map[string]string{ParamBeforeQuery: "z"}, index(creds))
	if missing.Outcome != policy.Skip {
		t.Fatalf("want a skip for the missing query, got %+v", missing)
	}
}

func TestClaimTimeSources(t *testing.T) {
	top := cred("a", map[string]any{"validFrom": "2026-01-01T00:00:00Z"})
	if _, ok := claimTime(top, "validFrom"); !ok {
		t.Fatal("want the top level claim")
	}
	bad := cred("a", map[string]any{"credentialSubject": map[string]any{"when": "soon"}})
	if _, ok := claimTime(bad, "when"); ok {
		t.Fatal("want no time for text that is not a date")
	}
	if _, ok := claimTime(cred("a", map[string]any{}), "when"); ok {
		t.Fatal("want no time without the claim")
	}
}

func TestUnknownRuleAndIndex(t *testing.T) {
	got := Run(context.Background(), []Rule{{Kind: "NOPE"}}, nil)
	if len(got) != 1 || got[0].Outcome != policy.Error {
		t.Fatalf("want an error result, got %+v", got)
	}
	byID := index([]Credential{{VC: vc.FromObject(map[string]any{})}})
	if _, ok := byID["credential-0"]; !ok {
		t.Fatalf("want the fallback key, got %v", byID)
	}
}

func TestHolderOf(t *testing.T) {
	if holderOf(nil) != nil {
		t.Fatal("want no holder")
	}
	got := holderOf([]Credential{cred("a", subjectCredential("did:key:one"))})
	if got == nil || got.ID != "did:key:one" {
		t.Fatalf("unexpected holder: %+v", got)
	}
}

func TestKindsAndVerdict(t *testing.T) {
	if got := Kinds(); len(got) != 3 || got[0] != KindDateOrder {
		t.Fatalf("unexpected kinds: %v", got)
	}
	cases := []struct {
		name string
		in   []Result
		want policy.Outcome
	}{
		{"empty", nil, policy.Pass},
		{"skip only", []Result{{Outcome: policy.Skip}}, policy.Pass},
		{"error", []Result{{Outcome: policy.Error}}, policy.Error},
		{"fail wins", []Result{{Outcome: policy.Error}, {Outcome: policy.Fail}}, policy.Fail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Verdict(tc.in); got != tc.want {
				t.Fatalf("want %s, got %s", tc.want, got)
			}
		})
	}
}

func TestYesNo(t *testing.T) {
	if yesNo(true) != "yes" || yesNo(false) != "no" {
		t.Fatal("unexpected words")
	}
}
