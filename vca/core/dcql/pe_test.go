// SPDX-License-Identifier: Apache-2.0

package dcql_test

import (
	"encoding/json"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
)

func TestToPresentationExchange(t *testing.T) {
	q, err := dcql.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	pd, err := dcql.ToPresentationExchange(q, "request-1", "Prove your age")
	if err != nil {
		t.Fatal(err)
	}
	if pd.ID != "request-1" || pd.Purpose != "Prove your age" {
		t.Fatalf("definition = %+v", pd)
	}
	if len(pd.InputDescriptors) != 2 {
		t.Fatalf("descriptors = %d", len(pd.InputDescriptors))
	}
	pid := pd.InputDescriptors[0]
	if pid.ID != "pid" || pid.Constraints.LimitDisclosure != "required" {
		t.Errorf("pid descriptor = %+v", pid)
	}
	if _, ok := pid.Format[dcql.FormatSDJWT]; !ok {
		t.Errorf("pid format = %v", pid.Format)
	}
	if pid.Constraints.Fields[0].Path[0] != "$.vct" {
		t.Errorf("first field = %+v", pid.Constraints.Fields[0])
	}
	if pid.Constraints.Fields[1].Path[0] != "$.given_name" {
		t.Errorf("claim field = %+v", pid.Constraints.Fields[1])
	}
	// street sits outside the first claim set, so it is optional.
	if !pid.Constraints.Fields[2].Optional {
		t.Errorf("street must be optional, got %+v", pid.Constraints.Fields[2])
	}
	licence := pd.InputDescriptors[1]
	if licence.Constraints.Fields[1].Path[0] != "$['org.iso.18013.5.1']['portrait']" {
		t.Errorf("mdoc path = %q", licence.Constraints.Fields[1].Path[0])
	}
	if licence.Constraints.Fields[1].IntentToRetain == nil || *licence.Constraints.Fields[1].IntentToRetain {
		t.Error("an mdoc field says it does not retain the claim")
	}
	if len(pd.SubmissionRequirements) != 1 || pd.SubmissionRequirements[0].Rule != dcql.RulePick {
		t.Errorf("submission requirements = %+v", pd.SubmissionRequirements)
	}
	if pd.SubmissionRequirements[0].Count != 1 || pd.SubmissionRequirements[0].From != "group1" {
		t.Errorf("pick rule = %+v", pd.SubmissionRequirements[0])
	}
	if len(pid.Group) != 1 || pid.Group[0] != "group1" {
		t.Errorf("pid group = %v", pid.Group)
	}
}

func TestToPresentationExchangeAllRule(t *testing.T) {
	no := false
	q := dcql.Query{
		Credentials: []dcql.CredentialQuery{
			{ID: "a", Format: dcql.FormatJWTVCJSON, Meta: &dcql.Meta{TypeValues: [][]string{{"VerifiableCredential", "A"}, {"VerifiableCredential", "B"}}},
				Claims: []dcql.ClaimQuery{{Path: dcql.Path{dcql.Name("name")}, Values: []any{"x", "y"}}}},
			{ID: "b", Format: dcql.FormatLDPVC, Meta: &dcql.Meta{TypeValues: [][]string{{"VerifiableCredential", "B"}}}},
		},
		CredentialSets: []dcql.CredentialSetQuery{
			{Options: [][]string{{"a"}}, Purpose: "set purpose"},
			{Options: [][]string{{"b"}}, Required: &no},
		},
	}
	pd, err := dcql.ToPresentationExchange(q, "r", "fallback")
	if err != nil {
		t.Fatal(err)
	}
	if len(pd.SubmissionRequirements) != 1 {
		t.Fatalf("only the required set becomes a requirement, got %d", len(pd.SubmissionRequirements))
	}
	r := pd.SubmissionRequirements[0]
	if r.Rule != dcql.RuleAll || r.Purpose != "set purpose" {
		t.Errorf("requirement = %+v", r)
	}
	a := pd.InputDescriptors[0]
	if a.Constraints.LimitDisclosure != "preferred" {
		t.Errorf("a JWT VC descriptor prefers disclosure, got %q", a.Constraints.LimitDisclosure)
	}
	filter := a.Constraints.Fields[0].Filter
	if filter["type"] != "array" {
		t.Errorf("W3C type filter = %v", filter)
	}
	contains, ok := filter["contains"].(map[string]any)
	if !ok || contains["enum"] == nil {
		t.Errorf("two types become an enum filter, got %v", filter)
	}
	if a.Constraints.Fields[1].Path[0] != "$.vc.credentialSubject.name" {
		t.Errorf("claim path = %q", a.Constraints.Fields[1].Path[0])
	}
	if a.Constraints.Fields[1].Filter["enum"] == nil {
		t.Errorf("claim values become an enum filter, got %v", a.Constraints.Fields[1].Filter)
	}
	b := pd.InputDescriptors[1]
	if len(b.Constraints.Fields) != 1 {
		t.Errorf("a credential query without claims has only the type field, got %d", len(b.Constraints.Fields))
	}
}

func TestToPresentationExchangeWithoutSets(t *testing.T) {
	q := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "a", Format: dcql.FormatSDJWT}}}
	pd, err := dcql.ToPresentationExchange(q, "r", "")
	if err != nil {
		t.Fatal(err)
	}
	withSet := dcql.Query{
		Credentials:    q.Credentials,
		CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"a"}}}},
	}
	fallback, err := dcql.ToPresentationExchange(withSet, "r", "the fallback purpose")
	if err != nil {
		t.Fatal(err)
	}
	if fallback.SubmissionRequirements[0].Purpose != "the fallback purpose" {
		t.Errorf("a set without a purpose takes the query purpose, got %q", fallback.SubmissionRequirements[0].Purpose)
	}
	if len(pd.SubmissionRequirements) != 0 || len(pd.InputDescriptors[0].Group) != 0 {
		t.Errorf("a query without credential sets needs no requirement, got %+v", pd)
	}
	if len(pd.InputDescriptors[0].Constraints.Fields) != 0 {
		t.Errorf("a query without metadata and claims has no field, got %+v", pd.InputDescriptors[0].Constraints.Fields)
	}
}

func TestMarshalPresentationExchange(t *testing.T) {
	q, err := dcql.Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	data, err := dcql.MarshalPresentationExchange(q, "r", "why")
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back["id"] != "r" {
		t.Errorf("id = %v", back["id"])
	}
	if _, err := dcql.MarshalPresentationExchange(dcql.Query{}, "r", ""); err == nil {
		t.Error("an empty query wants an error")
	}
	if _, err := dcql.ToPresentationExchange(q, "", ""); err == nil {
		t.Error("an empty id wants an error")
	}
}

func TestOptionalClaimWithoutClaimSets(t *testing.T) {
	q := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "a", Format: dcql.FormatSDJWT, Meta: &dcql.Meta{VctValues: []string{"v"}},
		Claims:    []dcql.ClaimQuery{{ID: "one", Path: dcql.Path{dcql.Name("one")}}, {ID: "two", Path: dcql.Path{dcql.Name("two")}}},
		ClaimSets: [][]string{{"one"}},
	}}}
	pd, err := dcql.ToPresentationExchange(q, "r", "")
	if err != nil {
		t.Fatal(err)
	}
	fields := pd.InputDescriptors[0].Constraints.Fields
	if fields[1].Optional {
		t.Error("a claim in the first claim set is not optional")
	}
	if !fields[2].Optional {
		t.Error("a claim that no claim set names is optional")
	}
}
