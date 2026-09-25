// SPDX-License-Identifier: Apache-2.0

package dcql_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/dcql"
)

// TestValuesAndCredentialSetsRoundTrip builds a query with claim values,
// claim sets, and a credential set with two options, writes it, reads it
// back, and gets the same query (ADR-042 decision 2).
func TestValuesAndCredentialSetsRoundTrip(t *testing.T) {
	no := false
	q, err := dcql.BuildRequest(dcql.Request{
		Purpose: "Check the driving licence.",
		Selections: []dcql.Selection{
			{ID: "licence", Format: dcql.FormatSDJWT, Type: "https://ntsa.example/licence",
				Claims:    []string{"given_name", "family_name", "birth_date", "licence_class", "points"},
				Values:    map[string][]any{"licence_class": {"B", "C"}, "points": {float64(0), float64(1)}},
				ClaimSets: [][]string{{"given_name", "licence_class"}, {"family_name", "licence_class"}}},
			{ID: "passport", Format: dcql.FormatJWTVCJSON, Type: "Passport", Claims: []string{"valid"},
				Values: map[string][]any{"valid": {true}}},
			{ID: "extra", Format: dcql.FormatLDPVC, Type: "Residence", Claims: []string{"county"}},
		},
		Sets: []dcql.Set{
			{Options: [][]string{{"licence"}, {"passport"}}, Required: true},
			{Options: [][]string{{"extra"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := dcql.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"values":["B","C"]`, `"values":[0,1]`, `"values":[true]`,
		`"claim_sets":[["given_name","licence_class"],["family_name","licence_class"]]`,
		`"options":[["licence"],["passport"]]`, `"required":false`,
	} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the query lacks %s: %s", want, data)
		}
	}
	back, err := dcql.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, q) {
		t.Fatalf("round trip changed the query:\n%#v\n%#v", back, q)
	}
	if len(q.CredentialSets) != 2 || !q.CredentialSets[0].IsRequired() || q.CredentialSets[1].Required == nil || *q.CredentialSets[1].Required != no {
		t.Errorf("credential sets = %+v", q.CredentialSets)
	}
	if q.CredentialSets[0].Purpose != "Check the driving licence." {
		t.Errorf("a set without a purpose takes the purpose of the request")
	}
	licence, _ := q.Find("licence")
	if got := licence.Claims[3].ValueStrings(); strings.Join(got, ",") != "B,C" {
		t.Errorf("value strings = %v", got)
	}
	passport, _ := q.Find("passport")
	if got := passport.Claims[0].ValueStrings(); len(got) != 1 || got[0] != "true" {
		t.Errorf("value strings = %v", got)
	}
	if got := licence.Claims[4].ValueStrings(); strings.Join(got, ",") != "0,1" {
		t.Errorf("number value strings = %v", got)
	}
}

// TestBuildRequestErrors names each fault of a request.
func TestBuildRequestErrors(t *testing.T) {
	base := dcql.Selection{ID: "a", Format: dcql.FormatSDJWT, Type: "t", Claims: []string{"x"}}
	cases := map[string]dcql.Request{
		"no selection":        {},
		"value of no claim":   {Selections: []dcql.Selection{{ID: "a", Format: dcql.FormatSDJWT, Type: "t", Claims: []string{"x"}, Values: map[string][]any{"y": {"1"}}}}},
		"claim set bad claim": {Selections: []dcql.Selection{{ID: "a", Format: dcql.FormatSDJWT, Type: "t", Claims: []string{"x"}, ClaimSets: [][]string{{"y"}}}}},
		"broken claim":        {Selections: []dcql.Selection{{ID: "a", Format: dcql.FormatSDJWT, Type: "t", Claims: []string{"x["}}}},
		"set of unknown id":   {Selections: []dcql.Selection{base}, Sets: []dcql.Set{{Options: [][]string{{"zzz"}}}}},
		"object value":        {Selections: []dcql.Selection{{ID: "a", Format: dcql.FormatSDJWT, Type: "t", Claims: []string{"x"}, Values: map[string][]any{"x": {map[string]any{}}}}}},
	}
	for name, r := range cases {
		if _, err := dcql.BuildRequest(r); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// TestValidateRejectsUnknownSetOption refuses a set option or a claim
// set that names an unknown or a repeated id, and a claim value that is
// not a string, a whole number, or a boolean.
func TestValidateRejectsUnknownSetOption(t *testing.T) {
	cred := func() dcql.CredentialQuery {
		return dcql.CredentialQuery{ID: "a", Format: dcql.FormatSDJWT, Meta: &dcql.Meta{VctValues: []string{"t"}},
			Claims: []dcql.ClaimQuery{{ID: "x", Path: dcql.Path{dcql.Name("x")}}, {ID: "y", Path: dcql.Path{dcql.Name("y")}}}}
	}
	cases := map[string]func(q *dcql.Query){
		"unknown option":     func(q *dcql.Query) { q.CredentialSets = []dcql.CredentialSetQuery{{Options: [][]string{{"b"}}}} },
		"repeated option id": func(q *dcql.Query) { q.CredentialSets = []dcql.CredentialSetQuery{{Options: [][]string{{"a", "a"}}}} },
		"unknown claim set":  func(q *dcql.Query) { q.Credentials[0].ClaimSets = [][]string{{"z"}} },
		"repeated claim":     func(q *dcql.Query) { q.Credentials[0].ClaimSets = [][]string{{"x", "x"}} },
		"object value":       func(q *dcql.Query) { q.Credentials[0].Claims[0].Values = []any{map[string]any{"a": 1}} },
		"fraction value":     func(q *dcql.Query) { q.Credentials[0].Claims[0].Values = []any{1.5} },
		"null value":         func(q *dcql.Query) { q.Credentials[0].Claims[0].Values = []any{nil} },
		"empty value list":   func(q *dcql.Query) { q.Credentials[0].Claims[0].Values = []any{} },
	}
	for name, change := range cases {
		q := dcql.Query{Credentials: []dcql.CredentialQuery{cred()}}
		change(&q)
		if err := dcql.Validate(q); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	ok := dcql.Query{Credentials: []dcql.CredentialQuery{cred()}}
	ok.Credentials[0].Claims[0].Values = []any{"B", float64(2), true, json.Number("3")}
	if err := dcql.Validate(ok); err != nil {
		t.Errorf("scalar values: %v", err)
	}
}
