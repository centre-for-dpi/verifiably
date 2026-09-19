// SPDX-License-Identifier: Apache-2.0

package dcql

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func query(id string) Credential {
	return Credential{
		ID: id, Format: "dc+sd-jwt",
		Meta:   &Meta{VctValues: []string{"Passport"}},
		Claims: []Claim{{Path: []string{"given_name"}}},
	}
}

func TestBuildMandatoryMembers(t *testing.T) {
	got, err := Build([]Member{
		{Queries: []Credential{query("a")}},
		{Queries: []Credential{query("b")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Credentials) != 2 || len(got.CredentialSets) != 2 {
		t.Fatalf("want two queries in two sets, got %+v", got)
	}
	for _, set := range got.CredentialSets {
		if len(set.Options) != 1 || !set.Required {
			t.Fatalf("want one required option, got %+v", set)
		}
	}
}

func TestBuildAlternatives(t *testing.T) {
	got, err := Build([]Member{
		{Group: "identity", Queries: []Credential{query("passport")}},
		{Group: "identity", Queries: []Credential{query("licence")}},
		{Queries: []Credential{query("proof")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CredentialSets) != 2 {
		t.Fatalf("want two sets, got %+v", got.CredentialSets)
	}
	if len(got.CredentialSets[0].Options) != 2 {
		t.Fatalf("want two options in the alternative set, got %+v", got.CredentialSets[0])
	}
	if got.CredentialSets[0].Options[0][0] != "passport" {
		t.Fatalf("want the first option first, got %+v", got.CredentialSets[0].Options)
	}
}

func TestBuildProblems(t *testing.T) {
	if _, err := Build(nil); !errors.Is(err, ErrNoQuery) {
		t.Fatalf("want the empty error, got %v", err)
	}
	if _, err := Build([]Member{{Queries: []Credential{{}}}}); err == nil {
		t.Fatal("want an error for a query without an id")
	}
	if _, err := Build([]Member{
		{Queries: []Credential{query("a")}}, {Queries: []Credential{query("a")}},
	}); err == nil {
		t.Fatal("want an error for a repeated id")
	}
	if _, err := Build([]Member{{Group: "g"}}); !errors.Is(err, ErrNoQuery) {
		t.Fatalf("want the empty error for a member without a query, got %v", err)
	}
}

func TestJSONShape(t *testing.T) {
	built, err := Build([]Member{{Group: "g", Queries: []Credential{query("a")}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := built.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	creds, ok := doc["credentials"].([]any)
	if !ok || len(creds) != 1 {
		t.Fatalf("want one credential, got %v", doc["credentials"])
	}
	first := creds[0].(map[string]any)
	if first["format"] != "dc+sd-jwt" || first["id"] != "a" {
		t.Fatalf("unexpected credential: %v", first)
	}
	meta := first["meta"].(map[string]any)
	if _, ok := meta["vct_values"]; !ok {
		t.Fatalf("want the vct values, got %v", meta)
	}
	if _, ok := doc["credential_sets"]; !ok {
		t.Fatalf("want credential_sets, got %v", doc)
	}
}

func TestParseAndIDs(t *testing.T) {
	parsed, err := Parse(`{"credentials":[{"id":"b","format":"jwt_vc_json"},{"id":"a","format":"ldp_vc"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.QueryIDs(); len(got) != 2 || got[0] != "b" {
		t.Fatalf("unexpected ids: %v", got)
	}
	if got := SortedIDs(parsed); got[0] != "a" {
		t.Fatalf("want sorted ids, got %v", got)
	}
	if _, err := Parse("{oops"); err == nil {
		t.Fatal("want a parse error")
	}
}

func TestAuthorityShape(t *testing.T) {
	built, err := Build([]Member{{Queries: []Credential{{
		ID: "a", Format: "ldp_vc",
		Meta:               &Meta{TypeValues: [][]string{{"VerifiableCredential", "Passport"}}},
		TrustedAuthorities: []Authority{{Type: "openid_federation", Values: []string{"https://issuer.example"}}},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := built.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"trusted_authorities", "type_values", "openid_federation"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("want %q in %s", want, raw)
		}
	}
}
