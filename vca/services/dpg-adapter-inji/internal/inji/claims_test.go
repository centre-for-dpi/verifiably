// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStatusMarkersPerFormat(t *testing.T) {
	for _, format := range []string{"vc+sd-jwt", "dc+sd-jwt", "ldp_vc"} {
		if !StatusMarkers(format) {
			t.Fatalf("the format %q uses the status markers", format)
		}
	}
	if StatusMarkers("mso_mdoc") {
		t.Fatal("an mdoc has no status list entry")
	}
}

// expires is the end of the offers of the row tests.
var expires = time.Date(2026, 9, 26, 12, 15, 0, 0, time.UTC)

func TestClaimsRowCarriesTheStatusColumns(t *testing.T) {
	names := []string{"fullName", "credits"}
	got, err := ClaimsRow(`{"id":"s1"}`, "cfg", names, map[string]any{"fullName": "Amina", "credits": json.Number("12")},
		"ldp_vc", StatusEntry{Index: 12, URL: "https://s.example/list/1"}, Validity{}, expires)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != `{"id":"s1"}` || got.ConfigID != "cfg" || !got.ExpiresAt.Equal(expires) {
		t.Fatalf("row = %+v", got)
	}
	if got.Claims[0] != "Amina" || got.Claims[1] != "12" {
		t.Fatalf("claims = %v", got.Claims)
	}
	if got.StatusIndex != "12" || got.StatusURI != "https://s.example/list/1" || got.ValidFrom != "" {
		t.Fatalf("reserved = %+v", got)
	}
	// Without a status entry the index is 0 and the address empty, so
	// the guard of the template leaves the entry out.
	none, err := ClaimsRow("k", "cfg", names, map[string]any{"fullName": "A"}, "vc+sd-jwt", StatusEntry{}, Validity{}, expires)
	if err != nil || none.StatusIndex != "0" || none.StatusURI != "" || none.Claims[1] != "" {
		t.Fatalf("row = %+v %v", none, err)
	}
	// An mDoc has no status entry.
	mdoc, err := ClaimsRow("k", "cfg", names, map[string]any{"fullName": "A"}, "mso_mdoc", StatusEntry{Index: 1}, Validity{}, expires)
	if err != nil || mdoc.StatusIndex != "" {
		t.Fatalf("mdoc row = %+v %v", mdoc, err)
	}
}

func TestClaimsRowCarriesTheValidityWindow(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	got, err := ClaimsRow("k", "cfg", []string{"a"}, map[string]any{"a": "b"}, "ldp_vc", StatusEntry{},
		Validity{From: from, Until: until}, expires)
	if err != nil || got.ValidFrom != "2026-01-01T00:00:00Z" || got.ValidUntil != "2027-01-01T00:00:00Z" {
		t.Fatalf("row = %+v %v", got, err)
	}
}

func TestClaimsRowRefusesAnUnknownClaim(t *testing.T) {
	_, err := ClaimsRow("k", "cfg", []string{"a"}, map[string]any{"a": "b", "zeta": 1, "beta": 2}, "ldp_vc",
		StatusEntry{}, Validity{}, expires)
	if err == nil || !strings.Contains(err.Error(), "beta, zeta") {
		t.Fatalf("err = %v", err)
	}
	if _, err := ClaimsRow("k", "cfg", make([]string, MaxClaims+1), nil, "ldp_vc", StatusEntry{}, Validity{}, expires); err == nil {
		t.Fatal("65 columns passed")
	}
}

func TestAuthorizationCodeOffer(t *testing.T) {
	got := AuthorizationCodeOffer("https://i.example", "FarmerCredential", "state-1",
		"https://esignet.example/v1/esignet")
	if got["credential_issuer"] != "https://i.example" {
		t.Fatalf("offer = %v", got)
	}
	ids := mustAs[[]string](t, got["credential_configuration_ids"])
	if len(ids) != 1 || ids[0] != "FarmerCredential" {
		t.Fatalf("ids = %v", ids)
	}
	grants := mustAs[map[string]any](t, got["grants"])
	grant := mustAs[map[string]any](t, grants["authorization_code"])
	if grant["issuer_state"] != "state-1" {
		t.Fatalf("grant = %v", grant)
	}
	if grant["authorization_server"] != "https://esignet.example/v1/esignet" {
		t.Fatalf("grant = %v", grant)
	}
	bare := AuthorizationCodeOffer("https://i.example", "x", "s", "")
	grants = mustAs[map[string]any](t, bare["grants"])
	grant = mustAs[map[string]any](t, grants["authorization_code"])
	if _, ok := grant["authorization_server"]; ok {
		t.Fatal("an empty identity provider adds no member")
	}
}
