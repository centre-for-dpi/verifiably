// SPDX-License-Identifier: Apache-2.0

package inji

import (
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

func TestClaimsAlwaysCarryTheStatusMarkers(t *testing.T) {
	got := Claims(map[string]any{"fullName": "Ada"}, "ldp_vc",
		StatusEntry{Index: 12, URL: "https://s.example/list/1"}, Validity{}, false)
	if got["fullName"] != "Ada" {
		t.Fatalf("claims = %v", got)
	}
	if got[StatusIndexClaim] != "12" || got[StatusURIClaim] != "https://s.example/list/1" {
		t.Fatalf("markers = %v", got)
	}
	if _, ok := got[ValidFromClaim]; ok {
		t.Fatal("a request without a window adds no validity marker")
	}
}

func TestClaimsFillTheMarkersWithoutAStatusEntry(t *testing.T) {
	got := Claims(nil, "vc+sd-jwt", StatusEntry{}, Validity{}, false)
	if got[StatusIndexClaim] != "0" || got[StatusURIClaim] != "" {
		t.Fatalf("markers = %v; a missing marker leaves the template unresolved", got)
	}
}

func TestClaimsLeaveTheMarkersOutForAnotherFormat(t *testing.T) {
	got := Claims(map[string]any{"a": "b"}, "mso_mdoc", StatusEntry{Index: 1}, Validity{}, false)
	if _, ok := got[StatusIndexClaim]; ok {
		t.Fatalf("claims = %v; an unknown marker makes Inji reject the request", got)
	}
}

func TestClaimsCarryTheValidityWindow(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	got := Claims(nil, "ldp_vc", StatusEntry{}, Validity{From: from, Until: until}, true)
	if got[ValidFromClaim] != "2026-01-01T00:00:00Z" {
		t.Fatalf("validFrom = %v", got[ValidFromClaim])
	}
	if got[ValidUntilClaim] != "2027-01-01T00:00:00Z" {
		t.Fatalf("validUntil = %v", got[ValidUntilClaim])
	}
	open := Claims(nil, "ldp_vc", StatusEntry{}, Validity{}, true)
	if _, ok := open[ValidFromClaim]; ok {
		t.Fatal("an open window adds no bound")
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
