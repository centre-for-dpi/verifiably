// SPDX-License-Identifier: Apache-2.0

package waltid

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestIssuePathPerFormat(t *testing.T) {
	cases := map[Format]string{
		FormatJwtVcJSON: "/openid4vc/jwt/issue",
		FormatLdpVc:     "/openid4vc/jwt/issue",
		FormatVcSdJwt:   "/openid4vc/sdjwt/issue",
		FormatDcSdJwt:   "/openid4vc/sdjwt/issue",
		FormatMsoMdoc:   "/openid4vc/mdoc/issue",
	}
	for format, want := range cases {
		got, err := IssuePath(format)
		if err != nil || got != want {
			t.Fatalf("IssuePath(%s) = %q, %v; want %q", format, got, err, want)
		}
	}
	if _, err := IssuePath("bbs"); err == nil {
		t.Fatal("IssuePath accepted an unknown format")
	}
}

func TestAuthenticationMethodPerFlow(t *testing.T) {
	if AuthenticationMethod(true) != "PRE_AUTHORIZED" || AuthenticationMethod(false) != "NONE" {
		t.Fatal("the authentication method is wrong")
	}
}

func TestBuildVcdmCredentialCarriesTheWindowAndTheStatus(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	raw, err := BuildVcdmCredential(
		[]string{"FarmerCredential", "VerifiableCredential", ""},
		map[string]any{"given_name": "Ada"},
		StatusEntry{Bitstring: true, Index: 5, URL: "https://s.example/list/1"},
		Validity{From: from, Until: until},
	)
	if err != nil {
		t.Fatalf("BuildVcdmCredential: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("read the body: %v", err)
	}
	types := mustAs[[]any](t, doc["type"])
	if len(types) != 2 || types[0] != "VerifiableCredential" || types[1] != "FarmerCredential" {
		t.Fatalf("types = %v, a repeat must drop out", types)
	}
	if doc["validFrom"] != "2026-01-01T00:00:00Z" || doc["validUntil"] != "2027-01-01T00:00:00Z" {
		t.Fatalf("window = %v %v", doc["validFrom"], doc["validUntil"])
	}
	status := mustAs[map[string]any](t, doc["credentialStatus"])
	if status["statusListIndex"] != "5" {
		t.Fatalf("statusListIndex = %#v, a verifier needs a string", status["statusListIndex"])
	}
	if status["id"] != "https://s.example/list/1#5" {
		t.Fatalf("id = %v", status["id"])
	}
}

func TestBuildVcdmCredentialWithoutAStatusOrAWindow(t *testing.T) {
	raw, err := BuildVcdmCredential(nil, map[string]any{"a": "b"}, StatusEntry{}, Validity{})
	if err != nil {
		t.Fatalf("BuildVcdmCredential: %v", err)
	}
	var doc map[string]any
	if cerr := json.Unmarshal(raw, &doc); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if _, ok := doc["credentialStatus"]; ok {
		t.Fatal("a credential without a status entry must not be revocable")
	}
	if _, ok := doc["validFrom"]; ok {
		t.Fatal("an empty window must add no bound")
	}
}

func TestBuildSdJwtCredentialPutsTheClaimsAtTheRoot(t *testing.T) {
	raw, err := BuildSdJwtCredential(
		map[string]any{"age_over_18": true},
		StatusEntry{Token: true, Index: 9, URL: "https://s.example/token/1"},
		Validity{
			From:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Until: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	)
	if err != nil {
		t.Fatalf("BuildSdJwtCredential: %v", err)
	}
	var doc map[string]any
	if cerr := json.Unmarshal(raw, &doc); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if doc["age_over_18"] != true {
		t.Fatalf("the claim is not at the root: %v", doc)
	}
	if doc["nbf"] == nil || doc["exp"] == nil {
		t.Fatalf("the window is missing: %v", doc)
	}
	status := mustAs[map[string]any](t, doc["status"])
	list := mustAs[map[string]any](t, status["status_list"])
	if list["uri"] != "https://s.example/token/1" {
		t.Fatalf("status = %v", status)
	}
}

func TestBuildMdocDataStripsTheLastPartOfTheDoctype(t *testing.T) {
	raw, err := BuildMdocData("org.iso.18013.5.1.mDL", map[string]any{"family_name": "Lovelace"})
	if err != nil {
		t.Fatalf("BuildMdocData: %v", err)
	}
	var doc map[string]map[string]any
	if cerr := json.Unmarshal(raw, &doc); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if doc["org.iso.18013.5.1"]["family_name"] != "Lovelace" {
		t.Fatalf("body = %s", raw)
	}
	flat, err := BuildMdocData("mDL", map[string]any{"a": "b"})
	if err != nil {
		t.Fatalf("BuildMdocData: %v", err)
	}
	if !strings.HasPrefix(string(flat), `{"mDL"`) {
		t.Fatalf("a doctype without a dot keeps its name, got %s", flat)
	}
	if _, err := BuildMdocData("  ", nil); err == nil {
		t.Fatal("BuildMdocData accepted an empty doctype")
	}
}

func TestBuildSelectiveDisclosureMarksEveryClaim(t *testing.T) {
	raw := BuildSelectiveDisclosure(map[string]any{"a": 1, "b": 2})
	var doc map[string]any
	if cerr := json.Unmarshal(raw, &doc); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	fields := mustAs[map[string]any](t, doc["fields"])
	if len(fields) != 2 {
		t.Fatalf("fields = %v", fields)
	}
	first := mustAs[map[string]any](t, fields["a"])
	if first["sd"] != true {
		t.Fatalf("the claim a is not disclosable: %v", fields)
	}
	if doc["decoyMode"] != "NONE" {
		t.Fatalf("decoy mode = %v", doc["decoyMode"])
	}
}

func TestBorrowConfigurationIDPicksTheFirstOfTheFormat(t *testing.T) {
	meta := IssuerMetadata{CredentialConfigurationsSupported: map[string]ConfigurationEntry{
		"B_jwt": {Format: "jwt_vc_json"},
		"A_jwt": {Format: "jwt_vc_json"},
		"C_sd":  {Format: "vc+sd-jwt"},
	}}
	got, err := BorrowConfigurationID(meta, FormatJwtVcJSON)
	if err != nil || got != "A_jwt" {
		t.Fatalf("BorrowConfigurationID = %q, %v", got, err)
	}
	if _, err := BorrowConfigurationID(meta, FormatMsoMdoc); err == nil {
		t.Fatal("BorrowConfigurationID accepted a format the issuer does not advertise")
	}
}
