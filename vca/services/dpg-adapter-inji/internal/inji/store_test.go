// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const storeSchema = `{"type":"object","properties":{"fullName":{"type":"string"},"credits":{"type":"integer"}}}`

// TestTemplateReadsColumns: the template of every format reads the claim
// columns of the VCA claims store, not the claim names (ADR-051
// decision 4).
func TestTemplateReadsColumns(t *testing.T) {
	for _, format := range []string{"ldp_vc", "vc+sd-jwt", "mso_mdoc"} {
		typ := "ResidencePermitCredential"
		if format == "mso_mdoc" {
			typ = "org.example.residence.1"
		}
		dto, err := BuildConfiguration(ConfigInput{ID: "c-" + format, Format: format, Type: typ, JSONSchema: storeSchema}, DefaultProfiles())
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		tmpl, err := DecodeTemplate(dto.VcTemplate)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(tmpl, `"fullName": "${c1}"`) && !strings.Contains(tmpl, `"elementValue": "${c1}"`) {
			t.Errorf("%s: the template does not read c1:\n%s", format, tmpl)
		}
		if !strings.Contains(tmpl, "${c2}") || strings.Contains(tmpl, "${fullName}") || strings.Contains(tmpl, "${credits}") {
			t.Errorf("%s: the template reads a claim name:\n%s", format, tmpl)
		}
		if format == "ldp_vc" {
			for _, want := range []string{"${v_valid_from}", "${v_valid_until}", "${v_status_uri}", "${v_status_index}", "#if($v_status_uri"} {
				if !strings.Contains(tmpl, want) {
					t.Errorf("ldp_vc template lacks %s:\n%s", want, tmpl)
				}
			}
		}
		if strings.Contains(tmpl, "${"+StatusURIClaim+"}") || strings.Contains(tmpl, "${"+ValidFromClaim+"}") {
			t.Errorf("%s: the template reads a staged marker:\n%s", format, tmpl)
		}
	}
	// The identity QR reads the columns too.
	dto, err := BuildConfiguration(ConfigInput{ID: "q", Format: "ldp_vc", Type: "IdentityCredential",
		JSONSchema: `{"type":"object","properties":{"fullName":{"type":"string"}}}`}, DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	if len(dto.QrSettings) != 1 || dto.QrSettings[0]["Full Name"] != "${c1}" {
		t.Errorf("qrSettings = %v", dto.QrSettings)
	}
}

// TestScopeIsShared: every configuration has the one scope that the
// data provider maps onto the claims store (ADR-051 decision 3).
func TestScopeIsShared(t *testing.T) {
	for _, format := range []string{"ldp_vc", "vc+sd-jwt", "mso_mdoc"} {
		dto, err := BuildConfiguration(ConfigInput{ID: "own-id", Format: format, Type: "a.b", JSONSchema: storeSchema}, DefaultProfiles())
		if err != nil {
			t.Fatal(err)
		}
		if dto.Scope != SharedScope || SharedScope != "vca_credential" {
			t.Errorf("%s scope = %q", format, dto.Scope)
		}
	}
}

// TestIdIsAnOptionalClaim: every configuration declares id, so the
// staging call of the pre-authorized code passes the claim check of
// Certify with {"id": <staging id>}, and marks it optional.
func TestIdIsAnOptionalClaim(t *testing.T) {
	for _, format := range []string{"ldp_vc", "vc+sd-jwt", "mso_mdoc"} {
		dto, err := BuildConfiguration(ConfigInput{ID: "x", Format: format, Type: "a.b", JSONSchema: storeSchema}, DefaultProfiles())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(dto)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		field := map[string]string{"ldp_vc": "credentialSubjectDefinition", "vc+sd-jwt": "sdJwtClaims", "mso_mdoc": "msoMdocClaims"}[format]
		claims, isMap := body[field].(map[string]any)
		if !isMap {
			t.Fatalf("%s: no %s: %s", format, field, raw)
		}
		id, ok := claims[StagingClaim].(map[string]any)
		if !ok {
			t.Fatalf("%s: %s has no id claim: %s", format, field, raw)
		}
		// Certify reads a claim without the member as optional. The
		// mDoc entry is a namespace map, so it carries none.
		mandatory, set := id["mandatory"]
		if (set && mandatory != false) || (!set && format != "mso_mdoc") {
			t.Errorf("%s: id is not optional: %v", format, id)
		}
		for _, marker := range []string{StatusIndexClaim, StatusURIClaim, ValidFromClaim, ValidUntilClaim} {
			if _, ok := claims[marker]; ok {
				t.Errorf("%s: %s still declares %s", format, field, marker)
			}
		}
	}
}

// TestMoreThan64ClaimsFails: the claims store has 64 claim columns, and
// the registration says so.
func TestMoreThan64ClaimsFails(t *testing.T) {
	props := make([]string, 0, 65)
	for i := range 65 {
		props = append(props, fmt.Sprintf(`"claim%d":{"type":"string"}`, i))
	}
	schema := `{"type":"object","properties":{` + strings.Join(props, ",") + `}}`
	_, err := BuildConfiguration(ConfigInput{ID: "big", Format: "ldp_vc", Type: "Big", JSONSchema: schema}, DefaultProfiles())
	if err == nil || !strings.Contains(err.Error(), "64") {
		t.Errorf("65 claims = %v", err)
	}
	names, err := ClaimNames(storeSchema)
	if err != nil || strings.Join(names, ",") != "fullName,credits" {
		t.Errorf("ClaimNames = %v %v", names, err)
	}
	if _, err := ClaimNames(schema); err == nil {
		t.Error("ClaimNames took 65 claims")
	}
}
