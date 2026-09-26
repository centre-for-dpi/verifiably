// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/ingest"
)

// identitySchema carries four claims that the QR specification names and
// one that it does not.
const identitySchema = `{"type":"object","properties":{` +
	`"fullName":{"type":"string"},"dateOfBirth":{"type":"string"},"gender":{"type":"string"},` +
	`"mobileNumber":{"type":"string"},"farmerID":{"type":"string"},"hectares":{"type":"number"}}}`

// TestBuildConfigurationSignsAnIdentityQR asks Certify for a Claim 169
// QR code beside a JSON-LD and an SD-JWT credential: the entry maps each
// claim the specification names onto its PixelPass attribute, names the
// signature algorithm of the key, and the template puts the first signed
// code in the credential.
func TestBuildConfigurationSignsAnIdentityQR(t *testing.T) {
	for _, tc := range []struct {
		format, algorithm string
	}{{"ldp_vc", "EdDSA"}, {"vc+sd-jwt", "ES256"}} {
		dto, err := BuildConfiguration(ConfigInput{ID: "Identity_" + tc.format, Format: tc.format, Type: "NationalIdentityCredential",
			JSONSchema: identitySchema}, DefaultProfiles())
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"Full Name": "${fullName}", "Date of Birth": "${dateOfBirth}",
			"Gender": "${gender}", "Phone Number": "${mobileNumber}"}
		if len(dto.QrSettings) != 1 || !sameMap(dto.QrSettings[0], want) {
			t.Fatalf("%s qrSettings = %v", tc.format, dto.QrSettings)
		}
		if dto.QrSignatureAlgo != tc.algorithm {
			t.Errorf("%s qrSignatureAlgo = %q", tc.format, dto.QrSignatureAlgo)
		}
		tmpl, err := DecodeTemplate(dto.VcTemplate)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(tmpl, `"`+IdentityQRClaim+`": "$claim_169_values.get(0)"`) || !strings.Contains(tmpl, "#if($claim_169_values") {
			t.Errorf("%s template lacks the guarded identity QR:\n%s", tc.format, tmpl)
		}
		raw, err := json.Marshal(dto)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"qrSettings":[{`) || !strings.Contains(string(raw), `"qrSignatureAlgo":"`+tc.algorithm+`"`) {
			t.Errorf("the body names the fields as Certify reads them: %s", raw)
		}
	}
}

// TestBuildConfigurationWithoutIdentityClaims leaves the QR out when no
// claim maps onto the specification, and for an mDoc.
func TestBuildConfigurationWithoutIdentityClaims(t *testing.T) {
	dto, err := BuildConfiguration(ConfigInput{ID: "Farm", Format: "ldp_vc", Type: "FarmCredential",
		JSONSchema: `{"type":"object","properties":{"farmerID":{"type":"string"},"hectares":{"type":"number"}}}`}, DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := DecodeTemplate(dto.VcTemplate)
	if err != nil {
		t.Fatal(err)
	}
	if dto.QrSettings != nil || dto.QrSignatureAlgo != "" || strings.Contains(tmpl, IdentityQRClaim) {
		t.Fatalf("no identity claim wants no QR: %+v\n%s", dto, tmpl)
	}
	mdoc, err := BuildConfiguration(ConfigInput{ID: "Id_mdoc", Format: "mso_mdoc", Type: "org.iso.18013.5.1.mDL",
		JSONSchema: identitySchema}, DefaultProfiles())
	if err != nil {
		t.Fatal(err)
	}
	if mdoc.QrSettings != nil {
		t.Fatalf("an mDoc carries no identity QR: %v", mdoc.QrSettings)
	}
}

// TestIdentityQRAttributes maps the usual claim names onto the
// attributes of the QR specification and leaves a number out.
func TestIdentityQRAttributes(t *testing.T) {
	for name, want := range map[string]string{
		"name": "Full Name", "full_name": "Full Name", "givenName": "First Name", "familyName": "Last Name",
		"middleName": "Middle Name", "birthDate": "Date of Birth", "sex": "Gender", "email": "Email ID",
		"phone": "Phone Number", "nationality": "Nationality", "maritalStatus": "Marital Status",
		"guardian": "Guardian", "address": "Address", "uin": "ID", "language": "Language",
	} {
		if got := Claim169Attribute(name); got != want {
			t.Errorf("%s maps onto %q, want %q", name, got, want)
		}
	}
	if got := Claim169Attribute("farmerID"); got != "" {
		t.Errorf("farmerID maps onto %q", got)
	}
}

// TestIdentityQRFromCredential reads the signed code out of the credential
// Certify returns: the credential subject of a JSON-LD credential, and a
// claim of the payload of an SD-JWT.
func TestIdentityQRFromCredential(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/doc/credential-ldp-claim169.json")
	if err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Credential json.RawMessage `json:"credential"`
	}
	if jerr := json.Unmarshal(raw, &answer); jerr != nil {
		t.Fatal(jerr)
	}
	text := IdentityQR(answer.Credential)
	cwt, _, err := ingest.DecodeClaim169(text)
	if err != nil {
		t.Fatalf("the recorded code must decode: %v", err)
	}
	if cwt.Data["4"] != "Wanjiku Njeri" || cwt.Issuer != "did:web:certify.inji.example" {
		t.Fatalf("claim 169 = %v, issuer %q", cwt.Data, cwt.Issuer)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"vct":"x","` + IdentityQRClaim + `":"` + text + `"}`))
	sdJwt := "eyJhbGciOiJFUzI1NiJ9." + payload + ".c2ln~WyJzIiwibiIsInYiXQ~"
	if got := IdentityQR([]byte(sdJwt)); got != text {
		t.Fatalf("SD-JWT code = %q", got)
	}
	for _, none := range []string{"", "{}", `{"credentialSubject":{"fullName":"x"}}`, "a.b", "a.!!.c", "a." +
		base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c"} {
		if got := IdentityQR([]byte(none)); got != "" {
			t.Errorf("%q gives %q", none, got)
		}
	}
}

// sameMap compares two string maps.
func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
