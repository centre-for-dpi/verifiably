// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// Inji Certify 0.14.0 signs an identity QR code per the MOSIP QR code
// specification 1.1.0 beside a credential when the configuration has
// qrSettings. Each entry of qrSettings is a Velocity template of one
// JSON object. Its keys are the attribute names of the key mapper of
// PixelPass, which turns them into the integer keys of claim 169. Certify
// signs the claims as a CWT with the key of the configuration, compresses
// and base45 encodes it, and hands the codes to the credential template
// as the list claim_169_values.

// IdentityQRClaim is the claim of the credential that carries the first
// signed code. The adapter writes it into the template, so it reads it
// back from the credential.
const IdentityQRClaim = "identityQR"

// qrValues is the template variable Certify fills with the signed codes.
const qrValues = "claim_169_values"

// qrGuard opens the part of a template that only a signed code fills.
const qrGuard = `#if($` + qrValues + ` && $` + qrValues + `.size() > 0)`

// qrPlaceholder places the first signed code.
const qrPlaceholder = `"$` + qrValues + `.get(0)"`

// claim169Attributes maps a claim name, in lower case without
// separators, onto the attribute of claim 169 that PixelPass knows
// (CLAIM_169_KEY_MAPPER). The attribute numbers are those of the QR code
// specification: ID is 1, Full Name is 4, Date of Birth is 8.
var claim169Attributes = map[string]string{
	"uin": "ID", "vid": "ID", "nationalid": "ID", "idnumber": "ID", "individualid": "ID",
	"language":   "Language",
	"fullname":   "Full Name",
	"name":       "Full Name",
	"firstname":  "First Name",
	"givenname":  "First Name",
	"middlename": "Middle Name",
	"lastname":   "Last Name", "familyname": "Last Name", "surname": "Last Name",
	"dateofbirth": "Date of Birth", "birthdate": "Date of Birth", "dob": "Date of Birth",
	"gender": "Gender", "sex": "Gender",
	"address": "Address",
	"email":   "Email ID", "emailid": "Email ID",
	"phone": "Phone Number", "phonenumber": "Phone Number", "mobile": "Phone Number", "mobilenumber": "Phone Number",
	"nationality":   "Nationality",
	"maritalstatus": "Marital Status",
	"guardian":      "Guardian",
}

// Claim169Attribute returns the claim 169 attribute of a claim name, or
// the empty string when the specification names no such attribute.
func Claim169Attribute(name string) string {
	key := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
	return claim169Attributes[key]
}

// qrSettings returns the one entry of qrSettings for the string claims
// that map onto claim 169, or nil when none does. A claim that maps onto
// an attribute another claim took stays out.
func qrSettings(claims []claim) []map[string]string {
	entry := map[string]string{}
	for _, c := range claims {
		attr := Claim169Attribute(c.name)
		if attr == "" || !c.quoted {
			continue
		}
		if _, taken := entry[attr]; !taken {
			entry[attr] = "${" + c.name + "}"
		}
	}
	if len(entry) == 0 {
		return nil
	}
	return []map[string]string{entry}
}

// identityQRPart returns the template part that places the first code,
// with a leading comma, or nothing when the entry asks for no code.
func identityQRPart(settings []map[string]string, indent string) string {
	if settings == nil {
		return ""
	}
	return "\n" + qrGuard + ",\n" + indent + quote(IdentityQRClaim) + ": " + qrPlaceholder + "\n#end"
}

// IdentityQR returns the signed code a credential carries: the claim of
// the credential subject of a JSON-LD credential, or the claim of the
// payload of an SD-JWT. It returns the empty string when there is none.
func IdentityQR(credential []byte) string {
	var doc struct {
		Subject map[string]any `json:"credentialSubject"`
	}
	if json.Unmarshal(credential, &doc) == nil {
		return anyval.As[string](doc.Subject[IdentityQRClaim])
	}
	jwt, _, _ := strings.Cut(string(credential), "~")
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return ""
	}
	return anyval.As[string](payload[IdentityQRClaim])
}
