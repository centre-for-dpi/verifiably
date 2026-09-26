// SPDX-License-Identifier: Apache-2.0

package vc

import "testing"

// TestTypeTitle is P4-05: a type name reads as words in sentence case.
// Camel case splits into words, a URL or URN style type keeps its last
// meaningful part, and a known short form stays in capitals.
func TestTypeTitle(t *testing.T) {
	for in, want := range map[string]string{
		"OpenBadgeCredential":        "Open badge credential",
		"  OpenBadgeCredential ":     "Open badge credential",
		"UniversityDegreeCredential": "University degree credential",
		"VerifiableCredential":       "Verifiable credential",
		"VerifiableId":               "Verifiable ID",
		"PIDCredential":              "PID credential",
		"KYCCheck":                   "KYC check",
		"EHICVerifiableCredential":   "EHIC verifiable credential",
		"FarmerCredential":           "Farmer credential",
		"farmer":                     "Farmer",
		"nurse-licence":              "Nurse licence",
		"identity_credential":        "Identity credential",
		"https://example.org/credentials/v1/EmployeeBadge":     "Employee badge",
		"https://credentials.example.org/identity_credential/": "Identity credential",
		"https://example.org/types#AlumniCredential":           "Alumni credential",
		"https://example.org/vct/pid/1.0":                      "PID",
		"urn:eu.europa.ec.eudi:pid:1":                          "PID",
		"urn:example:OpenBadgeCredential:v2":                   "Open badge credential",
		"org.iso.18013.5.1.mDL":                                "mDL",
		"eu.europa.ec.eudi.pid.1":                              "PID",
		"Farmer Credential":                                    "Farmer Credential",
		"Open badge credential":                                "Open badge credential",
		"":                                                     "",
		"https://example.org/":                                 "https://example.org/",
		"urn:1:2":                                              "urn:1:2",
		"https://exa mple.org/%zz":                             "https://exa mple.org/%zz",
		"https://example.org/%zz":                              "https://example.org/%zz",
		"__":                                                   "__",
		"urn:example:Badge:1.urn":                              "Badge",
		"VerifiablePortableDocumentA1":                         "Verifiable portable document A1",
		"NaturalPersonVerifiableID":                            "Natural person verifiable ID",
		"KycCredential":                                        "KYC credential",
		"OpenCredential2":                                      "Open credential2",
		"Credential2":                                          "Credential2",
		"ÉtatCivil":                                            "État civil",
	} {
		if got := TypeTitle(in); got != want {
			t.Errorf("TypeTitle(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTypeTitleIsStable checks that a title stays as it is when it runs
// through TypeTitle again, so a page may call it on a stored title.
func TestTypeTitleIsStable(t *testing.T) {
	for _, in := range []string{"OpenBadgeCredential", "urn:eu.europa.ec.eudi:pid:1", "org.iso.18013.5.1.mDL", "VerifiableId"} {
		once := TypeTitle(in)
		if twice := TypeTitle(once); twice != once {
			t.Errorf("TypeTitle(%q) = %q, then %q", in, once, twice)
		}
	}
}
