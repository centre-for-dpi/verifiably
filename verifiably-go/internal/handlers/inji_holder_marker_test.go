package handlers

import (
	"encoding/base64"
	"testing"
)

// F(3): Inji Certify renders an undefined ${var} verbatim when the data provider
// returned no value, so a claim can "succeed" with placeholder junk. The claim
// callback must detect these markers and refuse to store the credential.
func TestHasUnsubstitutedTemplateMarkers(t *testing.T) {
	sdjwtWith := "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOltdfQ.sig~" +
		base64.RawURLEncoding.EncodeToString([]byte(`["salt","last_name","${last_name}"]`)) + "~"
	sdjwtClean := "eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOltdfQ.sig~" +
		base64.RawURLEncoding.EncodeToString([]byte(`["salt","last_name","Aisha"]`)) + "~"

	cases := []struct {
		name string
		vc   string
		want bool
	}{
		{"w3c with markers", `{"credentialSubject":{"last_name":"${last_name}","testa_id":"${testa_id}"}}`, true},
		{"w3c holderId marker", `{"credentialSubject":{"id":"${_holderId}","x":"y"}}`, true},
		{"w3c clean", `{"credentialSubject":{"last_name":"Aisha","testa_id":"TESTA-0001"}}`, false},
		{"w3c literal dollar no braces", `{"credentialSubject":{"price":"$100"}}`, false},
		{"sd-jwt disclosure with marker", sdjwtWith, true},
		{"sd-jwt disclosure clean", sdjwtClean, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasUnsubstitutedTemplateMarkers(tc.vc); got != tc.want {
				t.Errorf("hasUnsubstitutedTemplateMarkers = %v, want %v", got, tc.want)
			}
		})
	}
}
