// SPDX-License-Identifier: Apache-2.0

package vc

import (
	"slices"
	"testing"
)

// TestFixedClaims names the claims a presentation of a credential always
// carries. An SD-JWT sends its plain claims whatever the holder ticks,
// and a format without selective disclosure sends each claim.
func TestFixedClaims(t *testing.T) {
	tok, _ := sampleSDJWT(t)
	got, err := FixedClaims([]byte(tok))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"onBehalfOf"}) {
		t.Fatalf("SD-JWT fixed claims = %v, want the one plain display claim", got)
	}
	ld := []byte(`{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential"],` +
		`"credentialSubject":{"id":"did:key:z","b":"2","a":"1"}}`)
	if got, err = FixedClaims(ld); err != nil || !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("JSON-LD fixed claims = %v, %v", got, err)
	}
	head := b64(map[string]any{"alg": "ES256"})
	for _, bad := range []string{"not-a-jwt", "a.!!.c~", `{"docType":"x"`,
		head + "." + b64(map[string]any{"vct": "x"}) + ".sig~%%~", head + "." + b64([]int{1}) + ".sig~"} {
		if _, err := FixedClaims([]byte(bad)); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}
