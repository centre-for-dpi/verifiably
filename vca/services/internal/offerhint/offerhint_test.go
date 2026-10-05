// SPDX-License-Identifier: Apache-2.0

package offerhint_test

import (
	"net/url"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/offerhint"
)

func TestAddAndOfRoundTrip(t *testing.T) {
	base := "openid-credential-offer://issuer.example?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer%3Fid%3D1"
	got := offerhint.Add(base, "ProofOfResidence_dc+sd-jwt")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	// The offer keeps its own parameter as it was.
	if u.Query().Get("credential_offer_uri") != "https://issuer.example/offer?id=1" {
		t.Fatalf("offer = %q", got)
	}
	if id := offerhint.Of(got); id != "ProofOfResidence_dc+sd-jwt" {
		t.Fatalf("Of = %q from %q", id, got)
	}
	for name, uri := range map[string]string{
		"no hint":  base,
		"no query": "openid-credential-offer://issuer.example",
		"broken":   "%zz",
	} {
		if id := offerhint.Of(uri); id != "" {
			t.Errorf("%s: Of = %q", name, id)
		}
	}
	// No id, or a URI that does not parse, stays as it is.
	if offerhint.Add(base, " ") != base || offerhint.Add("%zz", "x") != "%zz" {
		t.Fatal("Add changed an offer it cannot annotate")
	}
	// A URI without a query gets one.
	if got := offerhint.Add("openid-credential-offer://issuer.example", "a"); offerhint.Of(got) != "a" {
		t.Fatalf("no query: %q", got)
	}
}
