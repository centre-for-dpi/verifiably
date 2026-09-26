// SPDX-License-Identifier: Apache-2.0

package detect_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/detect"
)

// P6-C3: a DIDComm out of band invitation is no OID4VCI offer. The
// wallet names it, with the label of the issuer and whether it carries a
// credential offer, so the holder opens it in a DIDComm wallet.

func encode(json string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

// oobInvitation is an out of band invitation that carries a credential
// offer, as the agent of the issuer makes it.
var oobInvitation = `{"@type":"https://didcomm.org/out-of-band/1.1/invitation","@id":"5b4a",` +
	`"label":"Ministry of Agriculture","handshake_protocols":["https://didcomm.org/didexchange/1.1"],` +
	`"requests~attach":[{"@id":"9c8d","mime-type":"application/json","data":{"base64":"` +
	base64.StdEncoding.EncodeToString([]byte(`{"@type":"https://didcomm.org/issue-credential/2.0/offer-credential","@id":"9c8d"}`)) + `"}}]}`

// TestWalletDetectsOobInvitation is P6-C3.
func TestWalletDetectsOobInvitation(t *testing.T) {
	for name, text := range map[string]string{
		"https":   "https://agent.registry.gov.test?oob=" + encode(oobInvitation),
		"didcomm": "didcomm://invite?oob=" + encode(oobInvitation),
		"padded":  "https://agent.registry.gov.test/?oob=" + base64.URLEncoding.EncodeToString([]byte(oobInvitation)),
	} {
		got, err := detect.Text(text, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.Kind != detect.Invitation {
			t.Fatalf("%s: kind = %v", name, got.Kind)
		}
		inv := got.Invitation
		if inv.URI != text || inv.Label != "Ministry of Agriculture" || !inv.CarriesOffer {
			t.Errorf("%s: invitation = %+v", name, inv)
		}
		if explain := detect.Explain(got); !strings.Contains(explain, "DIDComm wallet") {
			t.Errorf("%s: explain = %q", name, explain)
		}
	}
	// A connection invitation carries no offer.
	conn := `{"@type":"https://didcomm.org/connections/1.0/invitation","label":"Verifier desk","serviceEndpoint":"https://a.example"}`
	got, err := detect.Text("https://agent.registry.gov.test?c_i="+encode(conn), 0)
	if err != nil || got.Kind != detect.Invitation || got.Invitation.CarriesOffer || got.Invitation.Label != "Verifier desk" {
		t.Errorf("connection invitation = %+v, %v", got, err)
	}
	// A parameter that holds no invitation is no invitation.
	for _, text := range []string{
		"https://agent.registry.gov.test?oob=not-base64!",
		"https://agent.registry.gov.test?oob=" + encode(`{"@type":"https://example.org/other"}`),
		"https://agent.registry.gov.test?oob=" + encode(`[1,2]`),
	} {
		if got, err := detect.Text(text, 0); err != nil || got.Kind == detect.Invitation {
			t.Errorf("%q read as %v, %v", text, got.Kind, err)
		}
	}
}
