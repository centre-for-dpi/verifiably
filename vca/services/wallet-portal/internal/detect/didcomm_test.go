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

// P6-C7: the wallet reads what an invitation carries, so the holder
// sees it before the wallet of the stack receives the invitation
// (ADR-062 decision 4).

// b64 encodes a JSON message as the base64 data of an attachment.
func b64(json string) string { return base64.StdEncoding.EncodeToString([]byte(json)) }

// invitationWith returns an out of band invitation URL that carries one
// message.
func invitationWith(label, message string) string {
	return "https://agent.registry.gov.test?oob=" + encode(`{"@type":"https://didcomm.org/out-of-band/1.1/invitation","label":"`+label+
		`","requests~attach":[{"data":{"base64":"`+b64(message)+`"}}]}`)
}

// TestInvitationShowsWhatItCarries reads the values of an AnonCreds and
// a JSON-LD offer, and what an AnonCreds and a DIF PE proof request ask
// for.
func TestInvitationShowsWhatItCarries(t *testing.T) {
	anonOffer := `{"@type":"https://didcomm.org/issue-credential/2.0/offer-credential","@id":"t-1","credential_preview":{"attributes":[` +
		`{"name":"fullName","value":"[holder]"},{"name":"acres","value":"12"}]},"offers~attach":[{"data":{"base64":"` +
		b64(`{"schema_id":"did:indy:bcovrin:testnet:Ra8F/anoncreds/v0/SCHEMA/Farmer/1.0","cred_def_id":"x"}`) + `"}}]}`
	got, err := detect.Text(invitationWith("Ministry of Agriculture", anonOffer), 0)
	inv := got.Invitation
	if err != nil || !inv.CarriesOffer || inv.CarriesRequest || inv.Name != "Farmer" || len(inv.Offered) != 2 ||
		inv.Offered[0] != (detect.NamedValue{Name: "fullName", Value: "[holder]"}) || inv.Offered[1].Value != "12" {
		t.Errorf("anoncreds offer = %+v, %v", inv, err)
	}
	ldOffer := `{"@type":"https://didcomm.org/issue-credential/2.0/offer-credential","offers~attach":[{"data":{"json":` +
		`{"credential":{"type":["VerifiableCredential","PermanentResidentCard"],"credentialSubject":{"id":"did:key:z6Mk","givenName":"[given name]"}}}}}]}`
	got, err = detect.Text(invitationWith("Registry", ldOffer), 0)
	inv = got.Invitation
	if err != nil || !inv.CarriesOffer || inv.Name != "PermanentResidentCard" || len(inv.Offered) != 1 || inv.Offered[0].Name != "givenName" {
		t.Errorf("json-ld offer = %+v, %v", inv, err)
	}
	anonRequest := `{"@type":"https://didcomm.org/present-proof/2.0/request-presentation","request_presentations~attach":[{"data":{"base64":"` +
		b64(`{"name":"Farmer check","requested_attributes":{"attr1":{"name":"fullName"},"attr2":{"names":["farm","county"]}},`+
			`"requested_predicates":{"pred1":{"name":"acres","p_type":">=","p_value":10}}}`) + `"}}]}`
	got, err = detect.Text(invitationWith("Farm board", anonRequest), 0)
	inv = got.Invitation
	if err != nil || inv.CarriesOffer || !inv.CarriesRequest || inv.Name != "Farmer check" || strings.Join(inv.Requested, "|") != "fullName|farm|county|acres >= 10" {
		t.Errorf("anoncreds request = %+v, %v", inv, err)
	}
	peRequest := `{"@type":"https://didcomm.org/present-proof/2.0/request-presentation","request_presentations~attach":[{"data":{"json":` +
		`{"presentation_definition":{"name":"Licence","input_descriptors":[{"id":"d","name":"Photo","constraints":{"fields":[{"path":["$.credentialSubject.licenceNumber"]}]}},{"id":"e","name":"Age"}]}}}}]}`
	got, err = detect.Text(invitationWith("Road agency", peRequest), 0)
	inv = got.Invitation
	if err != nil || !inv.CarriesRequest || inv.Name != "Licence" || strings.Join(inv.Requested, "|") != "licenceNumber|Age" {
		t.Errorf("pe request = %+v, %v", inv, err)
	}
	// An attachment the wallet cannot read shows nothing and breaks
	// nothing.
	odd := `{"@type":"https://didcomm.org/issue-credential/2.0/offer-credential","offers~attach":[{"data":{"base64":"%%%"}}]}`
	if got, err = detect.Text(invitationWith("X", odd), 0); err != nil || !got.Invitation.CarriesOffer || len(got.Invitation.Offered) != 0 {
		t.Errorf("odd offer = %+v, %v", got.Invitation, err)
	}
}
