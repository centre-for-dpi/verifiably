// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"github.com/fxamacker/cbor/v2"

	"github.com/centre-for-dpi/vc-adapters/core/vc"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
)

// residenceMdoc returns an IssuerSigned mDoc of the doctype
// org.example.residence.1 with three elements, as base64url.
func residenceMdoc(t *testing.T) string {
	t.Helper()
	item := func(id uint, name string, value any) cbor.Tag {
		raw, err := cbor.Marshal(map[string]any{"digestID": id, "random": []byte{9}, "elementIdentifier": name, "elementValue": value})
		if err != nil {
			t.Fatal(err)
		}
		return cbor.Tag{Number: 24, Content: raw}
	}
	mso, err := cbor.Marshal(map[string]any{"version": "1.0", "digestAlgorithm": "SHA-256", "docType": "org.example.residence.1"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cbor.Marshal(cbor.Tag{Number: 24, Content: mso})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cbor.Marshal(map[string]any{
		"nameSpaces": map[string]any{"org.example.residence": []any{
			item(0, "fullName", "Jordan Example"), item(1, "city", "Demo City"), item(2, "residentNumber", "RES-2026-0001"),
		}},
		"issuerAuth": []any{[]byte{0xa1, 0x01, 0x26}, map[int]any{}, payload, []byte{0}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// mdocRequest asks for the full name and the city of the mDoc.
func mdocRequest(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"client_id": "https://verifier.example", "nonce": "n-1", "state": "s-1",
		"response_uri": "https://verifier.example/direct_post",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "residence", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": "org.example.residence.1"},
			"claims": []any{
				map[string]any{"path": []string{"org.iso.18013.5.1", "fullName"}},
				map[string]any{"path": []string{"org.iso.18013.5.1", "city"}},
			},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestBrowserStoreReadsAndPresentsAnMdoc claims an mDoc into the browser
// store. The card names the doctype and the claims, an mso_mdoc query
// of the doctype matches it, and the answer carries only the elements
// the holder agreed to share.
func TestBrowserStoreReadsAndPresentsAnMdoc(t *testing.T) {
	stack := newClaimStack(t)
	stack.offer = `{"credential_issuer":"` + claimIssuer + `","credential_configuration_ids":["residence_mdoc"],` +
		`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code-1","tx_code":{"length":4}}}}`
	stack.metadata = `{"credential_issuer":"` + claimIssuer + `","credential_endpoint":"` + claimEndpoint + `",` +
		`"credential_configurations_supported":{"residence_mdoc":{"format":"mso_mdoc","doctype":"org.example.residence.1"}}}`
	mdoc := residenceMdoc(t)
	stack.issue = func(map[string]any) string { return mdoc }
	stack.request = mdocRequest(t)
	svc := browserStore(t, stack)
	browser := newBrowserHolder(t)
	step, err := svc.ClaimStart(ctx(), pasteOffer(t, svc), "4821", browser.jwk)
	if err != nil {
		t.Fatal(err)
	}
	if _, ferr := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput)); ferr != nil {
		t.Fatal(ferr)
	}
	held, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	card := held.Msg.GetCards()[0]
	if card.GetType() != "org.example.residence.1" || card.GetClaims()["fullName"] != "Jordan Example" ||
		card.GetStatusText() == "The wallet cannot read this credential. Ask the issuer for a new one." {
		t.Fatalf("card = %+v", card)
	}
	scan, err := svc.Scan(ctx(), connect.NewRequest(&walletportalv1.ScanRequest{
		Text: "openid4vp://?client_id=v&request_uri=https://verifier.example/r/1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	id := scan.Msg.GetDetected().GetPresentationId()
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{PresentationId: id}))
	if err != nil {
		t.Fatal(err)
	}
	requested := start.Msg.GetRequested()[0]
	if len(requested.GetMatches()) != 1 || requested.GetClaims()[0].GetValue() != "Jordan Example" {
		t.Fatalf("requested = %+v", requested)
	}
	if _, cerr := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: id,
		SelectedCards:  map[string]string{"residence": requested.GetMatches()[0].GetId()},
		Disclosed:      map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{"residence": {Paths: []string{"org.iso.18013.5.1.fullName"}}},
	})); cerr != nil {
		t.Fatalf("PresentConfirm: %v", cerr)
	}
	sent, err := vc.Parse([]byte(stack.posted.Get("vp_token")))
	if err != nil {
		t.Fatalf("the answer %q is no mDoc: %v", stack.posted.Get("vp_token"), err)
	}
	names := make([]string, 0, len(sent.Claims))
	for name := range sent.Claims {
		names = append(names, name)
	}
	if !slices.Equal(names, []string{"fullName"}) {
		t.Fatalf("the answer carries %v, want the full name only", names)
	}
}
