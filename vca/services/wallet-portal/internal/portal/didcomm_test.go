// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// P6-C3: a DIDComm invitation that the holder pastes or scans gets a
// page that names it and points at a DIDComm wallet, not an error.

// invitationURI is an out of band invitation with a credential offer.
var invitationURI = "https://agent.registry.gov.test?oob=" + base64.RawURLEncoding.EncodeToString([]byte(
	`{"@type":"https://didcomm.org/out-of-band/1.1/invitation","label":"Ministry of Agriculture",`+
		`"requests~attach":[{"data":{"base64":"`+base64.StdEncoding.EncodeToString(
		[]byte(`{"@type":"https://didcomm.org/issue-credential/2.0/offer-credential"}`))+`"}}]}`))

// TestWalletDetectsOobInvitation is P6-C3 for the pages.
func TestWalletDetectsOobInvitation(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	for _, path := range []string{"/wallet/claim/offer", "/wallet/scan"} {
		field := "offer"
		if path == "/wallet/scan" {
			field = "text"
		}
		rec := h.post(t, path, url.Values{field: {invitationURI}})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		page := rec.Body.String()
		a11ytest.AssertPage(t, page)
		for _, want := range []string{
			"DIDComm invitation", "Ministry of Agriculture", "credential offer", "DIDComm wallet",
			"<code>" + invitationURI + "</code>", `href="` + invitationURI + `"`, "Open in a wallet",
		} {
			if !strings.Contains(page, want) {
				t.Errorf("%s lacks %q", path, want)
			}
		}
		if strings.Contains(page, `aria-invalid="true"`) {
			t.Errorf("%s reads the invitation as a bad text", path)
		}
	}
	// The camera scanner gets the card as a fragment.
	form := url.Values{"payload": {invitationURI}}
	req := httptest.NewRequest(http.MethodPost, "/wallet/scan/read", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", h.guard.Token(citizen()))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Ministry of Agriculture") {
		t.Fatalf("scan read: %d %s", rec.Code, rec.Body.String())
	}
	a11ytest.AssertFragment(t, rec.Body.String())
}

// P6-C7: the pages of a stack wallet that speaks DIDComm (ADR-062
// decision 4).

func (f *fakeHolder) OpenInvitation(_ context.Context, req *connect.Request[backendv1.OpenInvitationRequest],
) (*connect.Response[backendv1.OpenInvitationResponse], error) {
	f.opened = req.Msg.GetInvitationUri()
	if f.didcommErr != nil {
		return nil, f.didcommErr
	}
	return connect.NewResponse(&backendv1.OpenInvitationResponse{Connection: &backendv1.DidcommConnection{Id: "c-9", Label: "Farm board", State: "completed"}}), nil
}

func (f *fakeHolder) ListInbox(context.Context, *connect.Request[backendv1.ListInboxRequest]) (*connect.Response[backendv1.ListInboxResponse], error) {
	if f.didcommErr != nil {
		return nil, f.didcommErr
	}
	return connect.NewResponse(&backendv1.ListInboxResponse{Items: f.inbox}), nil
}

func (f *fakeHolder) ListWalletConnections(context.Context, *connect.Request[backendv1.ListWalletConnectionsRequest],
) (*connect.Response[backendv1.ListWalletConnectionsResponse], error) {
	if f.didcommErr != nil {
		return nil, f.didcommErr
	}
	return connect.NewResponse(&backendv1.ListWalletConnectionsResponse{Connections: f.connections}), nil
}

// didcommWallet is the harness of a stack wallet that speaks DIDComm.
func didcommWallet(t *testing.T) *harness {
	t.Helper()
	return setupShell(t, func(o *serviceOptions) { o.Didcomm = func(context.Context) bool { return true } },
		holderDeployment(backendv1.Feature_FEATURE_WALLET_DIDCOMM))
}

// oobWith returns an invitation URL that carries one message, or none.
func oobWith(label, message string) string {
	inv := `{"@type":"https://didcomm.org/out-of-band/1.1/invitation","label":"` + label + `"`
	if message != "" {
		inv += `,"requests~attach":[{"data":{"base64":"` + base64.StdEncoding.EncodeToString([]byte(message)) + `"}}]`
	}
	return "https://agent.registry.gov.test?oob=" + base64.RawURLEncoding.EncodeToString([]byte(inv+"}"))
}

// invitationID reads the hidden invitation id of an invitation page.
func invitationID(t *testing.T, page string) string {
	t.Helper()
	const marker = `name="invitation_id" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("the page has no invitation id: %s", page)
	}
	rest := page[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

// TestOfferInvitationShowsTheValuesFirst: the page shows what the offer
// carries and asks before the stack wallet takes it. Accept takes the
// credential, and decline sends nothing.
func TestOfferInvitationShowsTheValuesFirst(t *testing.T) {
	h := didcommWallet(t)
	uri := oobWith("Ministry of Agriculture", `{"@type":"https://didcomm.org/issue-credential/2.0/offer-credential","credential_preview":{"attributes":[`+
		`{"name":"fullName","value":"Amina Wanjiru"},{"name":"acres","value":"12"}]}}`)
	rec := h.post(t, "/wallet/scan", url.Values{"text": {uri}})
	page := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("scan: %d", rec.Code)
	}
	for _, want := range []string{"Ministry of Agriculture", "fullName", "Amina Wanjiru", "acres", `action="/wallet/invitation"`, "Add to my wallet", "Decline"} {
		if !strings.Contains(page, want) {
			t.Errorf("the offer page lacks %q", want)
		}
	}
	if strings.Contains(page, "Open in a wallet") || h.holder.lastAccept != nil {
		t.Error("the page sends the holder elsewhere, or the wallet took the offer before the answer")
	}
	id := invitationID(t, page)
	if rec = h.post(t, "/wallet/invitation", url.Values{"invitation_id": {id}, "action": {"decline"}}); rec.Code != http.StatusSeeOther || h.holder.lastAccept != nil {
		t.Fatalf("decline: %d, accept %+v", rec.Code, h.holder.lastAccept)
	}
	id = invitationID(t, h.post(t, "/wallet/scan", url.Values{"text": {uri}}).Body.String())
	if rec = h.post(t, "/wallet/invitation", url.Values{"invitation_id": {id}, "action": {"accept"}}); rec.Code != http.StatusSeeOther ||
		rec.Header().Get("Location") != "/wallet/" || h.holder.lastAccept.GetOfferUri() != uri {
		t.Fatalf("accept: %d %q %+v", rec.Code, rec.Header().Get("Location"), h.holder.lastAccept)
	}
	if rec = h.post(t, "/wallet/invitation", url.Values{"invitation_id": {id}, "action": {"accept"}}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "does not know this step") {
		t.Errorf("a second answer: %d", rec.Code)
	}
}

// TestRequestInvitationAsksForConsent: the page shows what the verifier
// asks for. Share answers it through the stack wallet and shows the
// answer of the verifier.
func TestRequestInvitationAsksForConsent(t *testing.T) {
	h := didcommWallet(t)
	uri := oobWith("Farm board", `{"@type":"https://didcomm.org/present-proof/2.0/request-presentation","request_presentations~attach":[{"data":{"json":`+
		`{"name":"Farmer check","requested_attributes":{"a":{"name":"fullName"}},"requested_predicates":{"p":{"name":"acres","p_type":">=","p_value":10}}}}}]}`)
	page := h.post(t, "/wallet/claim/offer", url.Values{"offer": {uri}}).Body.String()
	for _, want := range []string{"Farm board", "Farmer check", "fullName", "acres &gt;= 10", "Share", "Decline"} {
		if !strings.Contains(page, want) {
			t.Errorf("the request page lacks %q", want)
		}
	}
	rec := h.post(t, "/wallet/invitation", url.Values{"invitation_id": {invitationID(t, page)}, "action": {"accept"}})
	if rec.Code != http.StatusOK || h.holder.lastPresent.GetRequestUri() != uri || !strings.Contains(rec.Body.String(), "Accepted") {
		t.Fatalf("share: %d %+v", rec.Code, h.holder.lastPresent)
	}
}

// TestConnectionInvitation: an invitation with no message connects the
// stack wallet, and the connections page lists the connection.
func TestConnectionInvitation(t *testing.T) {
	h := didcommWallet(t)
	uri := oobWith("Farm board", "")
	page := h.post(t, "/wallet/scan", url.Values{"text": {uri}}).Body.String()
	if !strings.Contains(page, "Connect") {
		t.Fatalf("the connection page: %s", page)
	}
	rec := h.post(t, "/wallet/invitation", url.Values{"invitation_id": {invitationID(t, page)}, "action": {"accept"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/wallet/connections?notice=connected" || h.holder.opened != uri {
		t.Fatalf("connect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	h.holder.didcommErr = errDown
	rec = h.post(t, "/wallet/invitation", url.Values{"invitation_id": {invitationID(t, h.post(t, "/wallet/scan", url.Values{"text": {uri}}).Body.String())}, "action": {"accept"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "did not connect") {
		t.Errorf("a failed connection: %d", rec.Code)
	}
}

// TestConnectionsPage lists what waits over a connection and the
// connections. Accept takes an offer, and Share answers a request.
func TestConnectionsPage(t *testing.T) {
	h := didcommWallet(t)
	h.holder.inbox = []*backendv1.InboxItem{
		{Id: "p-1", Kind: backendv1.InboxItem_KIND_PROOF_REQUEST, ConnectionLabel: "Farm board", Name: "Farmer check", Requested: []string{"fullName", "acres >= 10"}},
		{Id: "o-1", Kind: backendv1.InboxItem_KIND_OFFER, ConnectionLabel: "Ministry of Agriculture", Name: "Farmer",
			Offered: []*backendv1.OfferedValue{{Name: "acres", Value: "12"}}},
	}
	h.holder.connections = []*backendv1.DidcommConnection{{Id: "c-1", Label: "Ministry of Agriculture", State: "completed"}}
	rec := h.get(t, "/wallet/connections?notice=connected")
	page := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("connections: %d", rec.Code)
	}
	for _, want := range []string{
		"Farmer check", "acres &gt;= 10", "Farm board", "Ministry of Agriculture", "Farmer", "12", "completed",
		`action="/wallet/inbox"`, `name="id" value="o-1"`, `name="kind" value="offer"`, `href="/wallet/connections"`, "The wallet is now connected.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the connections page lacks %q", want)
		}
	}
	if rec = h.post(t, "/wallet/inbox", url.Values{"id": {"o-1"}, "kind": {"offer"}}); rec.Code != http.StatusSeeOther || h.holder.lastAccept.GetInboxId() != "o-1" {
		t.Fatalf("accept: %d %+v", rec.Code, h.holder.lastAccept)
	}
	if rec = h.post(t, "/wallet/inbox", url.Values{"id": {"p-1"}, "kind": {"request"}}); rec.Code != http.StatusOK || h.holder.lastPresent.GetInboxId() != "p-1" {
		t.Fatalf("share: %d %+v", rec.Code, h.holder.lastPresent)
	}
	if rec = h.post(t, "/wallet/inbox", url.Values{"id": {"p-1"}, "kind": {"other"}}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "kind") {
		t.Errorf("an unknown kind: %d", rec.Code)
	}
	h.holder.inbox, h.holder.connections = nil, nil
	if page = h.get(t, "/wallet/connections").Body.String(); !strings.Contains(page, "Nothing waits for you.") || !strings.Contains(page, "The wallet has no connection yet.") {
		t.Errorf("an empty page: %s", page)
	}
	h.holder.didcommErr = errDown
	if rec = h.get(t, "/wallet/connections"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "did not list") {
		t.Errorf("a failed read: %d", rec.Code)
	}
}

// TestConnectionsPageOnlyWithFeature is ADR-034 decision 5: a stack
// wallet without DIDComm has no connections page, no navigation entry,
// and no answer form.
func TestConnectionsPageOnlyWithFeature(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	for _, path := range []string{"/wallet/connections"} {
		if rec := h.get(t, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	for _, path := range []string{"/wallet/inbox", "/wallet/invitation"} {
		if rec := h.post(t, path, url.Values{"id": {"x"}}); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	if strings.Contains(h.get(t, "/wallet/").Body.String(), `href="/wallet/connections"`) {
		t.Error("the navigation links the connections page")
	}
	if !strings.Contains(didcommWallet(t).get(t, "/wallet/").Body.String(), `href="/wallet/connections"`) {
		t.Error("the navigation does not link the connections page")
	}
}

// TestPermanentCardHasNoRemoveButton is ADR-062 decision 5.
func TestPermanentCardHasNoRemoveButton(t *testing.T) {
	h := didcommWallet(t)
	h.holder.credential = &backendv1.WalletCredential{Id: "anoncreds:r-1", Type: "Farmer", Issuer: "did:indy:bcovrin:testnet:Ra8F", Permanent: true,
		Credential: &commonv1.Credential{Format: commonv1.Format_FORMAT_ANONCREDS,
			Payload: []byte(`{"type":["Farmer"],"issuer":"did:indy:bcovrin:testnet:Ra8F","credentialSubject":{"fullName":"Amina Wanjiru"}}`)}}
	page := h.get(t, "/wallet/").Body.String()
	if !strings.Contains(page, "Amina Wanjiru") || strings.Contains(page, "Remove from my wallet") || !strings.Contains(page, "cannot remove") {
		t.Errorf("the card of a permanent credential: %s", page)
	}
}
