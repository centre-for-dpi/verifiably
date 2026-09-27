// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// P6-C7: a wallet of the stack that speaks DIDComm opens an invitation
// only after the holder accepts it (ADR-062 decision 4).

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

// didcommInvitation returns an invitation URL that carries one message.
func didcommInvitation(label, message string) string {
	inv := `{"@type":"https://didcomm.org/out-of-band/1.1/invitation","label":"` + label + `"`
	if message != "" {
		inv += `,"requests~attach":[{"data":{"base64":"` + base64.StdEncoding.EncodeToString([]byte(message)) + `"}}]`
	}
	return "https://agent.registry.gov.test?oob=" + base64.RawURLEncoding.EncodeToString([]byte(inv+"}"))
}

// The messages the tests carry.
const (
	offerMessage = `{"@type":"https://didcomm.org/issue-credential/2.0/offer-credential","credential_preview":{"attributes":[` +
		`{"name":"fullName","value":"[holder]"},{"name":"acres","value":"12"}]}}`
	requestMessage = `{"@type":"https://didcomm.org/present-proof/2.0/request-presentation","request_presentations~attach":[{"data":{"json":` +
		`{"name":"Farmer check","requested_attributes":{"a":{"name":"fullName"}},"requested_predicates":{"p":{"name":"acres","p_type":">=","p_value":10}}}}}]}`
)

// didcommWallet returns the service with a stack wallet that speaks
// DIDComm.
func didcommWallet(t *testing.T, h *fakeHolder) *service.Service {
	t.Helper()
	return build(t, func(o *service.Options) {
		o.Holder = h
		o.Didcomm = func(context.Context) bool { return true }
	})
}

// scanID pastes an invitation and returns the id of the pending
// invitation.
func scanID(t *testing.T, svc *service.Service, uri string) string {
	t.Helper()
	scan, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: uri}))
	if err != nil {
		t.Fatal(err)
	}
	return scan.Msg.GetDetected().GetInvitation().GetInvitationId()
}

// anonCard is the AnonCreds credential the stack wallet returns.
func anonCard() *backendv1.WalletCredential {
	return &backendv1.WalletCredential{Id: "anoncreds:r-1", Type: "Farmer", Issuer: "did:indy:bcovrin:testnet:Ra8F", Permanent: true,
		Credential: &commonv1.Credential{Format: commonv1.Format_FORMAT_ANONCREDS,
			Payload: []byte(`{"type":["Farmer"],"issuer":"did:indy:bcovrin:testnet:Ra8F","credentialSubject":{"fullName":"[holder]","acres":"12"}}`)}}
}

// TestScannedOfferWaitsForTheHolder: the scan names what the invitation
// carries and keeps it. The stack wallet receives it only on accept, and
// a decline sends nothing.
func TestScannedOfferWaitsForTheHolder(t *testing.T) {
	h := &fakeHolder{credential: anonCard()}
	svc := didcommWallet(t, h)
	uri := didcommInvitation("Ministry of Agriculture", offerMessage)
	scan, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: uri}))
	if err != nil {
		t.Fatal(err)
	}
	inv := scan.Msg.GetDetected().GetInvitation()
	if inv.GetInvitationId() == "" || !inv.GetCarriesOffer() || len(inv.GetOffered()) != 2 || inv.GetOffered()[1].GetValue() != "12" || h.seenOffer != "" {
		t.Fatalf("scan = %+v, offer sent %q", inv, h.seenOffer)
	}
	got, err := svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: inv.GetInvitationId()}))
	if err != nil {
		t.Fatalf("AnswerInvitation: %v", err)
	}
	if h.seenOffer != uri || got.Msg.GetCard().GetType() != "Farmer" || !got.Msg.GetCard().GetPermanent() || got.Msg.GetCard().GetClaims()["acres"] != "12" {
		t.Fatalf("answer = %+v, sent %q", got.Msg, h.seenOffer)
	}
	if _, err = svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: inv.GetInvitationId()})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("a second answer: %v", err)
	}
	// A decline forgets the invitation and calls nothing.
	h.seenOffer = ""
	scan, err = svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: uri}))
	if err != nil {
		t.Fatal(err)
	}
	id := scan.Msg.GetDetected().GetInvitation().GetInvitationId()
	declined, err := svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: id, Decline: true}))
	if err != nil || h.seenOffer != "" || !strings.Contains(declined.Msg.GetMessage(), "sent nothing") {
		t.Errorf("decline = %+v, %v, sent %q", declined, err, h.seenOffer)
	}
	// A wallet that fails the offer fails the answer.
	again := scanID(t, svc, uri)
	h.acceptErr = errors.New("down")
	if _, err = svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: again})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed offer: %v", err)
	}
}

// TestScannedRequestAnswersWithConsent: the holder accepts a proof
// request, the stack wallet answers it, and the wallet keeps a record
// that names the verifier and the shared claims.
func TestScannedRequestAnswersWithConsent(t *testing.T) {
	h := &fakeHolder{accepted: true}
	svc := didcommWallet(t, h)
	uri := didcommInvitation("Farm board", requestMessage)
	scan, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: uri}))
	if err != nil {
		t.Fatal(err)
	}
	inv := scan.Msg.GetDetected().GetInvitation()
	if !inv.GetCarriesRequest() || inv.GetName() != "Farmer check" || strings.Join(inv.GetRequested(), "|") != "fullName|acres >= 10" {
		t.Fatalf("scan = %+v", inv)
	}
	got, err := svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: inv.GetInvitationId()}))
	if err != nil {
		t.Fatalf("AnswerInvitation: %v", err)
	}
	rec := got.Msg.GetRecord()
	if h.seenPresent.GetRequestUri() != uri || rec.GetResult() != walletportalv1.PresentationRecord_RESULT_ACCEPTED || rec.GetVerifier() != "Farm board" ||
		strings.Join(rec.GetClaims(), "|") != "fullName|acres >= 10" {
		t.Fatalf("record = %+v, sent %+v", rec, h.seenPresent)
	}
	list, err := svc.ListPresentations(ctx(), connect.NewRequest(&walletportalv1.ListPresentationsRequest{}))
	if err != nil || len(list.Msg.GetRecords()) != 1 {
		t.Errorf("history = %+v, %v", list, err)
	}
	h.accepted = false
	again := scanID(t, svc, uri)
	got, err = svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: again}))
	if err != nil || got.Msg.GetRecord().GetResult() != walletportalv1.PresentationRecord_RESULT_REJECTED {
		t.Errorf("a refused proof = %+v, %v", got, err)
	}
	h.presentErr = errors.New("down")
	again = scanID(t, svc, uri)
	if _, err = svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: again})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed proof: %v", err)
	}
}

// TestScannedConnectionInvitation: an invitation with no message makes
// a connection of the stack wallet.
func TestScannedConnectionInvitation(t *testing.T) {
	h := &fakeHolder{}
	svc := didcommWallet(t, h)
	uri := didcommInvitation("Farm board", "")
	got, err := svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: scanID(t, svc, uri)}))
	if err != nil || got.Msg.GetConnectionLabel() != "Farm board" || h.opened != uri {
		t.Fatalf("answer = %+v, %v", got, err)
	}
	h.didcommErr = errors.New("down")
	if _, err = svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: scanID(t, svc, uri)})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed connection: %v", err)
	}
}

// TestInvitationStaysWithAWalletWithoutDidcomm: a wallet whose stack
// speaks no DIDComm keeps nothing of an invitation, as before.
func TestInvitationStaysWithAWalletWithoutDidcomm(t *testing.T) {
	for name, change := range map[string]func(*service.Options){
		"browser store":    nil,
		"no didcomm stack": func(o *service.Options) { o.Holder = &fakeHolder{} },
	} {
		svc := build(t, change)
		scan, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: didcommInvitation("X", offerMessage)}))
		if err != nil || scan.Msg.GetDetected().GetInvitation().GetInvitationId() != "" {
			t.Errorf("%s: scan = %+v, %v", name, scan, err)
		}
		if _, err = svc.AnswerInvitation(ctx(), connect.NewRequest(&walletportalv1.AnswerInvitationRequest{InvitationId: "id-1"})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("%s: answer %v", name, err)
		}
		if _, err = svc.ListInbox(ctx(), connect.NewRequest(&walletportalv1.ListInboxRequest{})); connect.CodeOf(err) != connect.CodeFailedPrecondition {
			t.Errorf("%s: inbox %v", name, err)
		}
	}
}

// TestInboxAndConnections: the inbox lists what waits over a
// connection, an entry is accepted by its id, and the connections list
// names the other party.
func TestInboxAndConnections(t *testing.T) {
	h := &fakeHolder{credential: anonCard(), accepted: true,
		inbox: []*backendv1.InboxItem{
			{Id: "p-1", Kind: backendv1.InboxItem_KIND_PROOF_REQUEST, ConnectionLabel: "Farm board", Name: "Farmer check", Requested: []string{"fullName"}},
			{Id: "o-1", Kind: backendv1.InboxItem_KIND_OFFER, ConnectionLabel: "Ministry", Name: "Farmer",
				Offered: []*backendv1.OfferedValue{{Name: "acres", Value: "12"}}},
		},
		connections: []*backendv1.DidcommConnection{{Id: "c-1", Label: "Ministry", State: "completed"}},
	}
	svc := didcommWallet(t, h)
	inbox, err := svc.ListInbox(ctx(), connect.NewRequest(&walletportalv1.ListInboxRequest{}))
	if err != nil || len(inbox.Msg.GetEntries()) != 2 {
		t.Fatalf("inbox = %+v, %v", inbox, err)
	}
	proof, offer := inbox.Msg.GetEntries()[0], inbox.Msg.GetEntries()[1]
	if proof.GetKind() != walletportalv1.InboxEntry_KIND_PROOF_REQUEST || proof.GetFrom() != "Farm board" || offer.GetOffered()[0].GetValue() != "12" {
		t.Errorf("entries = %+v", inbox.Msg.GetEntries())
	}
	got, err := svc.AnswerInbox(ctx(), connect.NewRequest(&walletportalv1.AnswerInboxRequest{Id: "o-1", Kind: walletportalv1.InboxEntry_KIND_OFFER}))
	if err != nil || h.seenInbox != "o-1" || got.Msg.GetCard().GetType() != "Farmer" {
		t.Errorf("offer = %+v, %v", got, err)
	}
	got, err = svc.AnswerInbox(ctx(), connect.NewRequest(&walletportalv1.AnswerInboxRequest{Id: "p-1", Kind: walletportalv1.InboxEntry_KIND_PROOF_REQUEST}))
	if err != nil || h.seenPresent.GetInboxId() != "p-1" || got.Msg.GetRecord().GetResult() != walletportalv1.PresentationRecord_RESULT_ACCEPTED ||
		got.Msg.GetRecord().GetVerifier() != "Farm board" {
		t.Errorf("proof = %+v, %v", got, err)
	}
	if _, err = svc.AnswerInbox(ctx(), connect.NewRequest(&walletportalv1.AnswerInboxRequest{Id: "x"})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("no kind: %v", err)
	}
	conns, err := svc.ListConnections(ctx(), connect.NewRequest(&walletportalv1.ListConnectionsRequest{}))
	if err != nil || len(conns.Msg.GetConnections()) != 1 || conns.Msg.GetConnections()[0].GetLabel() != "Ministry" {
		t.Errorf("connections = %+v, %v", conns, err)
	}
	h.didcommErr = errors.New("down")
	if _, err = svc.ListInbox(ctx(), connect.NewRequest(&walletportalv1.ListInboxRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed inbox: %v", err)
	}
	if _, err = svc.ListConnections(ctx(), connect.NewRequest(&walletportalv1.ListConnectionsRequest{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("failed connections: %v", err)
	}
}

// TestPermanentCardsCarryTheFlag is ADR-062 decision 5: a credential
// that the stack wallet cannot remove gets a card that says so.
func TestPermanentCardsCarryTheFlag(t *testing.T) {
	svc := didcommWallet(t, &fakeHolder{credential: anonCard()})
	list, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{}))
	if err != nil || len(list.Msg.GetCards()) != 1 || !list.Msg.GetCards()[0].GetPermanent() {
		t.Fatalf("cards = %+v, %v", list, err)
	}
}
