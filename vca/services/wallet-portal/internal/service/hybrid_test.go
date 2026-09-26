// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// stackHolder is a stack wallet that lists names only and renders a PDF,
// as Mimoto does.
type stackHolder struct {
	fakeHolder
	docErr error
	docID  string
}

func (h *stackHolder) GetCredentialDocument(_ context.Context, req *connect.Request[backendv1.GetCredentialDocumentRequest],
) (*connect.Response[backendv1.GetCredentialDocumentResponse], error) {
	h.docID = req.Msg.GetCredentialId()
	if h.docErr != nil {
		return nil, h.docErr
	}
	return connect.NewResponse(&backendv1.GetCredentialDocumentResponse{Content: []byte("%PDF-1.4"), MediaType: "application/pdf"}), nil
}

// hybrid builds a service beside a stack wallet that claims in its own
// pages.
func hybrid(t *testing.T, h *stackHolder, on bool) *service.Service {
	t.Helper()
	return build(t, func(o *service.Options) {
		o.Holder = h
		o.Hybrid = func(context.Context) bool { return on }
		o.Fetch = fetchRequest
		o.Post = func(context.Context, string, url.Values) ([]byte, error) {
			return []byte(`{"redirect_uri":"https://verifier.example/done"}`), nil
		}
	})
}

// named is a credential of the stack wallet with names only.
func named() *backendv1.WalletCredential {
	return &backendv1.WalletCredential{Id: "c9d27f40", Type: "Farmer Credential", Issuer: "Ministry of Agriculture"}
}

// TestHybridListsTheStackAndTheBrowser lists the stack cards first and
// then the credentials the holder loaded into the browser store.
func TestHybridListsTheStackAndTheBrowser(t *testing.T) {
	h := &stackHolder{fakeHolder: fakeHolder{credential: named()}}
	svc := hybrid(t, h, true)
	if svc.BrowserStorage() || !svc.KeepsBrowser(ctx()) {
		t.Fatal("a hybrid wallet keeps the browser store beside the stack")
	}
	if _, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: token(t)})); err != nil {
		t.Fatal(err)
	}
	mine, err := svc.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	got := mine.Msg.GetCards()
	if len(got) != 2 || got[0].GetTitle() != "Farmer Credential" || got[0].GetInBrowser() || !got[1].GetInBrowser() {
		t.Fatalf("cards = %v", got)
	}
	// Without the feature the stack alone holds the credentials.
	plain := hybrid(t, &stackHolder{fakeHolder: fakeHolder{credential: named()}}, false)
	if plain.KeepsBrowser(ctx()) {
		t.Fatal("a stack wallet without the feature keeps the browser store")
	}
	if _, err := plain.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: token(t)})); err != nil {
		t.Fatal(err)
	}
	if mine, err := plain.ListMine(ctx(), connect.NewRequest(&walletportalv1.ListMineRequest{})); err != nil || len(mine.Msg.GetCards()) != 1 {
		t.Fatalf("cards = %v %v", mine.Msg.GetCards(), err)
	}
}

// TestHybridAcceptPointsAtTheStack sends the holder to the claim page of
// the stack, because the stack wallet claims only there.
func TestHybridAcceptPointsAtTheStack(t *testing.T) {
	h := &stackHolder{}
	svc := hybrid(t, h, true)
	scan, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{
		Text: "openid-credential-offer://?credential_offer=" + url.QueryEscape(`{"credential_issuer":"https://a.example","credential_configuration_ids":["dl"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"x"}}}`),
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{OfferId: scan.Msg.GetDetected().GetOfferId()}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || h.seenOffer != "" {
		t.Fatalf("accept = %v, offer %q", err, h.seenOffer)
	}
}

// TestHybridDeletesAndPresentsWhereTheCredentialSits removes and
// presents a browser credential here, and a stack credential through the
// stack.
func TestHybridDeletesAndPresentsWhereTheCredentialSits(t *testing.T) {
	h := &stackHolder{fakeHolder: fakeHolder{credential: named(), accepted: true}}
	svc := hybrid(t, h, true)
	pasted, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: token(t)}))
	if err != nil {
		t.Fatal(err)
	}
	local := pasted.Msg.GetDetected().GetOfferId()
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		SelectedCards:  map[string]string{"licence": local},
	}))
	if err != nil || !confirm.Msg.GetAccepted() || h.seenPresent != nil {
		t.Fatalf("a browser credential: %v %v, stack call %v", confirm, err, h.seenPresent)
	}
	if _, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: "openid4vp://?request_uri=https://verifier.example/r/1",
		SelectedCards:  map[string]string{"licence": "c9d27f40"},
	})); err != nil || h.seenPresent.GetCredentialIds()[0] != "c9d27f40" {
		t.Fatalf("a stack credential: %v %v", err, h.seenPresent)
	}
	if _, err := svc.Delete(ctx(), connect.NewRequest(&walletportalv1.DeleteRequest{Id: local})); err != nil || h.deletedID != "" {
		t.Fatalf("delete a browser credential: %v, stack delete %q", err, h.deletedID)
	}
	if _, err := svc.Delete(ctx(), connect.NewRequest(&walletportalv1.DeleteRequest{Id: "c9d27f40"})); err != nil || h.deletedID != "c9d27f40" {
		t.Fatalf("delete a stack credential: %v, stack delete %q", err, h.deletedID)
	}
}

// TestDocument returns the PDF of a stack credential, and it refuses
// without a stack wallet, without an id, and when the stack fails.
func TestDocument(t *testing.T) {
	h := &stackHolder{}
	svc := hybrid(t, h, true)
	doc, err := svc.Document(ctx(), connect.NewRequest(&walletportalv1.DocumentRequest{Id: "c9d27f40"}))
	if err != nil || doc.Msg.GetMediaType() != "application/pdf" || h.docID != "c9d27f40" {
		t.Fatalf("document = %v %v", doc, err)
	}
	if _, err := svc.Document(ctx(), connect.NewRequest(&walletportalv1.DocumentRequest{})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no id: %v", err)
	}
	if _, err := svc.Document(context.Background(), connect.NewRequest(&walletportalv1.DocumentRequest{Id: "x"})); err == nil {
		t.Fatal("a call without a session passed")
	}
	h.docErr = errors.New("down")
	if _, err := svc.Document(ctx(), connect.NewRequest(&walletportalv1.DocumentRequest{Id: "x"})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("stack down: %v", err)
	}
	browser := build(t, nil)
	if _, err := browser.Document(ctx(), connect.NewRequest(&walletportalv1.DocumentRequest{Id: "x"})); connect.CodeOf(err) != connect.CodeUnimplemented {
		t.Fatalf("browser: %v", err)
	}
}
