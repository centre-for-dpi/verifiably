// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"crypto"
	"crypto/ecdsa"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// claimed claims the credential of the stack into the browser store and
// returns the service and the browser.
func claimed(t *testing.T, stack *claimStack) (*service.Service, browserHolder) {
	t.Helper()
	svc := browserStore(t, stack)
	browser := newBrowserHolder(t)
	step, err := svc.ClaimStart(ctx(), pasteOffer(t, svc), "4821", browser.jwk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput)); err != nil {
		t.Fatal(err)
	}
	return svc, browser
}

// consent opens the request of the verifier and returns the answer that
// shares the given name of the held credential.
func consent(t *testing.T, svc *service.Service) *walletportalv1.PresentConfirmRequest {
	t.Helper()
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
	matches := start.Msg.GetRequested()[0].GetMatches()
	if len(matches) != 1 {
		t.Fatalf("matches = %v", matches)
	}
	return &walletportalv1.PresentConfirmRequest{
		PresentationId: id,
		SelectedCards:  map[string]string{"licence": matches[0].GetId()},
		Disclosed:      map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{"licence": {Paths: []string{"given_name"}}},
	}
}

// TestAnswerOfABoundCredentialCarriesTheBrowserKeyBinding is ADR-073:
// the portal hands the browser the key binding input of the disclosed
// token, the browser signs it, and the verifier gets a presentation that
// core/sdjwt accepts with the audience and the nonce of the request.
func TestAnswerOfABoundCredentialCarriesTheBrowserKeyBinding(t *testing.T) {
	stack := newClaimStack(t)
	svc, browser := claimed(t, stack)
	req := consent(t, svc)
	input, err := svc.BindingInput(ctx(), req)
	if err != nil || input == "" {
		t.Fatalf("BindingInput = %q, %v", input, err)
	}
	req.KeyBinding = input + "." + browser.sign(t, input)
	resp, err := svc.PresentConfirm(ctx(), connect.NewRequest(req))
	if err != nil {
		t.Fatalf("PresentConfirm: %v", err)
	}
	if resp.Msg.GetRecord() == nil {
		t.Fatal("the wallet kept no record of the answer")
	}
	token := stack.posted.Get("vp_token")
	signer, ok := stack.issuer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("issuer key %T", stack.issuer)
	}
	if _, err := sdjwt.Verify(token, sdjwt.VerifyOptions{
		IssuerKey:         func(jose.Header, map[string]any) (crypto.PublicKey, error) { return signer.Public(), nil },
		RequireKeyBinding: true, Audience: "https://verifier.example", Nonce: "n-1", Now: clock.Add(time.Minute),
	}); err != nil {
		t.Fatalf("the verifier refuses the answer: %v\n%s", err, token)
	}
}

// TestABoundAnswerNeedsTheBrowserKeyBinding: with no key binding, or one
// over another answer, the portal refuses and sends nothing.
func TestABoundAnswerNeedsTheBrowserKeyBinding(t *testing.T) {
	stack := newClaimStack(t)
	svc, browser := claimed(t, stack)
	req := consent(t, svc)
	if _, err := svc.PresentConfirm(ctx(), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("no key binding: err = %v", err)
	}
	req = consent(t, svc)
	other := newBrowserHolder(t)
	input, err := svc.BindingInput(ctx(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.KeyBinding = input + "." + other.sign(t, input)
	if _, err := svc.PresentConfirm(ctx(), connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("a key binding of another key: err = %v", err)
	}
	_ = browser
	if stack.posted != nil {
		t.Fatalf("the verifier got %v", stack.posted)
	}
}

// TestAnUnboundCredentialNeedsNoBinding: a pasted credential with no
// holder key presents as before, and the input is empty.
func TestAnUnboundCredentialNeedsNoBinding(t *testing.T) {
	stack := newClaimStack(t)
	svc := browserStore(t, stack)
	if _, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: token(t)})); err != nil {
		t.Fatal(err)
	}
	req := consent(t, svc)
	input, err := svc.BindingInput(ctx(), req)
	if err != nil || input != "" {
		t.Fatalf("BindingInput = %q, %v; want none", input, err)
	}
	if _, err := svc.PresentConfirm(ctx(), connect.NewRequest(req)); err != nil {
		t.Fatalf("PresentConfirm: %v", err)
	}
	if _, err := svc.BindingInput(ctx(), &walletportalv1.PresentConfirmRequest{PresentationId: ""}); err == nil {
		t.Fatal("a request with no presentation gave an input")
	}
}

// TestTheBindingAndTheAnswerShareOneRequest: a verifier that hands each
// read of its request a new nonce still gets an answer whose key binding
// names the nonce of the consent page. The wallet reads the request
// once and keeps it until the answer goes, so the nonce that the browser
// signs is the nonce of the answer.
func TestTheBindingAndTheAnswerShareOneRequest(t *testing.T) {
	stack := newClaimStack(t)
	stack.freshNonce = true
	svc, browser := claimed(t, stack)
	req := consent(t, svc)
	input, err := svc.BindingInput(ctx(), req)
	if err != nil || input == "" {
		t.Fatalf("BindingInput = %q, %v", input, err)
	}
	req.KeyBinding = input + "." + browser.sign(t, input)
	if _, err := svc.PresentConfirm(ctx(), connect.NewRequest(req)); err != nil {
		t.Fatalf("PresentConfirm: %v", err)
	}
	signer, ok := stack.issuer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("issuer key %T", stack.issuer)
	}
	if _, err := sdjwt.Verify(stack.posted.Get("vp_token"), sdjwt.VerifyOptions{
		IssuerKey:         func(jose.Header, map[string]any) (crypto.PublicKey, error) { return signer.Public(), nil },
		RequireKeyBinding: true, Audience: "https://verifier.example", Nonce: "n-1", Now: clock.Add(time.Minute),
	}); err != nil {
		t.Fatalf("the answer does not carry the nonce of the consent page: %v", err)
	}
	if stack.fetches != 1 {
		t.Errorf("the wallet read the request %d times, want once", stack.fetches)
	}
}
