// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// The addresses of the interactive issuer of the tests.
const (
	iarOffer    = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer-inji.vca.example%2Foffers%2Fo1"
	iarServer   = "https://certify.example/v1/certify"
	iarEndpoint = iarServer + "/oauth/iar"
	iarToken    = iarServer + "/oauth/token"
)

// iarStack answers as the interactive authorization server of an issuer
// that asks for a presentation first.
type iarStack struct {
	calls  []url.Values
	urls   []string
	finish string
}

func (s *iarStack) post(_ context.Context, address string, form url.Values) ([]byte, error) {
	s.urls = append(s.urls, address)
	s.calls = append(s.calls, form)
	switch {
	case address == iarToken:
		return []byte(`{"access_token":"at-iar","token_type":"Bearer","c_nonce":"n"}`), nil
	case address == iarEndpoint && form.Get("auth_session") != "":
		if s.finish != "" {
			return []byte(s.finish), nil
		}
		return []byte(`{"status":"ok","code":"iar_auth_1"}`), nil
	case address == iarEndpoint:
		return json.Marshal(map[string]any{
			"status": "require_interaction", "type": "openid4vp_presentation", "auth_session": "sess-1",
			"openid4vp_request": map[string]any{
				"response_type": "vp_token", "response_mode": "iar-post", "client_id": "did:web:verify.inji.example",
				"nonce": "n-9", "response_uri": iarEndpoint,
				"presentation_definition": map[string]any{
					"id": "licence-check", "purpose": "The issuer checks your licence first.",
					"input_descriptors": []any{map[string]any{
						"id": "driver licence", "format": map[string]any{"dc+sd-jwt": map[string]any{}},
						"constraints": map[string]any{"fields": []any{
							map[string]any{"path": []string{"$.vct"}, "filter": map[string]any{"type": "string", "const": "DriverLicence"}},
							map[string]any{"path": []string{"$.given_name"}},
						}},
					}},
				},
			},
		})
	}
	return nil, errors.New("unknown address " + address)
}

// iarOfferDocument is the offer the adapter hosts.
func iarOfferDocument(context.Context, string) ([]byte, error) {
	return []byte(`{"credential_issuer":"https://certify.example","credential_configuration_ids":["FarmerCredential"],` +
		`"grants":{"authorization_code":{"issuer_state":"st-1","authorization_server":"` + iarServer + `"}}}`), nil
}

// iarServers returns the endpoints of the interactive server.
func iarServers(_ context.Context, server string) (issuers.Endpoints, error) {
	if server != iarServer {
		return issuers.Endpoints{}, issuers.ErrNoEndpoints
	}
	return issuers.Endpoints{Token: iarToken, Interactive: iarEndpoint}, nil
}

// iarService builds a wallet with a DPG wallet and the interactive stack.
func iarService(t *testing.T, stack *iarStack, holder *fakeHolder) *service.Service {
	t.Helper()
	return build(t, func(o *service.Options) {
		o.Holder = holder
		o.Fetch = iarOfferDocument
		o.Post = stack.post
		o.Servers = iarServers
		o.RequestHosts = []string{"verifier.example", "issuer-inji.vca.example"}
	})
}

// TestWalletAnswersPresentationDuringIssuance claims an offer whose
// issuer asks for a presentation first. The wallet starts the
// interactive authorization, shows the request on the consent screen,
// sends the presentation, trades the code for an access token, and
// claims the credential into the DPG wallet with it.
func TestWalletAnswersPresentationDuringIssuance(t *testing.T) {
	stack := &iarStack{}
	holder := &fakeHolder{credential: credential(t)}
	svc := iarService(t, stack, holder)
	pasted, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: iarOffer}))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{OfferId: pasted.Msg.GetDetected().GetOfferId()}))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	id := accepted.Msg.GetPresentationId()
	if id == "" || accepted.Msg.GetCard() != nil || holder.seenOffer != "" {
		t.Fatalf("accept = %+v, the wallet claimed before the presentation", accepted.Msg)
	}
	first := stack.calls[0]
	if first.Get("response_type") != "code" || first.Get("code_challenge_method") != "S256" || first.Get("code_challenge") == "" ||
		first.Get("interaction_types_supported") != "openid4vp_presentation" || first.Get("issuer_state") != "st-1" ||
		!strings.Contains(first.Get("authorization_details"), `"credential_configuration_id":"FarmerCredential"`) {
		t.Fatalf("first request = %v", first)
	}
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{PresentationId: id}))
	if err != nil {
		t.Fatalf("PresentStart: %v", err)
	}
	if !start.Msg.GetDuringIssuance() || start.Msg.GetVerifier() != "https://certify.example" ||
		start.Msg.GetPurpose() != "The issuer checks your licence first." {
		t.Fatalf("start = %+v", start.Msg)
	}
	requested := start.Msg.GetRequested()
	if len(requested) != 1 || len(requested[0].GetMatches()) != 1 {
		t.Fatalf("requested = %+v", requested)
	}
	query := requested[0].GetQueryId()
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: id, SelectedCards: map[string]string{query: "c1"},
		Disclosed: map[string]*walletportalv1.PresentConfirmRequest_ClaimPaths{query: {Paths: []string{"given_name"}}},
	}))
	if err != nil {
		t.Fatalf("PresentConfirm: %v", err)
	}
	if !confirm.Msg.GetAccepted() || confirm.Msg.GetCard() == nil || confirm.Msg.GetRecord().GetVerifier() != "https://certify.example" {
		t.Fatalf("confirm = %+v", confirm.Msg)
	}
	second := stack.calls[1]
	var answer struct {
		VPToken    string `json:"vp_token"`
		Submission struct {
			DefinitionID string `json:"definition_id"`
			Map          []struct {
				ID     string `json:"id"`
				Format string `json:"format"`
				Path   string `json:"path"`
			} `json:"descriptor_map"`
		} `json:"presentation_submission"`
	}
	if err := json.Unmarshal([]byte(second.Get("openid4vp_response")), &answer); err != nil || second.Get("auth_session") != "sess-1" {
		t.Fatalf("second request = %v (%v)", second, err)
	}
	if !strings.HasPrefix(answer.VPToken, "eyJ") || strings.Count(answer.VPToken, "~") != 2 || answer.Submission.DefinitionID != "licence-check" ||
		len(answer.Submission.Map) != 1 || answer.Submission.Map[0].ID != "driver licence" || answer.Submission.Map[0].Format != "dc+sd-jwt" {
		t.Fatalf("openid4vp_response = %+v", answer)
	}
	token := stack.calls[2]
	if stack.urls[2] != iarToken || token.Get("grant_type") != "authorization_code" || token.Get("code") != "iar_auth_1" ||
		token.Get("code_verifier") == "" || token.Has("redirect_uri") {
		t.Fatalf("token request = %v", token)
	}
	if holder.seenGrant != "at-iar" || holder.seenOffer != iarOffer {
		t.Fatalf("the DPG wallet got grant %q and offer %q", holder.seenGrant, holder.seenOffer)
	}
	if _, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{PresentationId: id})); err == nil {
		t.Fatal("the step stays open after the claim")
	}
}

// TestWalletPresentationDuringIssuanceRefused reports a presentation the
// issuer does not accept, and claims nothing.
func TestWalletPresentationDuringIssuanceRefused(t *testing.T) {
	stack := &iarStack{finish: `{"status":"error","error":"invalid_vp"}`}
	holder := &fakeHolder{credential: credential(t)}
	svc := iarService(t, stack, holder)
	pasted, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: iarOffer}))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{OfferId: pasted.Msg.GetDetected().GetOfferId()}))
	if err != nil {
		t.Fatal(err)
	}
	id := accepted.Msg.GetPresentationId()
	start, err := svc.PresentStart(ctx(), connect.NewRequest(&walletportalv1.PresentStartRequest{PresentationId: id}))
	if err != nil {
		t.Fatal(err)
	}
	query := start.Msg.GetRequested()[0].GetQueryId()
	confirm, err := svc.PresentConfirm(ctx(), connect.NewRequest(&walletportalv1.PresentConfirmRequest{
		PresentationId: id, SelectedCards: map[string]string{query: "c1"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if confirm.Msg.GetAccepted() || confirm.Msg.GetCard() != nil || holder.seenOffer != "" {
		t.Fatalf("confirm = %+v", confirm.Msg)
	}
	// A decline ends the step and tells no one.
	pasted, err = svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: iarOffer}))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err = svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{OfferId: pasted.Msg.GetDetected().GetOfferId()}))
	if err != nil {
		t.Fatal(err)
	}
	calls := len(stack.calls)
	if _, err := svc.PresentDecline(ctx(), connect.NewRequest(&walletportalv1.PresentDeclineRequest{
		PresentationId: accepted.Msg.GetPresentationId(),
	})); err != nil {
		t.Fatal(err)
	}
	if len(stack.calls) != calls {
		t.Fatal("a decline posted to the issuer")
	}
}

// TestWalletLeavesAPlainOfferToTheDpgWallet hands an offer without an
// interactive server to the DPG wallet as before.
func TestWalletLeavesAPlainOfferToTheDpgWallet(t *testing.T) {
	stack := &iarStack{}
	holder := &fakeHolder{credential: credential(t)}
	svc := build(t, func(o *service.Options) {
		o.Holder = holder
		o.Fetch = func(context.Context, string) ([]byte, error) {
			return []byte(`{"credential_issuer":"https://a.example","credential_configuration_ids":["dl"],` +
				`"grants":{"authorization_code":{"authorization_server":"https://idp.example"}}}`), nil
		}
		o.Post = stack.post
		o.Servers = iarServers
		o.RequestHosts = []string{"issuer-inji.vca.example"}
	})
	for _, text := range []string{iarOffer, "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Felsewhere.example%2Fo",
		`openid-credential-offer://?credential_offer={"credential_issuer":"https://a.example","grants":{"authorization_code":{}}}`} {
		pasted, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: text}))
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := svc.Accept(ctx(), connect.NewRequest(&walletportalv1.AcceptRequest{OfferId: pasted.Msg.GetDetected().GetOfferId()}))
		if err != nil {
			t.Fatal(err)
		}
		if accepted.Msg.GetCard() == nil || accepted.Msg.GetPresentationId() != "" || holder.seenOffer != text {
			t.Fatalf("%s: accept = %+v", text, accepted.Msg)
		}
	}
	if len(stack.calls) != 0 {
		t.Fatalf("the wallet called the interactive server: %v", stack.urls)
	}
}
