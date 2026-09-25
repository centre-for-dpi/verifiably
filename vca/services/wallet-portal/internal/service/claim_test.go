// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// signIn sets the endpoints of the issuer and a token endpoint that
// answers with an access token.
func signIn(posted *url.Values) func(*service.Options) {
	return func(o *service.Options) {
		o.ClientID = "vca-wallet"
		o.Endpoints = func(_ context.Context, issuer string) (issuers.Endpoints, error) {
			if issuer != "https://a.example" {
				return issuers.Endpoints{}, errors.New("no server")
			}
			return issuers.Endpoints{Authorization: "https://login.a.example/auth?realm=a", Token: "https://login.a.example/token"}, nil
		}
		o.Post = func(_ context.Context, target string, form url.Values) ([]byte, error) {
			if target != "https://login.a.example/token" {
				return nil, errors.New("wrong endpoint")
			}
			*posted = form
			return []byte(`{"access_token":"at-1","token_type":"Bearer"}`), nil
		}
	}
}

// TestClaimAuthCodeFlow checks the sign in at the issuer: the claim
// returns the authorization URL with PKCE and the configuration, and the
// answer of the issuer trades the code for a token that the DPG wallet
// uses as the grant.
func TestClaimAuthCodeFlow(t *testing.T) {
	holder := &fakeHolder{credential: credential(t)}
	var posted url.Values
	svc := build(t, func(o *service.Options) { withHolder(holder)(o); signIn(&posted)(o) })
	resp, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: "https://a.example", SchemaId: "dl", RedirectUri: "https://wallet.example/wallet/claim/callback",
	}))
	if err != nil {
		t.Fatal(err)
	}
	next, err := url.Parse(resp.Msg.GetAuthorizationUrl())
	if err != nil || next.Host != "login.a.example" || next.Path != "/auth" {
		t.Fatalf("authorization URL = %q", resp.Msg.GetAuthorizationUrl())
	}
	q := next.Query()
	for name, want := range map[string]string{
		"realm": "a", "response_type": "code", "client_id": "vca-wallet",
		"redirect_uri": "https://wallet.example/wallet/claim/callback", "code_challenge_method": "S256",
	} {
		if q.Get(name) != want {
			t.Fatalf("%s = %q", name, q.Get(name))
		}
	}
	if !strings.Contains(q.Get("authorization_details"), `"credential_configuration_id":"dl"`) || q.Get("state") == "" {
		t.Fatalf("query = %v", q)
	}
	if holder.seenOffer != "" {
		t.Fatal("the wallet claimed before the sign in")
	}
	// A state of another step, or a refusal, claims nothing.
	if _, unknown := svc.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: "nope", Code: "c"})); connect.CodeOf(unknown) != connect.CodeNotFound {
		t.Fatalf("unknown state: %v", unknown)
	}
	done, err := svc.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: q.Get("state"), Code: "code-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if done.Msg.GetCard().GetId() != "c1" || holder.seenGrant != "at-1" || !strings.Contains(holder.seenOffer, "authorization_code") {
		t.Fatalf("card = %v grant = %q offer = %q", done.Msg.GetCard(), holder.seenGrant, holder.seenOffer)
	}
	sum := sha256.Sum256([]byte(posted.Get("code_verifier")))
	if posted.Get("grant_type") != "authorization_code" || posted.Get("code") != "code-1" || posted.Get("client_id") != "vca-wallet" ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") ||
		posted.Get("redirect_uri") != "https://wallet.example/wallet/claim/callback" {
		t.Fatalf("token form = %v", posted)
	}
	// The state works once.
	if _, twice := svc.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: q.Get("state"), Code: "code-1"})); connect.CodeOf(twice) != connect.CodeNotFound {
		t.Fatalf("twice: %v", twice)
	}
}

// TestClaimCompleteProblems checks the faults after the sign in: a
// refusal of the issuer, a token endpoint that fails or answers no
// token, and a wallet that does not take the credential.
func TestClaimCompleteProblems(t *testing.T) {
	start := func(t *testing.T, svc *service.Service) string {
		t.Helper()
		resp, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
			CredentialIssuer: "https://a.example", SchemaId: "dl", RedirectUri: "https://wallet.example/cb",
		}))
		if err != nil {
			t.Fatal(err)
		}
		next, err := url.Parse(resp.Msg.GetAuthorizationUrl())
		if err != nil {
			t.Fatal(err)
		}
		return next.Query().Get("state")
	}
	var posted url.Values
	refused := build(t, func(o *service.Options) { withHolder(&fakeHolder{credential: credential(t)})(o); signIn(&posted)(o) })
	state := start(t, refused)
	if _, err := refused.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: state, Error: "access_denied"})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("refused: %v", err)
	}
	for name, answer := range map[string]func(context.Context, string, url.Values) ([]byte, error){
		"down": func(context.Context, string, url.Values) ([]byte, error) { return nil, errors.New("down") },
		"no token": func(context.Context, string, url.Values) ([]byte, error) {
			return []byte(`{"error":"invalid_grant"}`), nil
		},
	} {
		svc := build(t, func(o *service.Options) {
			withHolder(&fakeHolder{credential: credential(t)})(o)
			signIn(&posted)(o)
			o.Post = answer
		})
		pending := start(t, svc)
		if _, err := svc.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: pending, Code: "c"})); connect.CodeOf(err) != connect.CodeUnavailable {
			t.Fatalf("%s: %v", name, err)
		}
	}
	wallet := build(t, func(o *service.Options) {
		withHolder(&fakeHolder{acceptErr: errors.New("down")})(o)
		signIn(&posted)(o)
	})
	state = start(t, wallet)
	if _, err := wallet.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: state, Code: "c"})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("wallet down: %v", err)
	}
	if _, err := wallet.ClaimComplete(context.Background(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no session: %v", err)
	}
	// An issuer with no authorization server falls back to the DPG
	// wallet, which runs the flow with the grant of the IdP.
	holder := &fakeHolder{credential: credential(t)}
	plain := build(t, func(o *service.Options) { withHolder(holder)(o); signIn(&posted)(o) })
	resp, err := plain.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: "https://other.example", SchemaId: "dl", RedirectUri: "https://wallet.example/cb",
	}))
	if err != nil || resp.Msg.GetCard().GetId() != "c1" || resp.Msg.GetAuthorizationUrl() != "" {
		t.Fatalf("fallback = %v, %v", resp, err)
	}
}
