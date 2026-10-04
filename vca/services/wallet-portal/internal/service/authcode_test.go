// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// authCodeIssuer is the claim stack with an authorization server that
// takes pushed authorization requests (RFC 9126) and the authorization
// code grant with PKCE (RFC 7636).
type authCodeIssuer struct {
	*claimStack
	// par holds the pushed authorization requests.
	par []url.Values
	// pushed turns the pushed authorization endpoint on.
	pushed bool
}

func (a *authCodeIssuer) post(ctx context.Context, address string, form url.Values) ([]byte, error) {
	if address == claimIssuer+"/par" {
		a.par = append(a.par, form)
		return []byte(`{"request_uri":"urn:ietf:params:oauth:request_uri:r-1","expires_in":60}`), nil
	}
	return a.claimStack.post(ctx, address, form)
}

func (a *authCodeIssuer) endpoints(context.Context, string) (issuers.Endpoints, error) {
	ends := issuers.Endpoints{Authorization: claimIssuer + "/authorize", Token: claimToken}
	if a.pushed {
		ends.PushedAuthorization = claimIssuer + "/par"
	}
	return ends, nil
}

// authCodeOffer is an offer that names only the authorization code
// grant, with the issuer_state of the issuer.
const authCodeOffer = "openid-credential-offer://?credential_offer=" +
	`%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.example%22%2C%22credential_configuration_ids%22%3A%5B%22licence_sd_jwt%22%5D%2C` +
	`%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22st-9%22%7D%7D%7D`

// TestBrowserStoreClaimsWithTheAuthorizationCode is ADR-082: the browser
// store starts the authorization request with PKCE, pushes it when the
// issuer takes pushed requests, trades the code at the callback, and
// claims the credential with the proof the browser signs.
func TestBrowserStoreClaimsWithTheAuthorizationCode(t *testing.T) {
	for _, pushed := range []bool{true, false} {
		a := &authCodeIssuer{claimStack: newClaimStack(t), pushed: pushed}
		svc := build(t, func(o *service.Options) {
			o.Fetch, o.Post, o.PostCredential = a.fetch, a.post, a.credential
			o.RequestHosts = []string{"issuer.example"}
			o.Endpoints = a.endpoints
		})
		pasted, err := svc.Paste(ctx(), connect.NewRequest(&walletportalv1.PasteRequest{Text: authCodeOffer}))
		if err != nil {
			t.Fatal(err)
		}
		if !pasted.Msg.GetDetected().GetOffer().GetSignIn() {
			t.Fatalf("the offer summary %+v does not ask for a sign in", pasted.Msg.GetDetected().GetOffer())
		}
		started, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
			OfferId: pasted.Msg.GetDetected().GetOfferId(), RedirectUri: "https://wallet.example/wallet/claim/callback",
		}))
		if err != nil {
			t.Fatal(err)
		}
		next, err := url.Parse(started.Msg.GetAuthorizationUrl())
		if err != nil || next.Host != "issuer.example" || next.Path != "/authorize" {
			t.Fatalf("pushed %v: the authorization URL is %q, want the endpoint of the issuer", pushed, started.Msg.GetAuthorizationUrl())
		}
		q := next.Query()
		params := q
		if pushed {
			if len(a.par) != 1 || q.Get("request_uri") != "urn:ietf:params:oauth:request_uri:r-1" || q.Get("client_id") == "" {
				t.Fatalf("the pushed request %v gave the URL %v", a.par, q)
			}
			params = a.par[0]
		}
		if params.Get("code_challenge_method") != "S256" || params.Get("issuer_state") != "st-9" ||
			!strings.Contains(params.Get("authorization_details"), "licence_sd_jwt") || params.Get("state") == "" {
			t.Fatalf("pushed %v: the authorization request %v lacks PKCE, the issuer_state or the credential", pushed, params)
		}
		done, err := svc.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{
			State: params.Get("state"), Code: "code-7",
		}))
		if err != nil {
			t.Fatal(err)
		}
		token := a.tokens[len(a.tokens)-1]
		sum := sha256.Sum256([]byte(token.Get("code_verifier")))
		if token.Get("grant_type") != "authorization_code" || token.Get("code") != "code-7" ||
			base64.RawURLEncoding.EncodeToString(sum[:]) != params.Get("code_challenge") {
			t.Fatalf("the token request %v does not prove the PKCE challenge", token)
		}
		offerID := done.Msg.GetOfferId()
		if offerID == "" || done.Msg.GetOffer().GetCredentialIssuer() != claimIssuer {
			t.Fatalf("the callback answered %+v, want an authorized offer for the browser", done.Msg)
		}
		browser := newBrowserHolder(t)
		step, err := svc.ClaimStart(ctx(), offerID, "", browser.jwk)
		if err != nil {
			t.Fatal(err)
		}
		got, err := svc.ClaimFinish(ctx(), step.ID, browser.sign(t, step.SigningInput))
		if err != nil || !strings.Contains(got.Credential, "~") {
			t.Fatalf("ClaimFinish = %+v, %v", got, err)
		}
	}
}

// TestAuthorizationCodeRefusals names each step that stops the flow.
func TestAuthorizationCodeRefusals(t *testing.T) {
	a := &authCodeIssuer{claimStack: newClaimStack(t), pushed: true}
	svc := build(t, func(o *service.Options) {
		o.Fetch, o.Post, o.PostCredential = a.fetch, a.post, a.credential
		o.RequestHosts = []string{"issuer.example"}
		o.Endpoints = a.endpoints
	})
	if _, err := svc.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: "unknown", Code: "c"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown state: %v", err)
	}
	if _, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{OfferId: "unknown", RedirectUri: "https://w.example/cb"})); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("an unknown offer: %v", err)
	}
	started, err := svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: claimIssuer, SchemaId: "licence_sd_jwt", RedirectUri: "https://w.example/cb",
	}))
	if err != nil {
		t.Fatal(err)
	}
	state := lastState(t, a)
	if started.Msg.GetAuthorizationUrl() == "" || state == "" {
		t.Fatalf("a claim from the catalogue answered %+v", started.Msg)
	}
	if _, cerr := svc.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: state, Error: "access_denied"})); connect.CodeOf(cerr) != connect.CodePermissionDenied {
		t.Errorf("a refused sign in: %v", cerr)
	}
	a.tokenErr = context.DeadlineExceeded
	started, err = svc.Claim(ctx(), connect.NewRequest(&walletportalv1.ClaimRequest{
		CredentialIssuer: claimIssuer, SchemaId: "licence_sd_jwt", RedirectUri: "https://w.example/cb",
	}))
	if err != nil {
		t.Fatal(err)
	}
	state = lastState(t, a)
	if _, cerr := svc.ClaimComplete(ctx(), connect.NewRequest(&walletportalv1.ClaimCompleteRequest{State: state, Code: "c"})); connect.CodeOf(cerr) != connect.CodeUnavailable {
		t.Errorf("a token endpoint that fails: %v (%v)", cerr, started.Msg)
	}
}

// lastState returns the state of the last pushed authorization request.
func lastState(t *testing.T, a *authCodeIssuer) string {
	t.Helper()
	if len(a.par) == 0 {
		t.Fatal("the wallet pushed no authorization request")
	}
	return a.par[len(a.par)-1].Get("state")
}
