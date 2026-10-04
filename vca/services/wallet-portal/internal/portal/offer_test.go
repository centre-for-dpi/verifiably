// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
)

// offerMetadata is issuer metadata with a display name, a type display
// name, and the display names of the claims (OID4VCI 1.0 section 12.2).
const offerMetadata = `{"credential_issuer":"https://issuer.example","credential_endpoint":"https://issuer.example/credential",` +
	`"token_endpoint":"https://issuer.example/token","display":[{"name":"Demo Licensing Office","locale":"en"}],` +
	`"credential_configurations_supported":{"dl":{"format":"dc+sd-jwt","vct":"DriverLicence",` +
	`"display":[{"name":"Driver licence","locale":"en"}],` +
	`"claims":[{"path":["given_name"],"display":[{"name":"Given name"}]},{"path":["birth_date"]}]}}}`

// withMetadata wires the browser store to an issuer whose metadata
// answers with meta, or fails when meta is empty.
func withMetadata(t *testing.T, meta string) func(*service.Options) {
	t.Helper()
	base := withIssuer(t)
	return func(o *service.Options) {
		base(o)
		fetch := o.Fetch
		o.Fetch = func(ctx context.Context, address string) ([]byte, error) {
			if address == "https://issuer.example/.well-known/openid-credential-issuer" {
				if meta == "" {
					return nil, errors.New("down")
				}
				return []byte(meta), nil
			}
			return fetch(ctx, address)
		}
	}
}

// TestOfferPageNamesTheIssuerAndTheCredential reproduces the blank
// offer page of the proof run (walt.id step 069): the page asked the
// holder to read the issuer name and showed none. The page now names
// the issuer, its address and its trust state, the credential type, and
// the claims the credential carries.
func TestOfferPageNamesTheIssuerAndTheCredential(t *testing.T) {
	h := setupShell(t, withMetadata(t, offerMetadata), holderDeployment())
	page := h.post(t, "/wallet/claim/offer", url.Values{"offer": {browserOffer}}).Body.String()
	for _, want := range []string{
		"Agency A", "https://issuer.example", "Issuer: trusted", "Driver licence", "Given name", "birth_date",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("the offer page misses %q\n%s", want, page)
		}
	}
}

// TestOfferPageSaysWhenTheMetadataIsUnread names the issuer address and
// says the wallet could not read the metadata.
func TestOfferPageSaysWhenTheMetadataIsUnread(t *testing.T) {
	h := setupShell(t, withMetadata(t, ""), holderDeployment())
	page := h.post(t, "/wallet/claim/offer", url.Values{"offer": {browserOffer}}).Body.String()
	for _, want := range []string{"https://issuer.example", "The wallet could not read the metadata of the issuer."} {
		if !strings.Contains(page, want) {
			t.Fatalf("the offer page misses %q\n%s", want, page)
		}
	}
}

// TestBrowserStoreSignsInAtTheIssuer is ADR-082 on the pages: an offer
// of the authorization code grant asks the holder to sign in first, the
// claim form sends the browser to the authorization endpoint, and the
// callback opens the claim form that wallet.js signs.
func TestBrowserStoreSignsInAtTheIssuer(t *testing.T) {
	base := withMetadata(t, offerMetadata)
	h := setupShell(t, func(o *service.Options) {
		base(o)
		o.Endpoints = func(context.Context, string) (issuers.Endpoints, error) {
			return issuers.Endpoints{Authorization: "https://issuer.example/authorize", Token: "https://issuer.example/token"}, nil
		}
		fetch := o.Fetch
		o.Fetch = func(ctx context.Context, address string) ([]byte, error) {
			if address == "https://issuer.example/offers/1" {
				return []byte(`{"credential_issuer":"https://issuer.example","credential_configuration_ids":["dl"],` +
					`"grants":{"authorization_code":{"issuer_state":"st-1"}}}`), nil
			}
			return fetch(ctx, address)
		}
	}, holderDeployment())
	page := h.post(t, "/wallet/claim/offer", url.Values{"offer": {browserOffer}}).Body.String()
	if !strings.Contains(page, "The issuer asks you to sign in first.") || strings.Contains(page, "data-browser-claim") ||
		!strings.Contains(page, `action="/wallet/claim"`) {
		t.Fatalf("the offer page does not ask for the sign in first\n%s", page)
	}
	start := h.post(t, "/wallet/claim", url.Values{"offer_id": {offerIDOf(t, page)}})
	next, err := url.Parse(start.Header().Get("Location"))
	if err != nil || next.Host != "issuer.example" || next.Query().Get("issuer_state") != "st-1" {
		t.Fatalf("the claim form sent the browser to %q", start.Header().Get("Location"))
	}
	back := h.get(t, "/wallet/claim/callback?code=c-1&state="+url.QueryEscape(next.Query().Get("state"))).Body.String()
	if !strings.Contains(back, "data-browser-claim") || !strings.Contains(back, "Driver licence") {
		t.Fatalf("the callback does not open the claim of the browser\n%s", back)
	}
}
