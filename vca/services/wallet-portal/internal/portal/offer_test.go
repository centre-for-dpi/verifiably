// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

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
