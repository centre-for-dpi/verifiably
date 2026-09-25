// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	walletportalv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// pinOffer is a pre-authorized offer that needs a transaction code.
const pinOffer = `openid-credential-offer://?credential_offer=` +
	`%7B%22credential_issuer%22%3A%22https%3A%2F%2Fa.example%22%2C` +
	`%22credential_configuration_ids%22%3A%5B%22dl%22%5D%2C%22grants%22%3A%7B` +
	`%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22tx_code%22%3A%7B%7D%7D%7D%7D`

// recordingHolder records the offer, the code and the grant it gets.
type recordingHolder struct {
	fakeHolder
	offer, pin, grant string
}

func (f *recordingHolder) AcceptOffer(_ context.Context, req *connect.Request[backendv1.AcceptOfferRequest],
) (*connect.Response[backendv1.AcceptOfferResponse], error) {
	f.offer, f.pin, f.grant = req.Msg.GetOfferUri(), req.Msg.GetPin(), req.Msg.GetAuthorizationGrant()
	return connect.NewResponse(&backendv1.AcceptOfferResponse{Credential: f.credential}), nil
}

// TestClaimPreAuthWithTxCode checks the card "Code or QR":
// the holder pastes the offer and the transaction code, and the wallet
// claims at once. An offer that needs a code the holder did not give
// asks for it first.
func TestClaimPreAuthWithTxCode(t *testing.T) {
	holder := &recordingHolder{fakeHolder: fakeHolder{credential: credential(t)}}
	h := setupShell(t, func(o *serviceOptions) { o.Holder = holder }, holderDeployment())
	page := h.get(t, "/wallet/claim")
	body := page.Body.String()
	for _, want := range []string{
		"Claim a credential", "Code or QR", `name="offer"`, `name="tx_code"`, `inputmode="numeric"`,
		`id="scan-start"`, `id="scan-form" data-ingest="/wallet/scan/read"`, "/wallet/static/scanner.js", "/wallet/static/jsqr.min.js",
		"Sign in at issuer",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("claim page misses %s\n%s", want, body)
		}
	}
	rec := h.post(t, "/wallet/claim/offer", url.Values{"offer": {pinOffer}, "tx_code": {"493817"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/wallet/" {
		t.Fatalf("status = %d location = %q body = %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if holder.pin != "493817" || !strings.Contains(holder.offer, "a.example") {
		t.Fatalf("pin = %q offer = %q", holder.pin, holder.offer)
	}
	ask := h.post(t, "/wallet/claim/offer", url.Values{"offer": {pinOffer}})
	if ask.Code != http.StatusOK || !strings.Contains(ask.Body.String(), "Transaction code") ||
		!strings.Contains(ask.Body.String(), "Agency A offers you a credential.") {
		t.Fatalf("no code: status = %d body = %s", ask.Code, ask.Body.String())
	}
	bad := h.post(t, "/wallet/claim/offer", url.Values{"offer": {"hello there"}})
	if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), `aria-invalid="true"`) {
		t.Fatalf("bad text: status = %d", bad.Code)
	}
	request := h.post(t, "/wallet/claim/offer", url.Values{"offer": {requestURI}})
	if request.Code != http.StatusSeeOther || !strings.HasPrefix(request.Header().Get("Location"), "/wallet/present?id=") {
		t.Fatalf("request: status = %d", request.Code)
	}
}

// TestClaimAuthCodeRedirects checks the card "Sign in at issuer":
// the wallet sends the browser to the authorization server, and the
// callback claims the credential with the access token.
func TestClaimAuthCodeRedirects(t *testing.T) {
	holder := &recordingHolder{fakeHolder: fakeHolder{credential: credential(t)}}
	h := setupShell(t, func(o *serviceOptions) {
		o.Holder = holder
		o.Endpoints = func(context.Context, string) (issuers.Endpoints, error) {
			return issuers.Endpoints{Authorization: "https://login.a.example/auth", Token: "https://login.a.example/token"}, nil
		}
		o.Post = func(context.Context, string, url.Values) ([]byte, error) {
			return []byte(`{"access_token":"at-1"}`), nil
		}
	}, holderDeployment())
	rec := h.post(t, "/wallet/claim", url.Values{"credential_issuer": {"https://a.example"}, "schema_id": {"dl"}})
	next, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || err != nil || next.Host != "login.a.example" {
		t.Fatalf("status = %d location = %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := next.Query().Get("redirect_uri"); got != "https://holder-waltid.labs.example/wallet/claim/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
	back := h.get(t, "/wallet/claim/callback?state="+url.QueryEscape(next.Query().Get("state"))+"&code=c-1")
	if back.Code != http.StatusSeeOther || back.Header().Get("Location") != "/wallet/" || holder.grant != "at-1" {
		t.Fatalf("callback: status = %d location = %q grant = %q", back.Code, back.Header().Get("Location"), holder.grant)
	}
	refused := h.get(t, "/wallet/claim/callback?state=x&error=access_denied")
	if refused.Code != http.StatusOK || !strings.Contains(refused.Body.String(), "The issuer did not give the credential.") {
		t.Fatalf("refused: status = %d", refused.Code)
	}
}

// TestClaimCardOnDiscover checks the claim card of board
// Holder-Discover: it names the credential and the issuer and shows only
// the ways the issuer allows.
func TestClaimCardOnDiscover(t *testing.T) {
	h := setupShell(t, func(o *serviceOptions) {
		o.Catalogue = ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) { return boardOfferings(), nil })
	}, holderDeployment())
	// The service lists the offerings by type: the farmer registration,
	// the nurse licence, then the trade licence.
	body := h.get(t, "/wallet/discover?claim=2").Body.String()
	for _, want := range []string{
		`id="claim"`, "Claim Nurse licence from Ministry of Health", "Code or QR", "Sign in at issuer",
		`name="credential_issuer" value="https://health.example"`, `name="schema_id" value="nurse"`, `href="/wallet/discover">Close</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("claim card misses %s\n%s", want, body)
		}
	}
	code := h.get(t, "/wallet/discover?claim=1").Body.String()
	if !strings.Contains(code, "Code or QR") || strings.Contains(code, `name="credential_issuer"`) {
		t.Fatal("a code only issuer shows the sign in")
	}
	signin := h.get(t, "/wallet/discover?claim=3").Body.String()
	if strings.Contains(signin, `name="tx_code"`) || !strings.Contains(signin, `name="credential_issuer" value="https://county.example"`) {
		t.Fatal("a sign in only issuer shows the code")
	}
	for _, bad := range []string{"0", "4", "x"} {
		if strings.Contains(h.get(t, "/wallet/discover?claim="+bad).Body.String(), `id="claim"`) {
			t.Fatalf("claim=%s shows a card", bad)
		}
	}
	// In browser storage the wallet cannot run the sign in.
	browser := setupShell(t, func(o *serviceOptions) {
		o.Holder = nil
		o.Catalogue = ports.CatalogueFunc(func(context.Context) ([]*walletportalv1.Offering, error) { return boardOfferings(), nil })
	}, holderDeployment())
	if strings.Contains(browser.get(t, "/wallet/discover?claim=3").Body.String(), `name="credential_issuer"`) {
		t.Fatal("browser storage shows the sign in")
	}
}

// TestClaimDeclineOnlyWithFeature checks that the wallet offers to
// decline a pending offer only when the own adapter lists
// FEATURE_WALLET_REJECT_OFFER.
func TestClaimDeclineOnlyWithFeature(t *testing.T) {
	plain := setupShell(t, nil, holderDeployment())
	page := plain.post(t, "/wallet/claim/offer", url.Values{"offer": {pinOffer}})
	if strings.Contains(page.Body.String(), "Decline") || strings.Contains(page.Body.String(), `action="/wallet/reject"`) {
		t.Fatal("the offer page offers to decline without the feature")
	}
	id := formValues(t, page.Body.String()).Get("offer_id")
	if rec := plain.post(t, "/wallet/reject", url.Values{"offer_id": {id}}); rec.Code != http.StatusNotFound {
		t.Fatalf("reject without the feature: status = %d", rec.Code)
	}
	withFeature := setupShell(t, nil, holderDeployment(backendv1.Feature_FEATURE_WALLET_REJECT_OFFER))
	page = withFeature.post(t, "/wallet/claim/offer", url.Values{"offer": {pinOffer}})
	if !strings.Contains(page.Body.String(), "Decline") {
		t.Fatalf("the offer page misses Decline\n%s", page.Body.String())
	}
	id = formValues(t, page.Body.String()).Get("offer_id")
	if rec := withFeature.post(t, "/wallet/reject", url.Values{"offer_id": {id}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("reject with the feature: status = %d", rec.Code)
	}
	// Decline reaches the wallet of the stack through RejectOffer (P6-W4).
	if len(withFeature.holder.rejected) != 1 || withFeature.holder.rejected[0].GetOfferUri() != pinOffer ||
		withFeature.holder.rejected[0].GetWalletId() != "wallet-1" {
		t.Fatalf("the stack wallet got %+v", withFeature.holder.rejected)
	}
}

// TestScanReadAnswersTheScanner checks the endpoint of the camera
// scanner: an offer comes back as a fragment with the accept form, a
// request sends the browser on, and a missing token stays out.
func TestScanReadAnswersTheScanner(t *testing.T) {
	h := setupShell(t, nil, holderDeployment())
	read := func(payload string, token bool) *httptest.ResponseRecorder {
		form := url.Values{"payload": {payload}}
		req := httptest.NewRequest(http.MethodPost, "/wallet/scan/read", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if token {
			req.Header.Set("X-CSRF-Token", h.guard.Token(citizen()))
		}
		rec := httptest.NewRecorder()
		h.handler.ServeHTTP(rec, req)
		return rec
	}
	offer := read(pinOffer, true)
	if offer.Code != http.StatusOK || !strings.Contains(offer.Body.String(), "Add to my wallet") {
		t.Fatalf("offer: %d %s", offer.Code, offer.Body.String())
	}
	a11ytest.AssertFragment(t, offer.Body.String())
	request := read(requestURI, true)
	if !strings.HasPrefix(request.Header().Get("HX-Redirect"), "/wallet/present?id=") {
		t.Fatalf("request: %v", request.Header())
	}
	a11ytest.AssertFragment(t, request.Body.String())
	unknown := read("hello there", true)
	if unknown.Code != http.StatusOK || !strings.Contains(unknown.Body.String(), "does not know this text") {
		t.Fatalf("unknown: %d %s", unknown.Code, unknown.Body.String())
	}
	a11ytest.AssertFragment(t, unknown.Body.String())
	if rec := read(pinOffer, false); rec.Code != http.StatusForbidden {
		t.Fatalf("no token: %d", rec.Code)
	}
	empty := read("", true)
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), "could not read") {
		t.Fatalf("empty: %d %s", empty.Code, empty.Body.String())
	}
}
