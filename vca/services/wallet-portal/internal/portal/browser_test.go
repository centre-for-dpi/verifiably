// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/sdjwt"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// The offer of the issuer that the browser store claims.
const browserOffer = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F1"

// signer is the signing key of the browser, as wallet.js keeps it.
type signer struct {
	key *ecdsa.PrivateKey
	jwk string
}

func newSigner(t *testing.T) signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(key.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: key, jwk: string(raw)}
}

// sign returns the ES256 signature of WebCrypto over a signing input.
func (s signer) sign(t *testing.T, input string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(input))
	r, v, err := ecdsa.Sign(rand.Reader, s.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	v.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// withIssuer turns the harness into a browser store wired to an issuer
// that binds each credential to the key of the proof.
func withIssuer(t *testing.T) func(*service.Options) {
	t.Helper()
	issuerKey, err := jose.GenerateKey(jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	return func(o *service.Options) {
		o.Holder = nil
		o.RequestHosts = []string{"issuer.example", "verifier.example"}
		o.Fetch = func(_ context.Context, address string) ([]byte, error) {
			switch address {
			case "https://issuer.example/offers/1":
				return []byte(`{"credential_issuer":"https://issuer.example","credential_configuration_ids":["dl"],` +
					`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"c-1","tx_code":{}}}}`), nil
			case "https://issuer.example/.well-known/openid-credential-issuer":
				return []byte(`{"credential_endpoint":"https://issuer.example/credential","token_endpoint":"https://issuer.example/token",` +
					`"credential_configurations_supported":{"dl":{"format":"dc+sd-jwt","vct":"DriverLicence"}}}`), nil
			}
			return requestObject(""), nil
		}
		o.Post = func(_ context.Context, address string, _ url.Values) ([]byte, error) {
			if address == "https://issuer.example/token" {
				return []byte(`{"access_token":"at","c_nonce":"cn"}`), nil
			}
			return []byte(`{}`), nil
		}
		o.PostCredential = func(_ context.Context, _, _ string, body []byte) ([]byte, error) {
			var req struct {
				Proof struct {
					JWT string `json:"jwt"`
				} `json:"proof"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				return nil, err
			}
			raw, err := base64.RawURLEncoding.DecodeString(strings.Split(req.Proof.JWT, ".")[0])
			if err != nil {
				return nil, err
			}
			var hdr struct {
				JWK map[string]any `json:"jwk"`
			}
			if err = json.Unmarshal(raw, &hdr); err != nil {
				return nil, err
			}
			claims, discs, err := sdjwt.Conceal(map[string]any{"given_name": "Ada"}, []string{"given_name"})
			if err != nil {
				return nil, err
			}
			claims["iss"], claims["vct"], claims["cnf"] = "https://issuer.example", "DriverLicence", map[string]any{"jwk": hdr.JWK}
			jwt, err := jose.Sign(issuerKey, "k", "dc+sd-jwt", claims)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]string{"credential": sdjwt.Serialize(sdjwt.Presentation{IssuerJWT: jwt, Disclosures: discs})})
		}
	}
}

// offerIDOf reads the offer id of the claim form of an offer page.
func offerIDOf(t *testing.T, page string) string {
	t.Helper()
	const mark = `name="offer_id" value="`
	i := strings.Index(page, mark)
	if i < 0 {
		t.Fatalf("the offer page has no offer id: %s", page)
	}
	rest := page[i+len(mark):]
	return rest[:strings.Index(rest, `"`)]
}

// TestTheBrowserStoreClaimsWithTheKeyOfTheBrowser is ADR-073 on the
// pages: the offer page of the browser store carries a claim form that
// wallet.js signs, the two JSON steps answer the proof and the
// credential, and the credential shows on the home page.
func TestTheBrowserStoreClaimsWithTheKeyOfTheBrowser(t *testing.T) {
	h := setup(t, withIssuer(t))
	page := h.post(t, "/wallet/claim/offer", url.Values{"offer": {browserOffer}})
	body := page.Body.String()
	for _, want := range []string{"data-browser-claim", "wallet.js", `id="wallet-status"`, `name="pin"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("the offer page misses %q: %s", want, body)
		}
	}
	browser := newSigner(t)
	step := h.jsonPost(t, "/wallet/claim/proof", http.StatusOK, url.Values{
		"offer_id": {offerIDOf(t, body)}, "pin": {"1234"}, "jwk": {browser.jwk},
	})
	done := h.jsonPost(t, "/wallet/claim/finish", http.StatusOK, url.Values{
		"claim": {step["claim"]}, "signature": {browser.sign(t, step["signing_input"])},
	})
	if done["credential"] == "" || done["id"] == "" || done["next"] != "/wallet/" {
		t.Fatalf("finish = %v", done)
	}
	if home := h.get(t, "/wallet/").Body.String(); !strings.Contains(home, "Ada") {
		t.Fatalf("the home page does not show the claimed credential")
	}
	// A refusal answers JSON with its sentence.
	failed := h.jsonPost(t, "/wallet/claim/finish", http.StatusBadRequest, url.Values{"claim": {"none"}, "signature": {"x"}})
	if failed["error"] == "" {
		t.Fatal("a refusal carries no sentence")
	}
	failed = h.jsonPost(t, "/wallet/claim/proof", http.StatusBadRequest, url.Values{"offer_id": {"none"}, "jwk": {"{}"}})
	if failed["error"] == "" {
		t.Fatal("a refused start carries no sentence")
	}
}

// TestTheConsentFormAsksTheBrowserForAKeyBinding: the consent form of
// the browser store carries the key binding field that wallet.js fills,
// the binding step answers its signing input, and the answer goes out.
func TestTheConsentFormAsksTheBrowserForAKeyBinding(t *testing.T) {
	h := setup(t, withIssuer(t))
	body := h.post(t, "/wallet/claim/offer", url.Values{"offer": {browserOffer}}).Body.String()
	browser := newSigner(t)
	step := h.jsonPost(t, "/wallet/claim/proof", http.StatusOK, url.Values{
		"offer_id": {offerIDOf(t, body)}, "pin": {"1234"}, "jwk": {browser.jwk},
	})
	done := h.jsonPost(t, "/wallet/claim/finish", http.StatusOK, url.Values{
		"claim": {step["claim"]}, "signature": {browser.sign(t, step["signing_input"])},
	})
	opened := h.post(t, "/wallet/claim/offer", url.Values{"offer": {requestURI}})
	target := opened.Header().Get("Location")
	consent := h.get(t, strings.TrimSuffix(target, "#request")).Body.String()
	for _, want := range []string{"data-key-binding", `name="key_binding"`, "wallet.js", `id="wallet-status"`} {
		if !strings.Contains(consent, want) {
			t.Fatalf("the consent page misses %q", want)
		}
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	id := parsed.Query().Get("id")
	form := url.Values{"id": {id}, "card.licence": {done["id"]}, "claim.licence": {"given_name"}}
	input := h.jsonPost(t, "/wallet/present/binding", http.StatusOK, form)["signing_input"]
	if input == "" {
		t.Fatal("a bound credential got no key binding input")
	}
	form.Set("key_binding", input+"."+browser.sign(t, input))
	if sent := h.post(t, "/wallet/present", form); sent.Code != http.StatusOK || !strings.Contains(sent.Body.String(), "The verifier has your answer.") {
		t.Fatalf("status = %d: %s", sent.Code, sent.Body.String())
	}
	failed := h.jsonPost(t, "/wallet/present/binding", http.StatusBadRequest, url.Values{"id": {"gone"}})
	if failed["error"] == "" {
		t.Fatal("a refused binding step carries no sentence")
	}
}

// TestAcceptInTheBrowserStoreNeedsScript: with no script the claim form
// posts to accept, and the page says the browser signs the claim.
func TestAcceptInTheBrowserStoreNeedsScript(t *testing.T) {
	h := setup(t, withIssuer(t))
	body := h.post(t, "/wallet/claim/offer", url.Values{"offer": {browserOffer}}).Body.String()
	rec := h.post(t, "/wallet/accept", url.Values{"offer_id": {offerIDOf(t, body)}, "pin": {"1234"}})
	if !strings.Contains(rec.Body.String(), "JavaScript") {
		t.Fatalf("the problem page does not name JavaScript: %s", rec.Body.String())
	}
}

// jsonPost posts a form with the page token to a JSON endpoint and
// reads the answer.
func (h *harness) jsonPost(t *testing.T, path string, want int, form url.Values) map[string]string {
	t.Helper()
	form.Set(session.Field, h.guard.Token(citizen()))
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	if rec.Code != want || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("%s: status %d %q, want %d JSON: %s", path, rec.Code, rec.Header().Get("Content-Type"), want, rec.Body.String())
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s: the answer is not JSON: %s", path, rec.Body.String())
	}
	return out
}
