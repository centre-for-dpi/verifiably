// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// sessionToken is the session cookie of the browser of the test.
const sessionToken = "session-token-of-the-test"

// browserCitizen is a citizen of a browser store wallet whose browser
// has not bound its key yet.
func browserCitizen() session.Citizen {
	return session.Citizen{Subject: "https://idp|abc", SessionID: "sid-1", Name: "Wanjiku Njeri", ExpiresAt: clock.Add(10 * time.Minute)}
}

// keyCall is one call of the binding at wallet-auth.
type keyCall struct {
	auth, token, jwk, proof string
}

// browserKeyDeployment is a browser store wallet whose own stack lists
// DIDs, with a binding that records its calls.
func browserKeyDeployment(t *testing.T, who session.Citizen, answer error) (*harness, *[]keyCall) {
	t.Helper()
	var calls []keyCall
	topo := holderDeployment(backendv1.Feature_FEATURE_WALLET_DIDS)
	topo.RegisterKey = func(_ context.Context, auth, token, jwk, proof string) (portal.HolderKey, error) {
		calls = append(calls, keyCall{auth: auth, token: token, jwk: jwk, proof: proof})
		if answer != nil {
			return portal.HolderKey{}, answer
		}
		return portal.HolderKey{Thumbprint: "thumbprint-1", HolderDID: "did:jwk:e30", SessionToken: "renewed-session-token"}, nil
	}
	return setupWho(t, func(o *service.Options) { o.Holder = nil }, topo, who), &calls
}

// keyPost posts one step of the binding with the session cookie.
func (h *harness) keyPost(path string, form url.Values, cookie bool) *httptest.ResponseRecorder {
	form.Set(session.Field, h.guard.Token(h.who))
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if cookie {
		req.AddCookie(&http.Cookie{Name: session.CookieName, Value: sessionToken})
	}
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

// TestTheBrowserBindsItsKeyToTheWallet: after the browser makes its key,
// wallet.js asks for the signing input of a proof over the session, signs
// it, and posts the public key once. The portal hands both to the
// wallet-auth service of its pair and sets the session cookie that names
// the key, so the next page knows the browser holds one.
func TestTheBrowserBindsItsKeyToTheWallet(t *testing.T) {
	h, calls := browserKeyDeployment(t, browserCitizen(), nil)
	// The claim page marks a browser that still has to bind its key.
	page := h.post(t, "/wallet/claim/offer", url.Values{"offer": {browserOffer}}).Body.String()
	if !strings.Contains(page, `data-holder-key="register"`) {
		t.Errorf("the offer page does not ask the browser to bind its key: %s", page)
	}
	step := h.keyPost("/wallet/holder-key/proof", url.Values{}, true)
	var proof map[string]string
	if step.Code != http.StatusOK || json.Unmarshal(step.Body.Bytes(), &proof) != nil || proof["signing_input"] == "" {
		t.Fatalf("proof step: %d %s", step.Code, step.Body.String())
	}
	browser := newSigner(t)
	done := h.keyPost("/wallet/holder-key", url.Values{"jwk": {browser.jwk}, "signature": {browser.sign(t, proof["signing_input"])}}, true)
	if done.Code != http.StatusOK || !strings.Contains(done.Body.String(), `"thumbprint":"thumbprint-1"`) {
		t.Fatalf("bind step: %d %s", done.Code, done.Body.String())
	}
	if len(*calls) != 1 {
		t.Fatalf("wallet-auth got %d calls", len(*calls))
	}
	call := (*calls)[0]
	if call.token != sessionToken || call.jwk != browser.jwk || !strings.HasPrefix(call.auth, "http://") {
		t.Errorf("call = %+v", call)
	}
	jwk, err := jose.ParseJWK([]byte(browser.jwk))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := jose.Verify(call.proof, jwk.Key, []jose.Algorithm{jose.ES256})
	if err != nil || string(payload) != `{"sid":"sid-1"}` {
		t.Errorf("the proof %q does not sign the session: %s %v", call.proof, payload, err)
	}
	cookie := done.Result().Cookies()
	if len(cookie) != 1 || cookie[0].Name != session.CookieName || cookie[0].Value != "renewed-session-token" || !cookie[0].HttpOnly || cookie[0].Path != "/" {
		t.Errorf("cookies = %+v", cookie)
	}
}

// TestTheKeyBindingRefuses answers each failed step with a sentence, and
// offers the binding to a browser store wallet only.
func TestTheKeyBindingRefuses(t *testing.T) {
	h, calls := browserKeyDeployment(t, browserCitizen(), nil)
	browser := newSigner(t)
	if rec := h.keyPost("/wallet/holder-key", url.Values{"jwk": {browser.jwk}, "signature": {"x"}}, false); rec.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: %d", rec.Code)
	}
	if rec := h.keyPost("/wallet/holder-key", url.Values{"jwk": {browser.jwk}}, true); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Errorf("no signature: %d %s", rec.Code, rec.Body.String())
	}
	if len(*calls) != 0 {
		t.Errorf("a refused step reached wallet-auth: %+v", *calls)
	}
	refused, _ := browserKeyDeployment(t, browserCitizen(), connect.NewError(connect.CodeInvalidArgument, errors.New("proof does not verify with public_jwk")))
	rec := refused.keyPost("/wallet/holder-key", url.Values{"jwk": {browser.jwk}, "signature": {"x"}}, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "public_jwk") || len(rec.Result().Cookies()) != 0 {
		t.Errorf("a refusal of wallet-auth: %d %s", rec.Code, rec.Body.String())
	}
	// A wallet of the stack keeps its own keys.
	stack := setupShell(t, nil, holderDeployment(backendv1.Feature_FEATURE_WALLET_DIDS))
	for _, path := range []string{"/wallet/holder-key/proof", "/wallet/holder-key"} {
		if rec := stack.keyPost(path, url.Values{}, true); rec.Code != http.StatusNotFound {
			t.Errorf("%s in a stack wallet: %d", path, rec.Code)
		}
	}
	// A browser that holds a key already gets no mark.
	held, _ := browserKeyDeployment(t, citizen(), nil)
	if page := held.post(t, "/wallet/claim/offer", url.Values{"offer": {browserOffer}}).Body.String(); strings.Contains(page, `data-holder-key="register"`) {
		t.Error("the offer page asks a bound browser to bind its key again")
	}
}

// TestBrowserKeysPageAsksNoStackWallet: a browser store wallet keeps its
// keys in the browser, so the keys page never asks the wallet of the
// stack. Before the first claim it says the browser makes its key then.
// After the binding it names the key by its thumbprint.
func TestBrowserKeysPageAsksNoStackWallet(t *testing.T) {
	h, _ := browserKeyDeployment(t, browserCitizen(), nil)
	body := h.get(t, "/wallet/keys").Body.String()
	if strings.Contains(body, "did not answer") || strings.Contains(body, `id="dids"`) {
		t.Errorf("the page asked the wallet of the stack:\n%s", body)
	}
	if summary := summaryOf(t, body); !strings.Contains(summary, "Your browser makes its key at your first claim") {
		t.Errorf("summary before a claim: %s", summary)
	}
	browser := newSigner(t)
	jwk, err := jose.ParseJWK([]byte(browser.jwk))
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := jose.Thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	who := browserCitizen()
	who.HasHolderKey, who.HolderDID = true, "did:jwk:"+base64.RawURLEncoding.EncodeToString([]byte(browser.jwk))
	bound, _ := browserKeyDeployment(t, who, nil)
	body = bound.get(t, "/wallet/keys").Body.String()
	summary := summaryOf(t, body)
	for _, want := range []string{"Your browser holds a key for this wallet.", thumbprint, who.HolderDID} {
		if !strings.Contains(summary, want) {
			t.Errorf("the summary lacks %q: %s", want, summary)
		}
	}
	if strings.Contains(body, "did not answer") {
		t.Errorf("the page asked the wallet of the stack:\n%s", body)
	}
}
