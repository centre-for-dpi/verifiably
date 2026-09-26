// SPDX-License-Identifier: Apache-2.0

package inji

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
)

// mimotoServer answers every Mimoto call with the handler of its method
// and path, and records the cookie of each call.
func mimotoServer(t *testing.T, answers map[string]http.HandlerFunc) (*Mimoto, *[]string) {
	t.Helper()
	var cookies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookies = append(cookies, r.Header.Get("Cookie"))
		h, ok := answers[r.Method+" "+r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return NewMimoto(newHTTP(srv)), &cookies
}

// answer writes a fixed JSON body.
func answer(t *testing.T, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { mustWrite(t, w, []byte(body)) }
}

// status writes a bare status.
func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

// TestMimotoWalletCalls walks the wallet calls: the token login sets the
// cookie, and every later call carries it.
func TestMimotoWalletCalls(t *testing.T) {
	var login, created, unlocked, selected map[string]any
	var auth string
	m, cookies := mimotoServer(t, map[string]http.HandlerFunc{
		"POST /v1/mimoto/auth/google/token-login": func(w http.ResponseWriter, r *http.Request) {
			auth = r.Header.Get("Authorization")
			w.Header().Add("Set-Cookie", "SESSION=s1; Path=/; HttpOnly")
			w.Header().Add("Set-Cookie", "XSRF-TOKEN=x1; Path=/")
			w.Header().Add("Set-Cookie", "broken")
			mustWrite(t, w, []byte(`{}`))
		},
		"POST /v1/mimoto/wallets": func(w http.ResponseWriter, r *http.Request) {
			decode(t, r, &created)
			mustWrite(t, w, []byte(`{"walletId":"w1"}`))
		},
		"POST /v1/mimoto/wallets/w1/unlock": func(w http.ResponseWriter, r *http.Request) {
			decode(t, r, &unlocked)
			mustWrite(t, w, []byte(`{"walletId":"w1"}`))
		},
		"GET /v1/mimoto/wallets/w1/credentials": answer(t,
			`[{"credentialId":"c1","issuerDisplayName":"Ministry of Agriculture","credentialTypeDisplayName":"Farmer Credential"}]`),
		"GET /v1/mimoto/wallets/w1/credentials/c1": func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Accept") != "application/pdf" || r.URL.Query().Get("action") != "download" {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			mustWrite(t, w, []byte("%PDF-1.4"))
		},
		"DELETE /v1/mimoto/wallets/w1/credentials/c1": status(http.StatusOK),
		"POST /v1/mimoto/wallets/w1/presentations": func(w http.ResponseWriter, r *http.Request) {
			decode(t, r, &login)
			mustWrite(t, w, []byte(`{"presentationId":"p1"}`))
		},
		"PATCH /v1/mimoto/wallets/w1/presentations/p1": func(w http.ResponseWriter, r *http.Request) {
			decode(t, r, &selected)
			mustWrite(t, w, []byte(`{"redirectUri":"https://verifier.example/done"}`))
		},
	})
	ctx := context.Background()
	cookie, err := m.TokenLogin(ctx, "google", "id.token.sig")
	if err != nil || cookie != "SESSION=s1; XSRF-TOKEN=x1" || auth != "Bearer id.token.sig" {
		t.Fatalf("login = %q %v, auth %q", cookie, err, auth)
	}
	id, err := m.CreateWallet(ctx, cookie, "VCA wallet", "123456")
	if err != nil || id != "w1" || created["walletPin"] != "123456" || created["confirmWalletPin"] != "123456" {
		t.Fatalf("wallet = %q %v %v", id, err, created)
	}
	if uerr := m.Unlock(ctx, cookie, "w1", "123456"); uerr != nil || unlocked["walletPin"] != "123456" {
		t.Fatalf("unlock: %v %v", uerr, unlocked)
	}
	held, err := m.Credentials(ctx, cookie, "w1")
	if err != nil || len(held) != 1 || held[0].Type != "Farmer Credential" || held[0].Issuer != "Ministry of Agriculture" {
		t.Fatalf("credentials = %v %v", held, err)
	}
	pdf, media, err := m.Document(ctx, cookie, "w1", "c1")
	if err != nil || string(pdf) != "%PDF-1.4" || media == "" {
		t.Fatalf("document = %q %q %v", pdf, media, err)
	}
	if derr := m.Delete(ctx, cookie, "w1", "c1"); derr != nil {
		t.Fatalf("delete: %v", derr)
	}
	sent, err := m.Present(ctx, cookie, "w1", "openid4vp://authorize?request_uri=x", []string{"c1"})
	if err != nil || sent.PresentationID != "p1" || sent.RedirectURI != "https://verifier.example/done" {
		t.Fatalf("present = %+v %v", sent, err)
	}
	if login["authorizationRequestUrl"] != "openid4vp://authorize?request_uri=x" || len(anyval.As[[]any](selected["selectedCredentials"])) != 1 {
		t.Fatalf("presentation bodies = %v %v", login, selected)
	}
	for _, c := range (*cookies)[1:] {
		if c != cookie {
			t.Fatalf("a call carried the cookie %q", c)
		}
	}
}

// decode reads a JSON request body.
func decode(t *testing.T, r *http.Request, into *map[string]any) {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("body %s: %v", raw, err)
	}
}

// TestMimotoFailures maps a refused session onto ErrMimotoSession and
// reports a broken answer.
func TestMimotoFailures(t *testing.T) {
	ctx := context.Background()
	var none *Mimoto
	if _, err := none.Credentials(ctx, "c", "w"); err == nil || NewMimoto(nil) != nil {
		t.Fatal("a Mimoto without a URL answered")
	}
	refused, _ := mimotoServer(t, map[string]http.HandlerFunc{
		"POST /v1/mimoto/auth/google/token-login": status(http.StatusUnauthorized),
		"GET /v1/mimoto/wallets/w1/credentials":   status(http.StatusForbidden),
		"POST /v1/mimoto/wallets":                 status(http.StatusBadRequest),
	})
	if _, err := refused.TokenLogin(ctx, "google", "t"); !errors.Is(err, ErrMimotoSession) {
		t.Fatalf("login error = %v", err)
	}
	if _, err := refused.Credentials(ctx, "c", "w1"); !errors.Is(err, ErrMimotoSession) {
		t.Fatalf("list error = %v", err)
	}
	if _, err := refused.CreateWallet(ctx, "c", "n", "123456"); err == nil || errors.Is(err, ErrMimotoSession) {
		t.Fatalf("create error = %v", err)
	}
	for _, name := range []string{"Document", "Delete", "Unlock", "Present"} {
		var err error
		switch name {
		case "Document":
			_, _, err = refused.Document(ctx, "c", "w1", "c1")
		case "Delete":
			err = refused.Delete(ctx, "c", "w1", "c1")
		case "Unlock":
			err = refused.Unlock(ctx, "c", "w1", "1")
		case "Present":
			_, err = refused.Present(ctx, "c", "w1", "u", []string{"c1"})
		}
		if err == nil {
			t.Errorf("%s answered for a missing route", name)
		}
	}
	broken, _ := mimotoServer(t, map[string]http.HandlerFunc{
		"POST /v1/mimoto/auth/google/token-login":      answer(t, `{}`),
		"POST /v1/mimoto/wallets":                      answer(t, `{"name":"x"}`),
		"GET /v1/mimoto/wallets/w1/credentials":        answer(t, `{"not":"a list"}`),
		"POST /v1/mimoto/wallets/w1/presentations":     answer(t, `{}`),
		"POST /v1/mimoto/wallets/w2/presentations":     answer(t, `{"presentationId":"p2"}`),
		"PATCH /v1/mimoto/wallets/w2/presentations/p2": status(http.StatusBadRequest),
		"POST /v1/mimoto/wallets/w3/presentations":     answer(t, `{"presentationId":"p3"}`),
		"PATCH /v1/mimoto/wallets/w3/presentations/p3": answer(t, `not json`),
	})
	if _, err := broken.TokenLogin(ctx, "google", "t"); err == nil || !strings.Contains(err.Error(), "cookie") {
		t.Fatalf("login without a cookie = %v", err)
	}
	if _, err := broken.CreateWallet(ctx, "c", "n", "1"); err == nil {
		t.Fatal("a wallet answer without an id passed")
	}
	if _, err := broken.Credentials(ctx, "c", "w1"); err == nil {
		t.Fatal("a broken list passed")
	}
	if _, err := broken.Present(ctx, "c", "w1", "u", nil); err == nil {
		t.Fatal("a presentation answer without an id passed")
	}
	if _, err := broken.Present(ctx, "c", "w2", "u", nil); err == nil {
		t.Fatal("a refused selection passed")
	}
	if sent, err := broken.Present(ctx, "c", "w3", "u", []string{"c"}); err != nil || sent.RedirectURI != "" {
		t.Fatalf("a selection answer without a redirect = %+v %v", sent, err)
	}
}

// TestAuthorizationRequestURL keeps an OID4VP URL and wraps a bare
// request object address.
func TestAuthorizationRequestURL(t *testing.T) {
	for in, want := range map[string]string{
		"openid4vp://authorize?client_id=x&request_uri=y":  "openid4vp://authorize?client_id=x&request_uri=y",
		" https://verify.example/v1/verify/vp-request/r1":  "openid4vp://authorize?request_uri=https%3A%2F%2Fverify.example%2Fv1%2Fverify%2Fvp-request%2Fr1",
		"https://verifier.example/authorize?request_uri=z": "https://verifier.example/authorize?request_uri=z",
	} {
		if got := AuthorizationRequestURL(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}
