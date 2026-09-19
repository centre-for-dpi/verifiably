// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// fakeLogins is a Logins that a test scripts.
type fakeLogins struct {
	signer    *oidcflow.Signer
	startErr  error
	endErr    error
	logoutURL string
	returnTo  string
	claims    oidcflow.Claims
}

func (f *fakeLogins) Start(_ context.Context, providerID, returnTo string) (string, error) {
	if f.startErr != nil {
		return "", f.startErr
	}
	if providerID == "" {
		return "", oidcflow.ErrProviderNotFound
	}
	return "https://idp/authorize?state=x&return=" + url.QueryEscape(returnTo), nil
}

func (f *fakeLogins) Complete(_ context.Context, state, code, providerError string) (string, oidcflow.Claims, string, error) {
	if providerError != "" {
		return "", oidcflow.Claims{}, "", oidcflow.ErrProviderError
	}
	if state != "good" || code == "" {
		return "", oidcflow.Claims{}, "", oidcflow.ErrStateUnknown
	}
	tok, claims, err := f.signer.Issue(f.claims)
	return tok, claims, f.returnTo, err
}

func (f *fakeLogins) End(_ context.Context, token string) (string, error) {
	if f.endErr != nil {
		return "", f.endErr
	}
	if _, err := f.signer.Revoke(token); err != nil {
		return "", err
	}
	return f.logoutURL, nil
}

func (f *fakeLogins) Session(_ context.Context, token string) (oidcflow.Claims, error) {
	return f.signer.Verify(token)
}

func newHandlers(t *testing.T) (*fakeLogins, oidcflow.Handlers, *http.ServeMux) {
	t.Helper()
	s := newSigner(t)
	c, err := oidcflow.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("oidcflow.NewCSRF: %v", err)
	}
	fl := &fakeLogins{signer: s, claims: oidcflow.Claims{Subject: "u", Roles: []string{"issuer-viewer"}}}
	h := oidcflow.Handlers{Logins: fl, Cookie: oidcflow.Cookie{Name: "sess", Secure: true}, CSRF: c}
	mux := http.NewServeMux()
	h.Mount(mux, "/auth/")
	return fl, h, mux
}

func do(mux *http.ServeMux, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	return rec
}

func TestHandlersLogin(t *testing.T) {
	fl, _, mux := newHandlers(t)
	rec := do(mux, httptest.NewRequest(http.MethodGet, "/auth/login?provider=idp&return_to=/home", nil))
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "return=%2Fhome") {
		t.Fatalf("login: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = do(mux, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown provider: %d", rec.Code)
	}
	fl.startErr = oidcflow.ErrUpstream
	rec = do(mux, httptest.NewRequest(http.MethodGet, "/auth/login?provider=idp", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "temporarily_unavailable") {
		t.Fatalf("upstream: %d %s", rec.Code, rec.Body.String())
	}
	fl.startErr = errors.New("boom")
	rec = do(mux, httptest.NewRequest(http.MethodGet, "/auth/login?provider=idp", nil))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "server_error") {
		t.Fatalf("internal: %d", rec.Code)
	}
	// RFC 9700: no tokens in the query.
	rec = do(mux, httptest.NewRequest(http.MethodGet, "/auth/login?provider=idp&access_token=x", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("query token: %d", rec.Code)
	}
}

func TestHandlersCallbackLogoutSession(t *testing.T) {
	fl, _, mux := newHandlers(t)
	rec := do(mux, httptest.NewRequest(http.MethodGet, "/auth/callback?state=good&code=c", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		SessionToken string `json:"session_token"`
		CSRFToken    string `json:"csrf_token"`
		ExpiresAt    string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.SessionToken == "" || body.CSRFToken == "" || body.ExpiresAt == "" {
		t.Fatalf("body: %s", rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "sess" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Value != body.SessionToken {
		t.Fatalf("cookie: %+v", cookies)
	}
	// Session with the cookie.
	r := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	r.AddCookie(cookies[0])
	rec = do(mux, r)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sub":"u"`) {
		t.Fatalf("session: %d %s", rec.Code, rec.Body.String())
	}
	// Session with the bearer header.
	r = httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	r.Header.Set("Authorization", "Bearer "+body.SessionToken)
	if rec = do(mux, r); rec.Code != http.StatusOK {
		t.Fatalf("bearer session: %d", rec.Code)
	}
	if rec = do(mux, httptest.NewRequest(http.MethodGet, "/auth/session", nil)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", rec.Code)
	}
	// Logout without CSRF token.
	r = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.AddCookie(cookies[0])
	if rec = do(mux, r); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "csrf") {
		t.Fatalf("logout no csrf: %d %s", rec.Code, rec.Body.String())
	}
	// Logout with a form token, no provider logout URL: JSON.
	r = httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader("csrf_token="+url.QueryEscape(body.CSRFToken)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookies[0])
	rec = do(mux, r)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "logged_out") {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body.String())
	}
	cleared := rec.Result().Cookies()
	if len(cleared) != 1 || cleared[0].MaxAge != -1 {
		t.Fatalf("cookie not cleared: %+v", cleared)
	}
	// The session is gone.
	r = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.Header.Set(oidcflow.CSRFHeader, body.CSRFToken)
	r.AddCookie(cookies[0])
	if rec = do(mux, r); rec.Code != http.StatusUnauthorized {
		t.Fatalf("logout twice: %d", rec.Code)
	}
	// Provider errors and unknown state.
	if rec = do(mux, httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied", nil)); rec.Code != http.StatusBadGateway {
		t.Fatalf("provider error: %d", rec.Code)
	}
	if rec = do(mux, httptest.NewRequest(http.MethodGet, "/auth/callback?state=bad&code=c", nil)); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown state: %d", rec.Code)
	}
	// Redirect to return_to and to the provider logout URL.
	fl.returnTo = "/home"
	fl.logoutURL = "https://idp/logout"
	rec = do(mux, httptest.NewRequest(http.MethodGet, "/auth/callback?state=good&code=c", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/home" {
		t.Fatalf("redirect: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	cookie := rec.Result().Cookies()[0]
	r = httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	r.AddCookie(cookie)
	rec = do(mux, r)
	var sess struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sess); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	r = httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	r.Header.Set(oidcflow.CSRFHeader, sess.CSRFToken)
	r.AddCookie(cookie)
	rec = do(mux, r)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://idp/logout" {
		t.Fatalf("provider logout: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestHandlersLogoutFallbackAndEndError(t *testing.T) {
	fl, h, _ := newHandlers(t)
	h.LogoutRedirect = "/bye"
	mux := http.NewServeMux()
	h.Mount(mux, "")
	rec := do(mux, httptest.NewRequest(http.MethodGet, "/callback?state=good&code=c", nil))
	cookie := rec.Result().Cookies()[0]
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	fl.endErr = oidcflow.ErrUpstream
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.Header.Set(oidcflow.CSRFHeader, body.CSRFToken)
	r.AddCookie(cookie)
	if rec = do(mux, r); rec.Code != http.StatusBadGateway {
		t.Fatalf("end error: %d", rec.Code)
	}
	fl.endErr = nil
	r = httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.Header.Set(oidcflow.CSRFHeader, body.CSRFToken)
	r.AddCookie(cookie)
	if rec = do(mux, r); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/bye" {
		t.Fatalf("fallback: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

func TestCookieAndTokenFromRequest(t *testing.T) {
	c := oidcflow.Cookie{Name: "s", Path: "/p"}
	rec := httptest.NewRecorder()
	c.Set(rec, "tok", time.Now().Add(time.Minute))
	ck := rec.Result().Cookies()[0]
	if ck.Path != "/p" || ck.Secure || ck.Value != "tok" {
		t.Fatalf("%+v", ck)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if oidcflow.TokenFromRequest(r, "s") != "" {
		t.Fatal("empty")
	}
	r.AddCookie(&http.Cookie{Name: "s", Value: "fromcookie"})
	if oidcflow.TokenFromRequest(r, "s") != "fromcookie" || oidcflow.TokenFromRequest(r, "") != "" {
		t.Fatal("cookie")
	}
	r.Header.Set("Authorization", "bearer fromheader")
	if oidcflow.TokenFromRequest(r, "s") != "fromheader" {
		t.Fatal("header")
	}
	rec = httptest.NewRecorder()
	oidcflow.WriteError(rec, 403, "access_denied", "no")
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "access_denied") {
		t.Fatal(rec.Body.String())
	}
}
