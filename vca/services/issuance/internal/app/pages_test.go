// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"connectrpc.com/connect"

	issuerauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/app"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// staff stands in for issuer-auth: it signs the sessions the tests send.
func staff(t *testing.T) *staffsessiontest.Issuer {
	t.Helper()
	return staffsessiontest.New(t, staffsession.IssuerAudience, fixedTime)
}

// withSession returns the wiring with the key set of issuer.
func withSession(buf *bytes.Buffer, issuer *staffsessiontest.Issuer) app.Deps {
	d := deps(buf)
	d.SessionKeys = issuer.Keys()
	return d
}

// get answers one GET, with the session cookie when token is set.
func get(a *app.App, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	return rec
}

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := settings(t, nil)
	cfg.ThemeFile = path
	var buf bytes.Buffer
	_, err := app.Build(cfg, deps(&buf))
	uikittest.AssertBadThemeError(t, err, path)
}

func TestIssuerPagesNeedSession(t *testing.T) {
	var buf bytes.Buffer
	issuer := staff(t)
	a, err := app.Build(settings(t, map[string]string{
		"VCA_ISSUANCE_LOGIN_URL": "https://issuer.example/auth/",
	}), withSession(&buf, issuer))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/issuer/", "/identity/", "/issue/", "/notifications/", "/help/"} {
		rec := get(a, path, "")
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "https://issuer.example/auth/?return_to=") {
			t.Errorf("%s without a session: status %d location %q", path, rec.Code, rec.Header().Get("Location"))
		}
		token := issuer.Token(t, "kc|wanjiru", "issuer-operator")
		if rec := get(a, path, token); rec.Code != http.StatusOK {
			t.Errorf("%s with a session: status %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestPublicRoutesStayOpen(t *testing.T) {
	var buf bytes.Buffer
	a, err := app.Build(settings(t, nil), withSession(&buf, staff(t)))
	if err != nil {
		t.Fatal(err)
	}
	// The root sends the browser to the issuer home.
	if rec := get(a, "/", ""); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/issuer/" {
		t.Errorf("root: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	// The shared assets and the document of a citizen need no session.
	if rec := get(a, ui.Prefix+"vca.css", ""); rec.Code != http.StatusOK {
		t.Errorf("assets: status %d", rec.Code)
	}
	if rec := get(a, "/issuance/pdf/unknown", ""); rec.Code != http.StatusNotFound {
		t.Errorf("document: status %d", rec.Code)
	}
	// The DID document of a did:web issuer needs no session. The test
	// adapter has no identity, so the answer is 404, not a sign in.
	if rec := get(a, "/.well-known/did.json", ""); rec.Code != http.StatusNotFound {
		t.Errorf("did document: status %d", rec.Code)
	}
}

// authStub stands in for issuer-auth: it records the session a logout ends.
type authStub struct {
	issuerauthv1connect.UnimplementedIssuerAuthServiceHandler
	ended []string
}

func (s *authStub) Logout(_ context.Context, req *connect.Request[issuerauthv1.LogoutRequest]) (*connect.Response[issuerauthv1.LogoutResponse], error) {
	s.ended = append(s.ended, req.Msg.GetSessionToken())
	return connect.NewResponse(&issuerauthv1.LogoutResponse{ProviderLogoutUrl: "https://idp.example/logout"}), nil
}

func TestSignOutEndsTheSessionAtIssuerAuth(t *testing.T) {
	stub := &authStub{}
	mux := http.NewServeMux()
	mux.Handle(issuerauthv1connect.NewIssuerAuthServiceHandler(stub))
	auth := httptest.NewServer(mux)
	defer auth.Close()
	peers := "issuer-waltid|https://issuer-waltid.labs.example|issuance=http://issuance:8080,issuer-auth=" + auth.URL
	var buf bytes.Buffer
	issuer := staff(t)
	a, err := app.Build(settings(t, map[string]string{
		"VCA_PEERS":                  peers,
		"VCA_ISSUANCE_AUTH_JWKS_URL": auth.URL + "/.well-known/jwks.json",
		"VCA_ISSUANCE_LOGIN_URL":     "https://issuer-waltid.labs.example/auth/",
	}), withSession(&buf, issuer))
	if err != nil {
		t.Fatal(err)
	}
	token := issuer.Token(t, "kc|wanjiru", "issuer-operator")
	page := get(a, "/help/", token).Body.String()
	m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the user menu has no synchronizer token")
	}
	form := url.Values{staffsession.Field: {m[1]}}
	req := httptest.NewRequest(http.MethodPost, "/issuer/signout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "https://idp.example/logout" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	if len(stub.ended) != 1 || stub.ended[0] != token {
		t.Fatalf("issuer-auth ended %v", stub.ended)
	}
	// Without the synchronizer token the guard refuses the form.
	req = httptest.NewRequest(http.MethodPost, "/issuer/signout", nil)
	req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
	rec = httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("sign out without a token: status %d", rec.Code)
	}
}
