// SPDX-License-Identifier: Apache-2.0

package oidctest_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/core/oidc"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
)

func TestFakeProviderEndpoints(t *testing.T) {
	for _, idp := range []*oidctest.Provider{oidctest.New(), oidctest.NewRS256()} {
		func() {
			defer idp.Close()
			res, err := http.Get(idp.DiscoveryURL())
			if err != nil || res.StatusCode != 200 {
				t.Fatalf("discovery: %v %v", err, res)
			}
			res.Body.Close()
			// The authorization endpoint rejects a request without PKCE.
			loc, err := idp.Authorize(idp.Server.URL + "/authorize?response_type=code&client_id=client")
			if err != nil || loc != "" {
				t.Fatalf("no pkce: %q %v", loc, err)
			}
			loc, _ = idp.Authorize(oidc.AuthorizeURL(idp.Server.URL+"/authorize", "other", "https://rp/cb", "s", "v", nil))
			if loc != "" {
				t.Fatal("unknown client accepted")
			}
			// A token request with a bad method or missing code fails.
			res, _ = http.Get(idp.Server.URL + "/token")
			if res.StatusCode != http.StatusBadRequest {
				t.Fatal("GET token accepted")
			}
			res.Body.Close()
			res, _ = http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {"x"}})
			if res.StatusCode != http.StatusBadRequest {
				t.Fatal("bad code accepted")
			}
			res.Body.Close()
			// A wrong verifier fails.
			verifier := oidc.NewVerifier()
			loc, _ = idp.Authorize(oidc.AuthorizeURL(idp.Server.URL+"/authorize", "client", "https://rp/cb", "s", verifier, nil))
			u, _ := url.Parse(loc)
			code := u.Query().Get("code")
			res, _ = http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://rp/cb"}, "code_verifier": {"wrong"}})
			if res.StatusCode != http.StatusBadRequest {
				t.Fatal("wrong verifier accepted")
			}
			res.Body.Close()
			// Client secret check.
			idp.ClientSecret = "s"
			res, _ = http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}})
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatal("missing secret accepted")
			}
			res.Body.Close()
			idp.ClientSecret = ""
			// The ID token verifies against the JWKS.
			tok := idp.IDToken("client", "n")
			res, _ = http.Get(idp.Server.URL + "/jwks")
			var raw strings.Builder
			buf := make([]byte, 4096)
			n, _ := res.Body.Read(buf)
			raw.Write(buf[:n])
			res.Body.Close()
			set, err := jose.ParseJWKS([]byte(raw.String()))
			if err != nil {
				t.Fatal(err)
			}
			claims, err := oidc.VerifyToken(tok, set, oidc.TokenOptions{Issuers: []string{idp.Issuer()}, ClientID: "client"})
			if err != nil || claims["nonce"] != "n" {
				t.Fatalf("verify: %v", err)
			}
			// Logout with and without a redirect.
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			res, _ = client.Get(idp.Server.URL + "/logout?post_logout_redirect_uri=https://rp/")
			if res.StatusCode != http.StatusFound {
				t.Fatal("logout redirect")
			}
			res.Body.Close()
			res, _ = client.Get(idp.Server.URL + "/logout")
			if res.StatusCode != http.StatusOK {
				t.Fatal("logout")
			}
			res.Body.Close()
			if idp.Requests["/logout"] != 2 {
				t.Fatal("request count")
			}
		}()
	}
	// Authorize against a closed server returns an error.
	idp := oidctest.New()
	idp.Close()
	if _, err := idp.Authorize(idp.Server.URL + "/authorize"); err == nil {
		t.Fatal("closed server")
	}
}

func TestFakeProviderSwitches(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	idp.Claims["name"] = "Ada"
	first := idp.IDToken("client", "n")
	idp.RotateKey()
	second := idp.IDToken("client", "n")
	h1, _ := jose.PeekHeader(first)
	h2, _ := jose.PeekHeader(second)
	if h1.Kid == h2.Kid {
		t.Fatal("rotation kept the kid")
	}
	verifier := oidc.NewVerifier()
	exchange := func() (int, string) {
		loc, _ := idp.Authorize(oidc.AuthorizeURL(idp.Server.URL+"/authorize", "client", "https://rp/cb", "s", verifier, nil))
		u, _ := url.Parse(loc)
		res, err := http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "redirect_uri": {"https://rp/cb"}, "code_verifier": {verifier}})
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		buf := make([]byte, 8192)
		n, _ := res.Body.Read(buf)
		return res.StatusCode, string(buf[:n])
	}
	if code, body := exchange(); code != 200 || !strings.Contains(body, "id_token") {
		t.Fatalf("ok: %d %s", code, body)
	}
	idp.WrongNonce = true
	if code, body := exchange(); code != 200 || !strings.Contains(body, "id_token") {
		t.Fatalf("wrong nonce: %d %s", code, body)
	}
	idp.WrongNonce = false
	idp.OmitIDToken = true
	if code, body := exchange(); code != 200 || strings.Contains(body, "id_token") {
		t.Fatalf("omit: %d %s", code, body)
	}
	idp.OmitIDToken = false
	idp.TokenError = "server_error"
	if code, body := exchange(); code != 400 || !strings.Contains(body, "server_error") {
		t.Fatalf("token error: %d %s", code, body)
	}
	idp.NoEndSession = true
	res, _ := http.Get(idp.DiscoveryURL())
	buf := make([]byte, 4096)
	n, _ := res.Body.Read(buf)
	res.Body.Close()
	if strings.Contains(string(buf[:n]), "end_session_endpoint") {
		t.Fatal("end session still advertised")
	}
}
