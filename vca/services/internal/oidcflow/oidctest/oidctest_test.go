// SPDX-License-Identifier: Apache-2.0

package oidctest_test

import (
	"io"
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
			if err := res.Body.Close(); err != nil {
				t.Fatalf("res.Body.Close: %v", err)
			}
			// The authorization endpoint rejects a request without PKCE.
			loc, err := idp.Authorize(idp.Server.URL + "/authorize?response_type=code&client_id=client")
			if err != nil || loc != "" {
				t.Fatalf("no pkce: %q %v", loc, err)
			}
			loc, errAssign := idp.Authorize(oidc.AuthorizeURL(idp.Server.URL+"/authorize", "other", "https://rp/cb", "s", "v", nil))
			if errAssign != nil {
				t.Fatalf("idp.Authorize: %v", errAssign)
			}
			if loc != "" {
				t.Fatal("unknown client accepted")
			}
			// A token request with a bad method or missing code fails.
			res, errAssign2 := http.Get(idp.Server.URL + "/token")
			if errAssign2 != nil {
				t.Fatalf("http.Get: %v", errAssign2)
			}
			if res.StatusCode != http.StatusBadRequest {
				t.Fatal("GET token accepted")
			}
			if err := res.Body.Close(); err != nil {
				t.Fatalf("res.Body.Close: %v", err)
			}
			res, errAssign3 := http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {"x"}})
			if errAssign3 != nil {
				t.Fatalf("http.PostForm: %v", errAssign3)
			}
			if res.StatusCode != http.StatusBadRequest {
				t.Fatal("bad code accepted")
			}
			if err := res.Body.Close(); err != nil {
				t.Fatalf("res.Body.Close: %v", err)
			}
			// A wrong verifier fails.
			verifier := oidc.NewVerifier()
			loc, errAssign4 := idp.Authorize(oidc.AuthorizeURL(idp.Server.URL+"/authorize", "client", "https://rp/cb", "s", verifier, nil))
			if errAssign4 != nil {
				t.Fatalf("idp.Authorize: %v", errAssign4)
			}
			u, err := url.Parse(loc)
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			code := u.Query().Get("code")
			res, errAssign5 := http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://rp/cb"}, "code_verifier": {"wrong"}})
			if errAssign5 != nil {
				t.Fatalf("http.PostForm: %v", errAssign5)
			}
			if res.StatusCode != http.StatusBadRequest {
				t.Fatal("wrong verifier accepted")
			}
			if err := res.Body.Close(); err != nil {
				t.Fatalf("res.Body.Close: %v", err)
			}
			// Client secret check.
			idp.ClientSecret = "s"
			res, errAssign6 := http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}})
			if errAssign6 != nil {
				t.Fatalf("http.PostForm: %v", errAssign6)
			}
			if res.StatusCode != http.StatusUnauthorized {
				t.Fatal("missing secret accepted")
			}
			if err := res.Body.Close(); err != nil {
				t.Fatalf("res.Body.Close: %v", err)
			}
			idp.ClientSecret = ""
			// The ID token verifies against the JWKS.
			tok := idp.IDToken("client", "n")
			res, errAssign7 := http.Get(idp.Server.URL + "/jwks")
			if errAssign7 != nil {
				t.Fatalf("http.Get: %v", errAssign7)
			}
			var raw strings.Builder
			buf, readErr := io.ReadAll(res.Body)
			if readErr != nil {
				t.Fatalf("read body: %v", readErr)
			}
			raw.Write(buf)
			if err := res.Body.Close(); err != nil {
				t.Fatalf("res.Body.Close: %v", err)
			}
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
			res, errAssign8 := client.Get(idp.Server.URL + "/logout?post_logout_redirect_uri=https://rp/")
			if errAssign8 != nil {
				t.Fatalf("client.Get: %v", errAssign8)
			}
			if res.StatusCode != http.StatusFound {
				t.Fatal("logout redirect")
			}
			if err := res.Body.Close(); err != nil {
				t.Fatalf("res.Body.Close: %v", err)
			}
			res, errAssign9 := client.Get(idp.Server.URL + "/logout")
			if errAssign9 != nil {
				t.Fatalf("client.Get: %v", errAssign9)
			}
			if res.StatusCode != http.StatusOK {
				t.Fatal("logout")
			}
			if err := res.Body.Close(); err != nil {
				t.Fatalf("res.Body.Close: %v", err)
			}
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
	h1, err := jose.PeekHeader(first)
	if err != nil {
		t.Fatalf("jose.PeekHeader: %v", err)
	}
	h2, err := jose.PeekHeader(second)
	if err != nil {
		t.Fatalf("jose.PeekHeader: %v", err)
	}
	if h1.Kid == h2.Kid {
		t.Fatal("rotation kept the kid")
	}
	verifier := oidc.NewVerifier()
	exchange := func() (int, string) {
		loc, err := idp.Authorize(oidc.AuthorizeURL(idp.Server.URL+"/authorize", "client", "https://rp/cb", "s", verifier, nil))
		if err != nil {
			t.Fatalf("idp.Authorize: %v", err)
		}
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatalf("url.Parse: %v", err)
		}
		res, err := http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "redirect_uri": {"https://rp/cb"}, "code_verifier": {verifier}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := res.Body.Close(); err != nil {
				t.Errorf("res.Body.Close: %v", err)
			}
		}()
		buf, readErr := io.ReadAll(res.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}
		return res.StatusCode, string(buf)
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
	res, err := http.Get(idp.DiscoveryURL())
	if err != nil {
		t.Fatalf("http.Get: %v", err)
	}
	buf, readErr := io.ReadAll(res.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	if err := res.Body.Close(); err != nil {
		t.Fatalf("res.Body.Close: %v", err)
	}
	if strings.Contains(string(buf), "end_session_endpoint") {
		t.Fatal("end session still advertised")
	}
}
