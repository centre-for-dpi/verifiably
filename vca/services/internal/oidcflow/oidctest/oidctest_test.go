// SPDX-License-Identifier: Apache-2.0

package oidctest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

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
			if gotErr := res.Body.Close(); gotErr != nil {
				t.Fatalf("res.Body.Close: %v", gotErr)
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
			if gotErr := res.Body.Close(); gotErr != nil {
				t.Fatalf("res.Body.Close: %v", gotErr)
			}
			res, errAssign3 := http.PostForm(idp.Server.URL+"/token", url.Values{"grant_type": {"authorization_code"}, "code": {"x"}})
			if errAssign3 != nil {
				t.Fatalf("http.PostForm: %v", errAssign3)
			}
			if res.StatusCode != http.StatusBadRequest {
				t.Fatal("bad code accepted")
			}
			if gotErr := res.Body.Close(); gotErr != nil {
				t.Fatalf("res.Body.Close: %v", gotErr)
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
			if gotErr := res.Body.Close(); gotErr != nil {
				t.Fatalf("res.Body.Close: %v", gotErr)
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
			if gotErr := res.Body.Close(); gotErr != nil {
				t.Fatalf("res.Body.Close: %v", gotErr)
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
			if gotErr := res.Body.Close(); gotErr != nil {
				t.Fatalf("res.Body.Close: %v", gotErr)
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
	h1, h1Err := jose.PeekHeader(first)
	if h1Err != nil {
		t.Fatalf("jose.PeekHeader: %v", h1Err)
	}
	h2, h2Err := jose.PeekHeader(second)
	if h2Err != nil {
		t.Fatalf("jose.PeekHeader: %v", h2Err)
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

// tokenStatus posts one token request with an optional Basic header and
// returns the status.
func tokenStatus(t *testing.T, idp *oidctest.Provider, form url.Values, basicSecret string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, idp.Server.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicSecret != "" {
		req.SetBasicAuth(idp.ClientID, basicSecret)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	return res.StatusCode
}

// assertion signs a client assertion with key and the given claims.
func assertion(t *testing.T, key crypto.PrivateKey, claims map[string]any) string {
	t.Helper()
	tok, err := jose.Sign(key, "", "JWT", claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestFakeProviderClientAuthentication covers the three client
// authentication methods the fake enforces: the secret in the form, a
// client assertion, and the default Basic.
func TestFakeProviderClientAuthentication(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	idp.PromptValuesSupported = []string{"create"}
	res, err := http.Get(idp.DiscoveryURL())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if decodeErr := json.NewDecoder(res.Body).Decode(&doc); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	if prompts, ok := doc["prompt_values_supported"].([]any); !ok || len(prompts) != 1 || prompts[0] != "create" {
		t.Errorf("discovery = %v", doc)
	}
	code := func() string {
		loc, authErr := idp.Authorize(oidc.AuthorizeURL(idp.Server.URL+"/authorize", idp.ClientID, "https://rp/cb", "s", oidc.NewVerifier(), nil))
		if authErr != nil {
			t.Fatal(authErr)
		}
		u, parseErr := url.Parse(loc)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return u.Query().Get("code")
	}
	base := func() url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code()}, "client_id": {idp.ClientID}}
	}
	// The secret in the form: Basic is refused, a wrong secret is refused.
	idp.ClientSecret = "s3cret"
	idp.ClientSecretPost = true
	if got := tokenStatus(t, idp, base(), "s3cret"); got != http.StatusUnauthorized {
		t.Errorf("basic against post = %d", got)
	}
	wrong := base()
	wrong.Set("client_secret", "nope")
	if got := tokenStatus(t, idp, wrong, ""); got != http.StatusUnauthorized {
		t.Errorf("wrong post secret = %d", got)
	}
	right := base()
	right.Set("client_secret", "s3cret")
	// The code is right but the verifier is missing, so the client passed
	// and the grant failed.
	if got := tokenStatus(t, idp, right, ""); got != http.StatusBadRequest {
		t.Errorf("right post secret = %d", got)
	}
	if idp.LastTokenForm.Get("client_secret") != "s3cret" {
		t.Errorf("LastTokenForm = %v", idp.LastTokenForm)
	}
	// A client assertion: the type, the key, iss, sub, aud, jti, and exp
	// all count. A Basic header or a secret beside it is refused.
	idp.ClientSecret = ""
	idp.ClientSecretPost = false
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp.ClientAssertionKey = &key.PublicKey
	good := map[string]any{"iss": idp.ClientID, "sub": idp.ClientID, "aud": idp.Server.URL + "/token", "jti": "j", "exp": time.Now().Add(time.Minute).Unix()}
	with := func(edit func(map[string]any), typ string) url.Values {
		claims := map[string]any{}
		for k, v := range good {
			claims[k] = v
		}
		if edit != nil {
			edit(claims)
		}
		form := base()
		form.Set("client_assertion_type", typ)
		form.Set("client_assertion", assertion(t, key, claims))
		return form
	}
	if got := tokenStatus(t, idp, with(nil, oidctest.ClientAssertionType), ""); got != http.StatusBadRequest {
		t.Errorf("good assertion = %d", got)
	}
	listed := with(func(c map[string]any) { c["aud"] = []any{"other", idp.Server.URL + "/token"} }, oidctest.ClientAssertionType)
	if got := tokenStatus(t, idp, listed, ""); got != http.StatusBadRequest {
		t.Errorf("aud list = %d", got)
	}
	bad := map[string]url.Values{
		"type":    with(nil, "urn:other"),
		"iss":     with(func(c map[string]any) { c["iss"] = "x" }, oidctest.ClientAssertionType),
		"sub":     with(func(c map[string]any) { c["sub"] = "x" }, oidctest.ClientAssertionType),
		"aud":     with(func(c map[string]any) { c["aud"] = "https://other/token" }, oidctest.ClientAssertionType),
		"aud num": with(func(c map[string]any) { c["aud"] = 7 }, oidctest.ClientAssertionType),
		"jti":     with(func(c map[string]any) { delete(c, "jti") }, oidctest.ClientAssertionType),
		"exp":     with(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, oidctest.ClientAssertionType),
	}
	empty := base()
	empty.Set("client_assertion_type", oidctest.ClientAssertionType)
	bad["empty"] = empty
	garbage := base()
	garbage.Set("client_assertion_type", oidctest.ClientAssertionType)
	garbage.Set("client_assertion", "not.a.jwt")
	bad["garbage"] = garbage
	secretToo := with(nil, oidctest.ClientAssertionType)
	secretToo.Set("client_secret", "s")
	bad["secret beside it"] = secretToo
	for name, form := range bad {
		if got := tokenStatus(t, idp, form, ""); got != http.StatusUnauthorized {
			t.Errorf("%s = %d", name, got)
		}
	}
	if got := tokenStatus(t, idp, with(nil, oidctest.ClientAssertionType), "s"); got != http.StatusUnauthorized {
		t.Errorf("basic beside an assertion = %d", got)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	form := base()
	form.Set("client_assertion_type", oidctest.ClientAssertionType)
	form.Set("client_assertion", assertion(t, other, good))
	if got := tokenStatus(t, idp, form, ""); got != http.StatusUnauthorized {
		t.Errorf("another key = %d", got)
	}
}
