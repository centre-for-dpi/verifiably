// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
)

func testProvider(idp *oidctest.Provider) oidcflow.Provider {
	return oidcflow.Provider{
		ID:           "idp",
		DisplayName:  "Fake",
		DiscoveryURL: idp.DiscoveryURL(),
		ClientID:     idp.ClientID,
		Enabled:      true,
	}
}

func newFlow(t *testing.T) *oidcflow.Flow {
	t.Helper()
	return &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}
}

// runLogin drives the fake provider through Begin and Complete.
func runLogin(t *testing.T, f *oidcflow.Flow, idp *oidctest.Provider, p oidcflow.Provider) (oidcflow.Result, error) {
	t.Helper()
	pend, authURL, err := f.Begin(context.Background(), p, "https://rp.example/callback", "/home")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	loc, err := idp.Authorize(authURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	if u.Query().Get("state") != pend.State {
		t.Fatalf("state mismatch")
	}
	return f.Complete(context.Background(), p, pend, u.Query().Get("code"))
}

func TestFlowES256(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	idp.Claims["realm_access"] = map[string]any{"roles": []any{"issuer-admin"}}
	f := newFlow(t)
	res, err := runLogin(t, f, idp, testProvider(idp))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if res.Issuer != idp.Issuer() || res.Subject != "user-1" || res.IDToken == "" || res.AccessToken == "" {
		t.Fatalf("bad result: %+v", res)
	}
	if res.TokenExpiresAt.IsZero() {
		t.Fatal("expected token expiry")
	}
	if got := oidcflow.ClaimPath(res.Claims, "realm_access.roles"); len(got) != 1 || got[0] != "issuer-admin" {
		t.Fatalf("claim path: %v", got)
	}
	// Second login reuses the cached metadata and JWKS.
	if _, err := runLogin(t, f, idp, testProvider(idp)); err != nil {
		t.Fatal(err)
	}
	if idp.Requests["/.well-known/openid-configuration"] != 1 || idp.Requests["/jwks"] != 1 {
		t.Fatalf("cache miss: %v", idp.Requests)
	}
}

func TestFlowRS256AndSecret(t *testing.T) {
	idp := oidctest.NewRS256()
	defer idp.Close()
	idp.ClientSecret = "s3cret"
	t.Setenv("IDP_SECRET", "s3cret")
	p := testProvider(idp)
	p.ClientSecret = oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "IDP_SECRET"}
	if _, err := runLogin(t, newFlow(t), idp, p); err != nil {
		t.Fatalf("complete: %v", err)
	}
	p.ClientSecret = oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "IDP_MISSING"}
	if _, err := runLogin(t, newFlow(t), idp, p); !errors.Is(err, oidcflow.ErrSecret) {
		t.Fatalf("want ErrSecret, got %v", err)
	}
}

func TestFlowKeyRotation(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	f := newFlow(t)
	if _, err := runLogin(t, f, idp, testProvider(idp)); err != nil {
		t.Fatal(err)
	}
	idp.RotateKey()
	if _, err := runLogin(t, f, idp, testProvider(idp)); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if idp.Requests["/jwks"] != 2 {
		t.Fatalf("want one refresh, got %d", idp.Requests["/jwks"])
	}
}

func TestFlowFailures(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	f := newFlow(t)
	p := testProvider(idp)

	p.Enabled = false
	if _, _, err := f.Begin(context.Background(), p, "https://rp/cb", ""); !errors.Is(err, oidcflow.ErrProviderDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	p.Enabled = true
	if _, _, err := f.Begin(context.Background(), p, "https://rp/cb", "https://evil"); !errors.Is(err, oidcflow.ErrReturnTo) {
		t.Fatalf("return_to: %v", err)
	}
	bad := p
	bad.DiscoveryURL = "http://127.0.0.1:1/.well-known/openid-configuration"
	if _, _, err := f.Begin(context.Background(), bad, "https://rp/cb", ""); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("upstream: %v", err)
	}
	if _, err := f.LogoutURL(context.Background(), bad, "", ""); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("logout upstream: %v", err)
	}

	pend, _, err := f.Begin(context.Background(), p, "https://rp/cb", "")
	if err != nil {
		t.Fatalf("f.Begin: %v", err)
	}
	if _, err := f.Complete(context.Background(), p, pend, ""); !errors.Is(err, oidcflow.ErrProviderError) {
		t.Fatalf("empty code: %v", err)
	}
	if _, err := f.Complete(context.Background(), p, pend, "nope"); !errors.Is(err, oidcflow.ErrProviderError) {
		t.Fatalf("bad code: %v", err)
	}
	expired := pend
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	if _, err := f.Complete(context.Background(), p, expired, "x"); !errors.Is(err, oidcflow.ErrStateUnknown) {
		t.Fatalf("expired: %v", err)
	}
	unreachable := pend
	unreachable.ProviderID = "x"
	if _, err := f.Complete(context.Background(), bad, pend, "x"); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("complete upstream: %v", err)
	}

	idp.WrongNonce = true
	if _, err := runLogin(t, f, idp, p); !errors.Is(err, oidcflow.ErrNonce) {
		t.Fatalf("nonce: %v", err)
	}
	idp.WrongNonce = false
	idp.OmitIDToken = true
	if _, err := runLogin(t, f, idp, p); !errors.Is(err, oidcflow.ErrProviderError) {
		t.Fatalf("no id_token: %v", err)
	}
	idp.OmitIDToken = false
	idp.TokenError = "invalid_client"
	if _, err := runLogin(t, f, idp, p); !errors.Is(err, oidcflow.ErrProviderError) {
		t.Fatalf("token error: %v", err)
	}
	idp.TokenError = ""

	// A token signed with a key the provider no longer publishes fails.
	wrongClient := p
	wrongClient.ClientID = "other"
	pend2, _, err := f.Begin(context.Background(), p, "https://rp/cb", "")
	if err != nil {
		t.Fatalf("f.Begin: %v", err)
	}
	loc, err := idp.Authorize(oidcflow.AuthorizeURL(idp.Server.URL+"/authorize", idp.ClientID, "https://rp/cb", pend2.State, pend2.Nonce, pend2.Verifier, []string{"openid"}))
	if err != nil {
		t.Fatalf("idp.Authorize: %v", err)
	}
	code := mustQuery(t, loc, "code")
	if _, err := f.Complete(context.Background(), wrongClient, pend2, code); !errors.Is(err, oidcflow.ErrSessionInvalid) {
		t.Fatalf("aud mismatch: %v", err)
	}
}

func mustQuery(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

func TestFlowInternalAuthorityAndTokenEndpointFailures(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	// The token endpoint lives on a host that returns garbage.
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/jwks") {
			http.Redirect(w, r, idp.Server.URL+"/jwks", http.StatusFound)
			return
		}
		_, errAssign := w.Write([]byte("<html>"))
		if errAssign != nil {
			t.Fatalf("w.Write: %v", errAssign)
		}
	}))
	defer garbage.Close()
	f := newFlow(t)
	p := testProvider(idp)
	p.InternalAuthority = garbage.URL
	m, err := f.Metadata(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.TokenEndpoint, garbage.URL) || !strings.HasPrefix(m.AuthorizationEndpoint, idp.Server.URL) {
		t.Fatalf("rebase: %+v", m)
	}
	if _, err := runLogin(t, f, idp, p); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("garbage token body: %v", err)
	}
	p.InternalAuthority = "http://127.0.0.1:1"
	if _, err := runLogin(t, f, idp, p); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("unreachable token endpoint: %v", err)
	}
}

func TestLogoutURL(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	f := newFlow(t)
	u, err := f.LogoutURL(context.Background(), testProvider(idp), "hint", "https://rp/")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/logout?", "id_token_hint=hint", "post_logout_redirect_uri=https%3A%2F%2Frp%2F", "client_id=client"} {
		if !strings.Contains(u, want) {
			t.Fatalf("%q lacks %q", u, want)
		}
	}
	if oidcflow.EndSessionURL("", "c", "", "") != "" {
		t.Fatal("expected empty")
	}
	if got := oidcflow.EndSessionURL("https://idp/logout?x=1", "c", "", ""); !strings.HasPrefix(got, "https://idp/logout?x=1&") {
		t.Fatal(got)
	}
	idp2 := oidctest.New()
	defer idp2.Close()
	idp2.NoEndSession = true
	u, err = f.LogoutURL(context.Background(), testProvider(idp2), "", "")
	if err != nil || u != "" {
		t.Fatalf("no end session: %q %v", u, err)
	}
}

func TestAuthorizeURL(t *testing.T) {
	u := oidcflow.AuthorizeURL("https://idp/auth?p=1", "c", "https://rp/cb", "st", "n", "verifier", []string{"openid", "email"})
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("p") != "1" || q.Get("response_type") != "code" || q.Get("nonce") != "n" || q.Get("state") != "st" || q.Get("code_challenge_method") != "S256" || q.Get("scope") != "openid email" {
		t.Fatalf("bad url %s", u)
	}
	if q.Has("response_mode") || strings.Contains(u, "token") {
		t.Fatal("implicit flow leaked")
	}
}

func TestValidReturnTo(t *testing.T) {
	good := []string{"/", "/home", "/a/b?c=d"}
	bad := []string{"", "home", "//evil", "/\\evil", "https://evil", "/a\nb", "/x?u=%zz\x00"}
	for _, s := range good {
		if !oidcflow.ValidReturnTo(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if oidcflow.ValidReturnTo(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func TestCacheAndMetadata(t *testing.T) {
	if _, err := oidcflow.ParseMetadata([]byte("{")); err == nil {
		t.Fatal("expected error")
	}
	m, err := oidcflow.ParseMetadata([]byte(`{"issuer":"https://i","authorization_endpoint":"https://i/a","token_endpoint":"https://i/t","jwks_uri":"https://i/j","end_session_endpoint":"https://i/e"}`))
	if err != nil || m.EndSessionEndpoint != "https://i/e" {
		t.Fatalf("%v %+v", err, m)
	}
	r := m.Rebase("http://internal:8080")
	if r.TokenEndpoint != "http://internal:8080/t" || r.JWKSURI != "http://internal:8080/j" || r.AuthorizationEndpoint != "https://i/a" {
		t.Fatalf("rebase: %+v", r)
	}
	if m.Rebase("").TokenEndpoint != "https://i/t" {
		t.Fatal("empty authority must keep endpoints")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/404":
			w.WriteHeader(http.StatusNotFound)
		case "/badjwks":
			_, errAssign := w.Write([]byte(`{"keys":[]}`))
			if errAssign != nil {
				t.Fatalf("w.Write: %v", errAssign)
			}
		case "/badmeta":
			_, errAssign2 := w.Write([]byte(`{}`))
			if errAssign2 != nil {
				t.Fatalf("w.Write: %v", errAssign2)
			}
		}
	}))
	defer srv.Close()
	c := oidcflow.NewCache(srv.Client(), time.Minute)
	ctx := context.Background()
	if _, err := c.Metadata(ctx, srv.URL+"/404"); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("404: %v", err)
	}
	if _, err := c.Metadata(ctx, srv.URL+"/badmeta"); err == nil {
		t.Fatal("bad metadata accepted")
	}
	if _, err := c.JWKS(ctx, srv.URL+"/badjwks", false); err == nil {
		t.Fatal("empty jwks accepted")
	}
	if _, err := c.JWKS(ctx, srv.URL+"/404", true); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("jwks 404: %v", err)
	}
	if _, err := c.Metadata(ctx, "://bad"); !errors.Is(err, oidcflow.ErrUpstream) {
		t.Fatalf("bad url: %v", err)
	}
}

func TestSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := oidcflow.EnvFileSecrets(oidcflow.SecretRef{Store: oidcflow.SecretFile, Name: path}); err != nil || v != "value" {
		t.Fatalf("file: %q %v", v, err)
	}
	if _, err := oidcflow.EnvFileSecrets(oidcflow.SecretRef{Store: oidcflow.SecretFile, Name: filepath.Join(dir, "missing")}); !errors.Is(err, oidcflow.ErrSecret) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := oidcflow.EnvFileSecrets(oidcflow.SecretRef{Store: oidcflow.SecretKMS, Name: "k"}); !errors.Is(err, oidcflow.ErrSecret) {
		t.Fatalf("kms: %v", err)
	}
	if v, err := oidcflow.EnvFileSecrets(oidcflow.SecretRef{}); err != nil || v != "" {
		t.Fatalf("empty: %q %v", v, err)
	}
}

func TestProviderValidateAndScopes(t *testing.T) {
	cases := map[string]oidcflow.Provider{
		"no id":         {ClientID: "c", DiscoveryURL: "https://i/.well-known/openid-configuration"},
		"no client":     {ID: "a", DiscoveryURL: "https://i/.well-known/openid-configuration"},
		"bad discovery": {ID: "a", ClientID: "c", DiscoveryURL: "ftp://x"},
		"bad internal":  {ID: "a", ClientID: "c", DiscoveryURL: "https://i/x", InternalAuthority: "nope"},
	}
	for name, p := range cases {
		if err := p.Validate(); !errors.Is(err, oidcflow.ErrInvalidProvider) {
			t.Errorf("%s: %v", name, err)
		}
	}
	p := oidcflow.Provider{ID: "a", ClientID: "c", DiscoveryURL: "https://i/x", InternalAuthority: "http://idp:8080"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := p.EffectiveScopes(); strings.Join(got, " ") != "openid profile email" {
		t.Fatal(got)
	}
	p.Scopes = []string{"email"}
	if got := p.EffectiveScopes(); strings.Join(got, " ") != "openid email" {
		t.Fatal(got)
	}
	p.Scopes = []string{"openid"}
	if got := p.EffectiveScopes(); strings.Join(got, " ") != "openid" {
		t.Fatal(got)
	}
}
