// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signRS256 builds an RS256 JWT by hand, as the legacy tests did.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	input := b64u(hdr) + "." + b64u(pl)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64u(sig)
}

// PKCE test vector from RFC 7636 appendix B.
func TestPKCE(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if got := Challenge(verifier); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("Challenge = %q", got)
	}
	if !VerifyChallenge(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM") || VerifyChallenge(verifier, "nope") {
		t.Fatal("VerifyChallenge")
	}
	v := NewVerifier()
	if len(v) != 43 || v == NewVerifier() {
		t.Fatalf("NewVerifier = %q", v)
	}
	if s := NewState(); len(s) != 22 || s == NewState() {
		t.Fatalf("NewState = %q", s)
	}
}

func TestDiscovery(t *testing.T) {
	raw := []byte(`{"issuer":"https://localhost:9443","authorization_endpoint":"https://localhost:9443/oauth2/authorize","token_endpoint":"https://localhost:9443/oauth2/token","userinfo_endpoint":"https://localhost:9443/oauth2/userinfo","jwks_uri":"https://localhost:9443/oauth2/jwks","scopes_supported":["openid"]}`)
	d, err := ParseDiscovery(raw)
	if err != nil || d.JWKSURI != "https://localhost:9443/oauth2/jwks" || len(d.ScopesSupported) != 1 {
		t.Fatalf("ParseDiscovery = %+v, %v", d, err)
	}
	r := d.Rebase("https://wso2is:9443")
	if r.TokenEndpoint != "https://wso2is:9443/oauth2/token" || r.JWKSURI != "https://wso2is:9443/oauth2/jwks" || r.Issuer != d.Issuer {
		t.Fatalf("Rebase = %+v", r)
	}
	if _, err := ParseDiscovery([]byte("{")); err == nil {
		t.Fatal("bad json must fail")
	}
	if _, err := ParseDiscovery([]byte(`{"issuer":"x"}`)); err == nil {
		t.Fatal("missing endpoints must fail")
	}
	if DiscoveryURL("https://idp.example/realms/a/") != "https://idp.example/realms/a/.well-known/openid-configuration" {
		t.Fatal("DiscoveryURL")
	}
}

// Regression: legacy TestSwapAuthority and TestURLAuthority.
func TestSwapAuthority(t *testing.T) {
	cases := []struct{ name, endpoint, authority, want string }{
		{"localhost to container", "https://localhost:9443/oauth2/token", "https://wso2is:9443", "https://wso2is:9443/oauth2/token"},
		{"container to public", "https://wso2is:9443/oauth2/authorize?foo=1", "https://172.24.0.1:9443", "https://172.24.0.1:9443/oauth2/authorize?foo=1"},
		{"scheme change", "http://keycloak:8180/realms/x/protocol/openid-connect/token", "https://auth.example.com", "https://auth.example.com/realms/x/protocol/openid-connect/token"},
		{"empty endpoint", "", "https://x:1", ""},
		{"empty authority", "https://localhost:9443/oauth2/token", "", "https://localhost:9443/oauth2/token"},
		{"bad endpoint", "://bad", "https://x:1", "://bad"},
		{"bad authority", "https://a/b", "://bad", "https://a/b"},
		{"authority without host", "https://a/b", "nohost", "https://a/b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SwapAuthority(tc.endpoint, tc.authority); got != tc.want {
				t.Fatalf("SwapAuthority = %q, want %q", got, tc.want)
			}
		})
	}
	if Authority("https://a:1/p?q") != "https://a:1" || Authority("nope") != "" || Authority("://x") != "" {
		t.Fatal("Authority")
	}
}

func TestAuthorizeURL(t *testing.T) {
	u := AuthorizeURL("https://idp/authorize", "client", "https://app/cb", "st", "verifier", []string{"openid", "email"})
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("code_challenge") != Challenge("verifier") || q.Get("scope") != "openid email" || q.Get("state") != "st" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("query = %v", q)
	}
	if !strings.HasPrefix(AuthorizeURL("https://idp/authorize?tenant=a", "c", "r", "s", "v", nil), "https://idp/authorize?tenant=a&") {
		t.Fatal("existing query must use &")
	}
}

type tokenFixture struct {
	rsaKey *rsa.PrivateKey
	ecKey  crypto.PrivateKey
	keys   jose.JWKS
}

func newTokenFixture(t *testing.T) tokenFixture {
	t.Helper()
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := jose.GenerateKey(jose.ES256)
	j1, _ := jose.PublicJWK(rsaKey, "k1")
	j2, _ := jose.PublicJWK(ecKey, "ec1")
	return tokenFixture{rsaKey: rsaKey, ecKey: ecKey, keys: jose.JWKS{Keys: []jose.JWK{j1, j2}}}
}

func baseOpts() TokenOptions {
	return TokenOptions{Issuers: []string{"http://keycloak:8180/realms/x", "https://auth.example/realms/x/"}, ClientID: "client", Now: now}
}

func TestVerifyTokenValid(t *testing.T) {
	f := newTokenFixture(t)
	exp := float64(now.Add(time.Hour).Unix())
	rs := signRS256(t, f.rsaKey, "k1", map[string]any{"iss": "https://auth.example/realms/x", "sub": "user-1", "given_name": "Ana", "aud": "client", "exp": exp})
	claims, err := VerifyToken(rs, f.keys, baseOpts())
	if err != nil || claims["sub"] != "user-1" {
		t.Fatalf("RS256: %v %v", claims, err)
	}
	if sc := StringClaims(claims); sc["given_name"] != "Ana" || len(sc) != 4 {
		t.Fatalf("StringClaims = %v", sc)
	}
	es, _ := jose.Sign(f.ecKey, "ec1", "JWT", map[string]any{"iss": "http://keycloak:8180/realms/x/", "sub": "user-2", "aud": []string{"account", "client"}, "exp": exp, "nbf": float64(now.Add(30 * time.Second).Unix())})
	if claims, err := VerifyToken(es, f.keys, baseOpts()); err != nil || claims["sub"] != "user-2" {
		t.Fatalf("ES256: %v %v", claims, err)
	}
	azp, _ := jose.Sign(f.ecKey, "ec1", "JWT", map[string]any{"iss": "http://keycloak:8180/realms/x", "azp": "client", "exp": exp})
	if _, err := VerifyToken(azp, f.keys, baseOpts()); err != nil {
		t.Fatalf("azp fallback: %v", err)
	}
	noClient := baseOpts()
	noClient.ClientID = ""
	noClient.Now = time.Time{}
	fresh, _ := jose.Sign(f.ecKey, "ec1", "JWT", map[string]any{"iss": "http://keycloak:8180/realms/x", "exp": float64(time.Now().Add(time.Hour).Unix())})
	if _, err := VerifyToken(fresh, f.keys, noClient); err != nil {
		t.Fatalf("no client id, wall clock: %v", err)
	}
}

func TestVerifyTokenRejects(t *testing.T) {
	f := newTokenFixture(t)
	exp := float64(now.Add(time.Hour).Unix())
	base := map[string]any{"iss": "https://auth.example/realms/x", "sub": "u", "aud": "client", "exp": exp}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	tampered := signRS256(t, f.rsaKey, "k1", base)
	parts := strings.Split(tampered, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[len(sig)/2] ^= 0xff
	tampered = parts[0] + "." + parts[1] + "." + b64u(sig)
	strict := baseOpts()
	strict.Leeway = time.Second

	cases := []struct {
		name string
		tok  string
		opts TokenOptions
		want error
	}{
		{"not a jwt", "abc", baseOpts(), nil},
		{"wrong issuer", signRS256(t, f.rsaKey, "k1", with(map[string]any{"iss": "https://evil.example"})), baseOpts(), ErrIssuer},
		{"tampered", tampered, baseOpts(), jose.ErrSignatureInvalid},
		{"wrong key", signRS256(t, other, "k1", base), baseOpts(), jose.ErrSignatureInvalid},
		{"unknown kid", signRS256(t, f.rsaKey, "k9", base), baseOpts(), jose.ErrNoKey},
		{"expired", signRS256(t, f.rsaKey, "k1", with(map[string]any{"exp": float64(now.Add(-time.Hour).Unix())})), baseOpts(), ErrExpired},
		{"no exp", signRS256(t, f.rsaKey, "k1", map[string]any{"iss": "https://auth.example/realms/x", "aud": "client"}), baseOpts(), nil},
		{"not yet valid", signRS256(t, f.rsaKey, "k1", with(map[string]any{"nbf": float64(now.Add(10 * time.Minute).Unix())})), baseOpts(), ErrNotYet},
		{"nbf beyond strict leeway", signRS256(t, f.rsaKey, "k1", with(map[string]any{"nbf": float64(now.Add(30 * time.Second).Unix())})), strict, ErrNotYet},
		{"wrong aud", signRS256(t, f.rsaKey, "k1", with(map[string]any{"aud": "other-client"})), baseOpts(), ErrAudience},
		{"aud array without client", signRS256(t, f.rsaKey, "k1", with(map[string]any{"aud": []any{"a", 1}})), baseOpts(), ErrAudience},
		{"no aud no azp", signRS256(t, f.rsaKey, "k1", map[string]any{"iss": "https://auth.example/realms/x", "exp": exp}), baseOpts(), ErrAudience},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyToken(tc.tok, f.keys, tc.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func FuzzParseDiscovery(f *testing.F) {
	f.Add([]byte(`{"issuer":"a","authorization_endpoint":"https://a/x","token_endpoint":"https://a/t"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if d, err := ParseDiscovery(data); err == nil {
			_ = d.Rebase("https://x:1")
		}
	})
}

func FuzzParseToken(f *testing.F) {
	key, _ := jose.GenerateKey(jose.ES256)
	pub, _ := jose.PublicJWK(key, "k")
	tok, _ := jose.Sign(key, "k", "JWT", map[string]any{"iss": "i", "exp": float64(now.Add(time.Hour).Unix()), "aud": "c"})
	f.Add(tok)
	f.Fuzz(func(t *testing.T, tok string) {
		_, _ = VerifyToken(tok, jose.JWKS{Keys: []jose.JWK{pub}}, TokenOptions{Issuers: []string{"i"}, ClientID: "c", Now: now})
	})
}
