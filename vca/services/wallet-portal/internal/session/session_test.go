// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
)

// fixture holds a signing key and the key set that matches it.
type fixture struct {
	key *ecdsa.PrivateKey
	set jose.JWKS
	kid string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	key, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(key.Public(), "")
	if err != nil {
		t.Fatal(err)
	}
	kid, err := jose.Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	pub.KeyID = kid
	return fixture{key: key, set: jose.JWKS{Keys: []jose.JWK{pub}}, kid: kid}
}

func (f fixture) token(t *testing.T, c oidcflow.Claims) string {
	t.Helper()
	tok, err := jose.Sign(f.key, f.kid, "JWT", c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func claims(exp time.Time) oidcflow.Claims {
	return oidcflow.Claims{
		Issuer: "https://auth.example", Subject: "https://idp|abc", ID: "jti-1", SID: "sid-1",
		WalletID: "wallet-1", HolderDID: "did:jwk:x", HasHolderKey: true, Name: "Wanjiku Njeri",
		ExpiresAt: exp.Unix(), IssuedAt: exp.Add(-time.Hour).Unix(),
	}
}

func at(s string) func() time.Time {
	t, verr := time.Parse(time.RFC3339, s)
	if verr != nil {
		panic(verr)
	}
	return func() time.Time { return t }
}

func verifier(t *testing.T, f fixture, issuer string, now func() time.Time) session.Verifier {
	t.Helper()
	v, err := session.NewVerifier(session.Options{Keys: session.StaticKeys(f.set), Issuer: issuer, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifierAccepts(t *testing.T) {
	f := newFixture(t)
	now := at("2026-09-19T10:00:00Z")
	tok := f.token(t, claims(now().Add(time.Hour)))
	v := verifier(t, f, "https://auth.example", now)
	got, err := v(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "https://idp|abc" || got.WalletID != "wallet-1" || !got.HasHolderKey {
		t.Fatalf("citizen = %+v", got)
	}
	if got.SessionID != "sid-1" || got.HolderDID != "did:jwk:x" || got.Name != "Wanjiku Njeri" {
		t.Fatalf("citizen = %+v", got)
	}
	if got.WalletKey() != "wallet-1" {
		t.Fatalf("wallet key = %q", got.WalletKey())
	}
	bare := session.Citizen{Subject: "https://idp|abc"}
	if bare.WalletKey() != "https...idp.abc" {
		t.Fatalf("wallet key = %q", bare.WalletKey())
	}
}

func TestVerifierRejects(t *testing.T) {
	f := newFixture(t)
	now := at("2026-09-19T10:00:00Z")
	other := newFixture(t)
	cases := map[string]string{
		"expired":     f.token(t, claims(now().Add(-time.Minute))),
		"other key":   other.token(t, claims(now().Add(time.Hour))),
		"not a token": "abc.def",
	}
	v := verifier(t, f, "", now)
	for name, tok := range cases {
		if _, err := v(tok); !errors.Is(err, session.ErrNoSession) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	wrongIssuer := verifier(t, f, "https://other.example", now)
	if _, err := wrongIssuer(f.token(t, claims(now().Add(time.Hour)))); err == nil {
		t.Fatal("want an issuer error")
	}
	noSubject := claims(now().Add(time.Hour))
	noSubject.Subject = ""
	if _, err := v(f.token(t, noSubject)); err == nil {
		t.Fatal("want a subject error")
	}
	sidLess := claims(now().Add(time.Hour))
	sidLess.SID = ""
	got, err := v(f.token(t, sidLess))
	if err != nil || got.SessionID != "jti-1" {
		t.Fatalf("sid fallback = %q %v", got.SessionID, err)
	}
}

func TestNewVerifierNeedsKeys(t *testing.T) {
	if _, err := session.NewVerifier(session.Options{}); err == nil {
		t.Fatal("want an error")
	}
}

func TestVerifierKeySourceFails(t *testing.T) {
	v, err := session.NewVerifier(session.Options{
		Keys: func(context.Context) (jose.JWKS, error) { return jose.JWKS{}, errors.New("down") },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v("a.b.c"); !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifierBadClaims(t *testing.T) {
	f := newFixture(t)
	tok, err := jose.Sign(f.key, f.kid, "JWT", []string{"not an object"})
	if err != nil {
		t.Fatal(err)
	}
	v := verifier(t, f, "", time.Now)
	if _, err := v(tok); !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("err = %v", err)
	}
}

func TestCachedKeys(t *testing.T) {
	f := newFixture(t)
	raw, err := json.Marshal(f.set)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	clock := time.Unix(1000, 0)
	keys := session.CachedKeys("https://auth.example/jwks", time.Minute,
		func(context.Context, string) ([]byte, error) {
			calls++
			return raw, nil
		}, func() time.Time { return clock })
	for i := 0; i < 3; i++ {
		if _, err := keys(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("calls = %d", calls)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err := keys(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls after the TTL = %d", calls)
	}
}

func TestCachedKeysErrors(t *testing.T) {
	down := session.CachedKeys("u", time.Minute, func(context.Context, string) ([]byte, error) {
		return nil, errors.New("down")
	}, nil)
	if _, err := down(context.Background()); err == nil {
		t.Fatal("want a fetch error")
	}
	bad := session.CachedKeys("u", time.Minute, func(context.Context, string) ([]byte, error) {
		return []byte("{"), nil
	}, nil)
	if _, err := bad(context.Background()); err == nil {
		t.Fatal("want a parse error")
	}
}

func TestTokenOf(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if session.TokenOf(r.Header, nil) != "" {
		t.Fatal("want no token")
	}
	if session.TokenOf(r.Header, r.Cookie) != "" {
		t.Fatal("want no cookie token")
	}
	r.AddCookie(&http.Cookie{Name: session.CookieName, Value: "from-cookie"})
	if got := session.TokenOf(r.Header, r.Cookie); got != "from-cookie" {
		t.Fatalf("cookie token = %q", got)
	}
	r.Header.Set("Authorization", "Bearer from-header")
	if got := session.TokenOf(r.Header, r.Cookie); got != "from-header" {
		t.Fatalf("header token = %q", got)
	}
}

func TestInterceptor(t *testing.T) {
	f := newFixture(t)
	now := at("2026-09-19T10:00:00Z")
	v := verifier(t, f, "", now)
	var seen session.Citizen
	next := connect.UnaryFunc(func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		c, err := session.Require(ctx)
		if err != nil {
			return nil, err
		}
		seen = c
		return nil, nil
	})
	req := connect.NewRequest(&struct{}{})
	handler := session.Interceptor(v)(next)
	if _, err := handler(context.Background(), req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no token: %v", err)
	}
	req.Header().Set("Authorization", "Bearer "+f.token(t, claims(now().Add(time.Hour))))
	if _, err := handler(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if seen.Subject == "" {
		t.Fatal("want a citizen on the context")
	}
	req.Header().Set("Authorization", "Bearer broken")
	if _, err := handler(context.Background(), req); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad token: %v", err)
	}
	if _, err := session.Interceptor(nil)(next)(context.Background(), req); err == nil {
		t.Fatal("want an error with no verifier")
	}
}

func TestRequireWithoutCitizen(t *testing.T) {
	if _, err := session.Require(context.Background()); !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("err = %v", err)
	}
	if _, ok := session.From(context.Background()); ok {
		t.Fatal("want no citizen")
	}
}

func TestMiddleware(t *testing.T) {
	f := newFixture(t)
	now := at("2026-09-19T10:00:00Z")
	v := verifier(t, f, "", now)
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := session.From(r.Context())
		mustWrite(t, w, []byte(c.Subject))
	})
	guarded := session.Middleware(v, "/wallet/login")(page)
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/", nil))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("no session: %d", rec.Code)
	}
	ok := httptest.NewRequest(http.MethodGet, "/wallet/", nil)
	ok.AddCookie(&http.Cookie{Name: session.CookieName, Value: f.token(t, claims(now().Add(time.Hour)))})
	rec = httptest.NewRecorder()
	guarded.ServeHTTP(rec, ok)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "idp") {
		t.Fatalf("session: %d %q", rec.Code, rec.Body.String())
	}
	bad := httptest.NewRequest(http.MethodGet, "/wallet/", nil)
	bad.AddCookie(&http.Cookie{Name: session.CookieName, Value: "broken"})
	rec = httptest.NewRecorder()
	guarded.ServeHTTP(rec, bad)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("bad token: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	session.Middleware(nil, "")(page).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/wallet/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no login page: %d", rec.Code)
	}
}

func TestGuard(t *testing.T) {
	if _, err := session.NewGuard([]byte("short")); err == nil {
		t.Fatal("want a key error")
	}
	g, err := session.NewGuard([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	c := session.Citizen{Subject: "s", SessionID: "sid-1"}
	tok := g.Token(c)
	form := httptest.NewRequest(http.MethodPost, "/wallet/accept", strings.NewReader(session.Field+"="+tok))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := g.Check(form, c); err != nil {
		t.Fatal(err)
	}
	other := httptest.NewRequest(http.MethodPost, "/wallet/accept", nil)
	if err := g.Check(other, c); !errors.Is(err, session.ErrCSRF) {
		t.Fatalf("err = %v", err)
	}
	bare := session.Citizen{Subject: "s"}
	head := httptest.NewRequest(http.MethodPost, "/wallet/accept", nil)
	head.Header.Set("X-CSRF-Token", g.Token(bare))
	if err := g.Check(head, bare); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(head, c); err == nil {
		t.Fatal("want a token of another session to fail")
	}
}
