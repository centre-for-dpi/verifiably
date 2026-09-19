// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

func newSigner(t *testing.T) *oidcflow.Signer {
	t.Helper()
	key, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := oidcflow.NewSigner(key, "https://auth.example", "vca", time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignerRoundTrip(t *testing.T) {
	s := newSigner(t)
	tok, claims, err := s.Issue(oidcflow.Claims{Subject: "u", Roles: []string{"issuer-admin"}, Provider: "idp"})
	if err != nil {
		t.Fatal(err)
	}
	if claims.ID == "" || claims.SID != claims.ID || claims.Issuer != "https://auth.example" || claims.ExpiresAt <= claims.IssuedAt {
		t.Fatalf("claims: %+v", claims)
	}
	h, err := jose.PeekHeader(tok)
	if err != nil || h.Alg != "ES256" || h.Kid != s.KeyID() || h.Typ != "JWT" {
		t.Fatalf("header %+v %v", h, err)
	}
	got, err := s.Verify(tok)
	if err != nil || got.Subject != "u" || !got.HasRole("issuer-admin") || got.HasRole("x") {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if s.TTL() != time.Minute {
		t.Fatal("ttl")
	}
	// Other services verify with the JWKS.
	set := s.JWKS()
	if _, _, err := jose.VerifyWithJWKS(tok, set, []jose.Algorithm{jose.ES256}); err != nil {
		t.Fatalf("jwks verify: %v", err)
	}
	rec := httptest.NewRecorder()
	s.JWKSHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), s.KeyID()) {
		t.Fatalf("jwks handler: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.JWKSHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatal(rec.Code)
	}

	// Revoke puts the sid on the deny list.
	if _, err := s.Revoke(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(tok); !errors.Is(err, oidcflow.ErrSessionRevoked) {
		t.Fatalf("want revoked, got %v", err)
	}
	if _, err := s.Revoke(tok); !errors.Is(err, oidcflow.ErrSessionRevoked) {
		t.Fatalf("revoke twice: %v", err)
	}
	if !s.Deny().Revoked(claims.SID) {
		t.Fatal("deny list")
	}
}

func TestSignerRejects(t *testing.T) {
	s := newSigner(t)
	other := newSigner(t)
	tok, _, err := other.Issue(oidcflow.Claims{Subject: "u"})
	if err != nil {
		t.Fatalf("other.Issue: %v", err)
	}
	if _, err := s.Verify(tok); !errors.Is(err, oidcflow.ErrSessionInvalid) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := s.Verify("garbage"); !errors.Is(err, oidcflow.ErrSessionInvalid) {
		t.Fatalf("garbage: %v", err)
	}
	// Wrong issuer and audience.
	key, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatalf("oidcflow.GenerateKey: %v", err)
	}
	wrongIss, err := oidcflow.NewSigner(key, "https://other", "vca", time.Minute, nil)
	if err != nil {
		t.Fatalf("oidcflow.NewSigner: %v", err)
	}
	wrongAud, err := oidcflow.NewSigner(key, "https://auth.example", "other", time.Minute, nil)
	if err != nil {
		t.Fatalf("oidcflow.NewSigner: %v", err)
	}
	same, err := oidcflow.NewSigner(key, "https://auth.example", "vca", time.Minute, nil)
	if err != nil {
		t.Fatalf("oidcflow.NewSigner: %v", err)
	}
	for name, sg := range map[string]*oidcflow.Signer{"iss": wrongIss, "aud": wrongAud} {
		tok, _, err := sg.Issue(oidcflow.Claims{Subject: "u"})
		if err != nil {
			t.Fatalf("sg.Issue: %v", err)
		}
		if _, err := same.Verify(tok); !errors.Is(err, oidcflow.ErrSessionInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Expired.
	past := time.Now().Add(-time.Hour)
	same.WithClock(func() time.Time { return past })
	tok, _, errAssign := same.Issue(oidcflow.Claims{Subject: "u"})
	if errAssign != nil {
		t.Fatalf("same.Issue: %v", errAssign)
	}
	same.WithClock(time.Now)
	if _, err := same.Verify(tok); !errors.Is(err, oidcflow.ErrSessionInvalid) {
		t.Fatalf("expired: %v", err)
	}
	// A token whose payload is not a claim set.
	bad, err := jose.Sign(key, "k", "JWT", []int{1})
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	if _, err := same.Verify(bad); !errors.Is(err, oidcflow.ErrSessionInvalid) {
		t.Fatalf("bad payload: %v", err)
	}
	// Constructor checks.
	if _, err := oidcflow.NewSigner(nil, "i", "a", 0, nil); err == nil {
		t.Fatal("nil key")
	}
	if _, err := oidcflow.NewSigner(key, "", "a", 0, nil); err == nil {
		t.Fatal("no issuer")
	}
	def, err := oidcflow.NewSigner(key, "i", "a", 0, nil)
	if err != nil {
		t.Fatalf("oidcflow.NewSigner: %v", err)
	}
	if def.TTL() != oidcflow.DefaultSessionTTL {
		t.Fatal("default ttl")
	}
}

func TestKeyPEM(t *testing.T) {
	key, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatalf("oidcflow.GenerateKey: %v", err)
	}
	raw, err := oidcflow.EncodeKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := oidcflow.ParseKeyPEM(raw)
	if err != nil || !back.Equal(key) {
		t.Fatalf("round trip: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	back, err = oidcflow.ParseKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	if err != nil || !back.Equal(key) {
		t.Fatalf("pkcs8: %v", err)
	}
	if _, err := oidcflow.ParseKeyPEM([]byte("nope")); err == nil {
		t.Fatal("no block")
	}
	if _, err := oidcflow.ParseKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}})); err == nil {
		t.Fatal("bad der")
	}
	// A P-384 key is ECDSA but not P-256.
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	if _, err := oidcflow.NewSigner(p384, "i", "a", 0, nil); err == nil {
		t.Fatal("p384 accepted")
	}
	if _, err := oidcflow.EncodeKeyPEM(&ecdsa.PrivateKey{}); err == nil {
		t.Fatal("empty key encoded")
	}
	// A non EC PKCS#8 key.
	rsaKey := rsaPKCS8(t)
	if _, err := oidcflow.ParseKeyPEM(rsaKey); err == nil {
		t.Fatal("rsa accepted")
	}
}

func TestPendingAndDenyStores(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	ps := oidcflow.NewMemoryPending(clock)
	if err := ps.Put(oidcflow.Pending{State: "a", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("ps.Put: %v", err)
	}
	if err := ps.Put(oidcflow.Pending{State: "old", ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatalf("ps.Put: %v", err)
	}
	if _, ok := ps.Take("old"); ok {
		t.Fatal("expired taken")
	}
	if _, ok := ps.Take("missing"); ok {
		t.Fatal("missing taken")
	}
	if p, ok := ps.Take("a"); !ok || p.State != "a" {
		t.Fatal("take")
	}
	if _, ok := ps.Take("a"); ok {
		t.Fatal("taken twice")
	}
	if err := ps.Put(oidcflow.Pending{State: "b", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("ps.Put: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := ps.Take("b"); ok {
		t.Fatal("expired on take")
	}
	if err := ps.Put(oidcflow.Pending{State: "c", ExpiresAt: now.Add(-time.Minute)}); err != nil {
		t.Fatalf("ps.Put: %v", err)
	}
	if err := ps.Put(oidcflow.Pending{State: "d", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("ps.Put: %v", err)
	}

	dl := oidcflow.NewMemoryDenyList(clock)
	if err := dl.Revoke("s1", now.Add(time.Minute)); err != nil {
		t.Fatalf("dl.Revoke: %v", err)
	}
	if err := dl.Revoke("s0", now.Add(-time.Minute)); err != nil {
		t.Fatalf("dl.Revoke: %v", err)
	}
	if !dl.Revoked("s1") || dl.Revoked("s0") || dl.Revoked("none") {
		t.Fatal("deny list")
	}
	now = now.Add(2 * time.Minute)
	if err := dl.Revoke("s2", now.Add(time.Minute)); err != nil {
		t.Fatalf("dl.Revoke: %v", err)
	}
	if dl.Revoked("s1") {
		t.Fatal("expired entry stays")
	}
	if oidcflow.NewMemoryPending(nil) == nil || oidcflow.NewMemoryDenyList(nil) == nil {
		t.Fatal("nil clock")
	}
}

func TestCSRF(t *testing.T) {
	if _, err := oidcflow.NewCSRF([]byte("short")); !errors.Is(err, oidcflow.ErrCSRF) {
		t.Fatal("short key accepted")
	}
	c, err := oidcflow.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	tok := c.Token("sid-1")
	if !c.Check("sid-1", tok) {
		t.Fatal("valid token rejected")
	}
	if c.Check("sid-2", tok) || c.Check("", tok) || c.Check("sid-1", "nodot") || c.Check("sid-1", ".x") || c.Check("sid-1", tok+"x") {
		t.Fatal("bad token accepted")
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("csrf_token=form"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if oidcflow.CSRFFromRequest(r) != "form" {
		t.Fatal("form field")
	}
	r.Header.Set(oidcflow.CSRFHeader, "hdr")
	if oidcflow.CSRFFromRequest(r) != "hdr" {
		t.Fatal("header")
	}
}

func TestClaimHelpers(t *testing.T) {
	claims := map[string]any{
		"realm_access": map[string]any{"roles": []any{"a", 1, "b"}},
		"role":         "solo",
		"n":            3.0,
	}
	if got := oidcflow.ClaimPath(claims, "realm_access.roles"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatal(got)
	}
	if got := oidcflow.ClaimPath(claims, "role"); len(got) != 1 || got[0] != "solo" {
		t.Fatal(got)
	}
	for _, p := range []string{"", "missing", "realm_access.missing", "role.deeper", "n", "realm_access..roles"} {
		if got := oidcflow.ClaimPath(claims, p); got != nil {
			t.Fatalf("%q: %v", p, got)
		}
	}
	if oidcflow.PairwiseSubject("https://idp/", "sub") != "https://idp|sub" {
		t.Fatal("pairwise")
	}
	h1 := oidcflow.HashSubject([]byte("salt"), "https://idp|sub")
	h2 := oidcflow.HashSubject([]byte("other"), "https://idp|sub")
	if h1 == h2 || len(h1) != 43 || strings.Contains(h1, "idp") {
		t.Fatal("hash")
	}
}

func TestErrorMapping(t *testing.T) {
	cases := map[error]connect.Code{
		oidcflow.ErrProviderNotFound: connect.CodeNotFound,
		oidcflow.ErrProviderDisabled: connect.CodeFailedPrecondition,
		oidcflow.ErrInvalidProvider:  connect.CodeInvalidArgument,
		oidcflow.ErrSessionInvalid:   connect.CodeUnauthenticated,
		oidcflow.ErrForbidden:        connect.CodePermissionDenied,
		oidcflow.ErrUpstream:         connect.CodeUnavailable,
		errors.New("other"):          connect.CodeInternal,
	}
	for err, code := range cases {
		if got := oidcflow.ConnectError(err).Code(); got != code {
			t.Errorf("%v: %v", err, got)
		}
	}
	ce := connect.NewError(connect.CodeAlreadyExists, errors.New("x"))
	if oidcflow.ConnectError(ce) != ce {
		t.Fatal("connect error not kept")
	}
	statuses := map[error]int{
		oidcflow.ErrProviderNotFound: 404,
		oidcflow.ErrReturnTo:         400,
		oidcflow.ErrSessionRevoked:   401,
		oidcflow.ErrForbidden:        403,
		oidcflow.ErrProviderError:    502,
		errors.New("other"):          500,
	}
	for err, want := range statuses {
		if got := oidcflow.HTTPStatus(err); got != want {
			t.Errorf("%v: %d", err, got)
		}
	}
}

func rsaPKCS8(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
