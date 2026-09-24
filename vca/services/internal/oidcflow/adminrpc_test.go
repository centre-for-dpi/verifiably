// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

var adminNow = time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)

// adminSigner stands in for the admin service: it signs admin sessions
// and serves its key set.
type adminSigner struct {
	signer *oidcflow.Signer
}

func newAdminSigner(t *testing.T, audience string) *adminSigner {
	t.Helper()
	key := anyval.Must(oidcflow.GenerateKey())
	signer := anyval.Must(oidcflow.NewSigner(key, "https://admin.test", audience, 15*time.Minute, nil))
	signer.WithClock(func() time.Time { return adminNow })
	return &adminSigner{signer: signer}
}

func (a *adminSigner) token(t *testing.T, roles ...string) string {
	t.Helper()
	tok, _, err := a.signer.Issue(oidcflow.Claims{Subject: "kc|root", Roles: roles})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (a *adminSigner) server(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("GET /.well-known/jwks.json", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		a.signer.JWKSHandler().ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func bearer(token string) http.Header {
	h := http.Header{}
	if token != "" {
		h.Set("Authorization", "Bearer "+token)
	}
	return h
}

// TestAdminJWTAuthorizerAcceptsAdminSession is ADR-035 decision 5: an
// auth service accepts the admin session token when the admin key set
// signed it.
func TestAdminJWTAuthorizerAcceptsAdminSession(t *testing.T) {
	admin := newAdminSigner(t, oidcflow.AdminAudience)
	var hits atomic.Int32
	srv := admin.server(t, &hits)
	auth := oidcflow.JWTAuthorizer{
		JWKSURL: srv.URL + "/.well-known/jwks.json", Audience: oidcflow.AdminAudience,
		Cache: oidcflow.NewCache(srv.Client(), 0), Now: func() time.Time { return adminNow },
	}.Authorize()
	ctx := context.Background()
	if err := auth(ctx, bearer(admin.token(t, "super-admin"))); err != nil {
		t.Fatalf("admin session: %v", err)
	}
	if err := auth(ctx, bearer(admin.token(t, "super-admin"))); err != nil {
		t.Fatalf("second admin session: %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("key set fetched %d times, want 1", n)
	}
	// A rotated key is fetched once more.
	rotated := newAdminSigner(t, oidcflow.AdminAudience)
	admin.signer = rotated.signer
	if err := auth(ctx, bearer(rotated.token(t))); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("key set fetched %d times, want 2", n)
	}
	// A flood of bad tokens does not fetch again inside the hold time.
	for range 3 {
		if err := auth(ctx, bearer("x.y.z")); err == nil {
			t.Fatal("garbage passed")
		}
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("key set fetched %d times, want 2 within the hold time", n)
	}
	// The convenience constructor reads the same key set with the real
	// clock.
	live := newAdminSigner(t, oidcflow.AdminAudience)
	live.signer.WithClock(time.Now)
	admin.signer = live.signer
	if err := oidcflow.AdminJWTAuthorizer(srv.URL+"/.well-known/jwks.json")(ctx, bearer(live.token(t))); err != nil {
		t.Fatalf("constructor: %v", err)
	}
}

// TestAdminJWTAuthorizerRejectsIssuerSession proves a session of another
// audience, another key, an expired session, a missing token, and an
// unreachable key set are all refused.
func TestAdminJWTAuthorizerRejectsIssuerSession(t *testing.T) {
	admin := newAdminSigner(t, oidcflow.AdminAudience)
	var hits atomic.Int32
	srv := admin.server(t, &hits)
	clock := adminNow
	auth := oidcflow.JWTAuthorizer{
		JWKSURL: srv.URL + "/.well-known/jwks.json", Audience: oidcflow.AdminAudience,
		Cache: oidcflow.NewCache(srv.Client(), 0), Now: func() time.Time { return clock },
	}.Authorize()
	ctx := context.Background()

	issuer := newAdminSigner(t, "vca-issuer")
	if err := auth(ctx, bearer(issuer.token(t, "issuer-admin"))); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatalf("issuer session: %v", err)
	}
	other := newAdminSigner(t, oidcflow.AdminAudience)
	if err := auth(ctx, bearer(other.token(t))); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatalf("another key: %v", err)
	}
	if err := auth(ctx, bearer("")); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatalf("no token: %v", err)
	}
	token := admin.token(t)
	clock = adminNow.Add(time.Hour)
	if err := auth(ctx, bearer(token)); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatalf("expired: %v", err)
	}
	if err := oidcflow.AdminJWTAuthorizer("")(ctx, bearer(token)); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatalf("no URL: %v", err)
	}
	srv.Close()
	down := oidcflow.JWTAuthorizer{JWKSURL: srv.URL + "/.well-known/jwks.json", Audience: oidcflow.AdminAudience}.Authorize()
	if err := down(ctx, bearer(admin.token(t))); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Fatalf("unreachable key set: %v", err)
	}
}
