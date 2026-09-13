// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

func TestPrincipalRules(t *testing.T) {
	p := Principal{Roles: []string{Viewer}}
	if !p.HasRole(Viewer) || p.HasRole(Admin) {
		t.Fatal("has role")
	}
	if p.Allowed(nil) || p.Allowed([]string{Operator}) || !p.Allowed([]string{Operator, Viewer}) {
		t.Fatal("allowed")
	}
	if !(Principal{Roles: []string{Admin}}).Allowed(nil) {
		t.Fatal("admin")
	}
}

func TestContext(t *testing.T) {
	if _, err := Require(context.Background()); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("err %v", err)
	}
	ctx := WithPrincipal(context.Background(), Principal{Subject: "s"})
	p, err := Require(ctx)
	if err != nil || p.Subject != "s" {
		t.Fatal("require")
	}
}

func TestFromHeaders(t *testing.T) {
	h := http.Header{}
	if _, ok := FromHeaders(h); ok {
		t.Fatal("empty")
	}
	h.Set(HeaderRoles, " issuer-admin, ,issuer-viewer ")
	h.Set(HeaderSubject, "alice")
	h.Set(HeaderTenant, "t1")
	p, ok := FromHeaders(h)
	if !ok || p.Subject != "alice" || p.Tenant != "t1" || len(p.Roles) != 2 || p.Roles[1] != Viewer {
		t.Fatalf("%+v", p)
	}
}

func signed(t *testing.T, key any, kid string, c any) string {
	t.Helper()
	tok, err := jose.Sign(key, kid, "JWT", c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestJWKSVerifier(t *testing.T) {
	key, _ := jose.GenerateKey(jose.ES256)
	pub, _ := jose.PublicJWK(key, "k1")
	set := jose.JWKS{Keys: []jose.JWK{pub}}
	now := func() time.Time { return time.Unix(1000, 0) }
	v := JWKSVerifier(set, now)
	p, err := v(signed(t, key, "k1", map[string]any{"sub": "alice", "exp": 2000, "roles": []string{Operator}, "tenant": "t"}))
	if err != nil || p.Subject != "alice" || p.Tenant != "t" || !p.HasRole(Operator) {
		t.Fatalf("%+v %v", p, err)
	}
	if _, err := v(signed(t, key, "k1", map[string]any{"sub": "alice", "exp": 999})); !errors.Is(err, ErrNoSession) {
		t.Fatalf("expired %v", err)
	}
	if _, err := v(signed(t, key, "k1", []int{1})); !errors.Is(err, ErrNoSession) {
		t.Fatalf("bad claims %v", err)
	}
	other, _ := jose.GenerateKey(jose.ES256)
	if _, err := v(signed(t, other, "k1", map[string]any{"exp": 2000})); !errors.Is(err, ErrNoSession) {
		t.Fatalf("wrong key %v", err)
	}
}

func TestInterceptor(t *testing.T) {
	var got Principal
	next := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		got, _ = From(ctx)
		return nil, nil
	}
	call := func(i connect.UnaryInterceptorFunc, h http.Header) error {
		req := connect.NewRequest(&struct{}{})
		for k, v := range h {
			req.Header().Set(k, v[0])
		}
		_, err := i(next)(context.Background(), req)
		return err
	}
	headerMode := Interceptor(nil)
	if err := call(headerMode, nil); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no header %v", err)
	}
	if err := call(headerMode, http.Header{HeaderRoles: {Admin}}); err != nil || !got.HasRole(Admin) {
		t.Fatalf("header %v", err)
	}
	verify := func(token string) (Principal, error) {
		if token != "good" {
			return Principal{}, ErrNoSession
		}
		return Principal{Subject: "bob"}, nil
	}
	jwtMode := Interceptor(verify)
	if err := call(jwtMode, http.Header{HeaderRoles: {Admin}}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no bearer %v", err)
	}
	if err := call(jwtMode, http.Header{"Authorization": {"Bearer bad"}}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad bearer %v", err)
	}
	if err := call(jwtMode, http.Header{"Authorization": {"bearer good"}}); err != nil || got.Subject != "bob" {
		t.Fatalf("good bearer %v", err)
	}
}
