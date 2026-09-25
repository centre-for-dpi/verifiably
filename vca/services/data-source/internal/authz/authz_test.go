// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
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

// TestSessionVerifierUsesTheStaffGuard proves the RPCs accept only a
// session that the key set of issuer-auth signed, for the issuer
// audience, and read its roles and tenant.
func TestSessionVerifierUsesTheStaffGuard(t *testing.T) {
	now := time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	guard, err := staffsession.New(staffsession.Options{
		Keys: issuer.Keys(), Audience: staffsession.IssuerAudience, Cookie: staffsession.IssuerCookie,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	v := SessionVerifier(guard.Verify)
	p, err := v(context.Background(), issuer.Token(t, "kc|amina", Operator))
	if err != nil || p.Subject != "kc|amina" || !p.HasRole(Operator) {
		t.Fatalf("%+v %v", p, err)
	}
	other := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	if _, err := v(context.Background(), other.Token(t, "kc|mallory", Admin)); !errors.Is(err, ErrNoSession) {
		t.Fatalf("a session of another key set: %v", err)
	}
	verifier := staffsessiontest.New(t, staffsession.VerifierAudience, now)
	if _, err := v(context.Background(), verifier.Token(t, "kc|amina", Admin)); !errors.Is(err, ErrNoSession) {
		t.Fatalf("a session of another audience: %v", err)
	}
	s := FromSession(staffsession.Session{Subject: "x", Tenant: "t1", Roles: []string{Viewer}})
	if s.Tenant != "t1" || !s.HasRole(Viewer) {
		t.Fatalf("principal = %+v", s)
	}
}

// TestInterceptorNeedsABearerSession proves no header stands in for the
// session: the roles header of the old header mode gets no principal.
func TestInterceptorNeedsABearerSession(t *testing.T) {
	var got Principal
	next := func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		got, _ = From(ctx)
		return nil, nil
	}
	call := func(h http.Header) error {
		req := connect.NewRequest(&struct{}{})
		for k, v := range h {
			req.Header().Set(k, v[0])
		}
		_, err := Interceptor(func(_ context.Context, token string) (Principal, error) {
			if token != "good" {
				return Principal{}, ErrNoSession
			}
			return Principal{Subject: "bob"}, nil
		})(next)(context.Background(), req)
		return err
	}
	if err := call(nil); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no session %v", err)
	}
	if err := call(http.Header{"X-Vca-Roles": {Admin}}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("a roles header must not open the service: %v", err)
	}
	if err := call(http.Header{"Authorization": {"Bearer bad"}}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad bearer %v", err)
	}
	if err := call(http.Header{"Authorization": {"bearer good"}}); err != nil || got.Subject != "bob" {
		t.Fatalf("good bearer %v", err)
	}
}
