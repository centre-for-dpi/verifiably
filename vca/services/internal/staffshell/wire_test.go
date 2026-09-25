// SPDX-License-Identifier: Apache-2.0

package staffshell_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	issuerauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	verifierauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1/verifierauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
)

type issuerAuth struct {
	issuerauthv1connect.UnimplementedIssuerAuthServiceHandler
	ended []string
}

func (a *issuerAuth) Logout(_ context.Context, req *connect.Request[issuerauthv1.LogoutRequest]) (*connect.Response[issuerauthv1.LogoutResponse], error) {
	a.ended = append(a.ended, req.Msg.GetSessionToken())
	return connect.NewResponse(&issuerauthv1.LogoutResponse{ProviderLogoutUrl: "https://idp.example/issuer"}), nil
}

type verifierAuth struct {
	verifierauthv1connect.UnimplementedVerifierAuthServiceHandler
	ended []string
}

func (a *verifierAuth) Logout(_ context.Context, req *connect.Request[verifierauthv1.LogoutRequest]) (*connect.Response[verifierauthv1.LogoutResponse], error) {
	a.ended = append(a.ended, req.Msg.GetSessionToken())
	return connect.NewResponse(&verifierauthv1.LogoutResponse{}), nil
}

// signOut posts the sign out form with a session cookie.
func signOut(h http.Handler, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/signout", nil)
	r.AddCookie(&http.Cookie{Name: cookie, Value: "jwt"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestWireEndsTheSessionOfEachRole(t *testing.T) {
	ia, va := &issuerAuth{}, &verifierAuth{}
	mux := http.NewServeMux()
	mux.Handle(issuerauthv1connect.NewIssuerAuthServiceHandler(ia))
	mux.Handle(verifierauthv1connect.NewVerifierAuthServiceHandler(va))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	for _, c := range []struct {
		role   commonv1.Role
		cookie string
		want   string
	}{
		{commonv1.Role_ROLE_ISSUER, staffsession.IssuerCookie, "https://idp.example/issuer"},
		{commonv1.Role_ROLE_VERIFIER, staffsession.VerifierCookie, "https://pair.example/auth/"},
	} {
		p := peer(c.role, configv1.Dpg_DPG_WALTID)
		p.Services[topology.AuthService(c.role)] = srv.URL
		shell, h := staffshell.Wire(staffshell.Setup{
			Role: c.role, Peers: []topology.Peer{p}, PublicURL: "https://pair.example",
			Auth: staffsession.Settings{JWKSURL: srv.URL + staffshell.JWKSPath, LoginURL: "https://pair.example/auth/"},
		})
		if shell.Pair() != p.Pair {
			t.Errorf("%s: pair %q", c.role, shell.Pair())
		}
		rec := signOut(h, c.cookie)
		if rec.Header().Get("Location") != c.want {
			t.Errorf("%s: location %q, want %q", c.role, rec.Header().Get("Location"), c.want)
		}
	}
	if len(ia.ended) != 1 || len(va.ended) != 1 {
		t.Fatalf("ended issuer %v verifier %v", ia.ended, va.ended)
	}
	// A role with no staff auth service only clears the cookie.
	_, h := staffshell.Wire(staffshell.Setup{Role: commonv1.Role_ROLE_HOLDER})
	if rec := signOut(h, staffsession.IssuerCookie); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
}
