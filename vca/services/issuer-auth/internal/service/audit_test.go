// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	issuerauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
)

// auditEvents reads every event of the service with the admin session.
func (f *fixture) auditEvents(t *testing.T) []*auditv1.AuditEvent {
	t.Helper()
	client := auditv1connect.NewAuditServiceClient(f.srv.Client(), f.srv.URL, withBearer(f.adminSigner.Token(t, "kc|root", "super-admin")))
	res, err := client.Query(context.Background(), connect.NewRequest(&auditv1.QueryRequest{}))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	return res.Msg.GetEvents()
}

// signIn runs the browser flow and returns the session cookie value.
func (f *fixture) signIn(t *testing.T) string {
	t.Helper()
	res := f.login(t, "")
	if cerr := res.Body.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	for _, c := range res.Cookies() {
		if c.Name == f.cfg.CookieName {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

// TestSignInWritesAuditEvent covers the four events of ADR-039 for
// this service: sign in, failed sign in, register, and sign out.
func TestSignInWritesAuditEvent(t *testing.T) {
	f := newFixture(t)
	f.idp.PromptValuesSupported = []string{"create"}
	ctx := context.Background()
	session := f.signIn(t)
	start, err := f.client.LoginStart(ctx, connect.NewRequest(&issuerauthv1.LoginStartRequest{ProviderId: "idp"}))
	if err != nil {
		t.Fatalf("LoginStart: %v", err)
	}
	if _, cerr := f.client.LoginCallback(ctx, connect.NewRequest(&issuerauthv1.LoginCallbackRequest{State: start.Msg.GetState(), Error: "access_denied"})); cerr == nil {
		t.Fatal("the provider error passed")
	}
	register, err := f.svc.Register(ctx, "idp", "")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	loc, err := f.idp.Authorize(register)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := f.client.LoginCallback(ctx, connect.NewRequest(&issuerauthv1.LoginCallbackRequest{State: u.Query().Get("state"), Code: u.Query().Get("code")})); cerr != nil {
		t.Fatalf("register callback: %v", cerr)
	}
	if _, lerr := f.client.Logout(ctx, connect.NewRequest(&issuerauthv1.LogoutRequest{SessionToken: session})); lerr != nil {
		t.Fatalf("Logout: %v", lerr)
	}
	subject := f.idp.Issuer() + "|user-1"
	want := []string{
		"auth.Logout|" + subject + "|idp|OUTCOME_SUCCESS|",
		"auth.Register|" + subject + "|idp|OUTCOME_SUCCESS|",
		"auth.Login||idp|OUTCOME_FAILURE|" + msg.T("audit.reason.provider"),
		"auth.Login|" + subject + "|idp|OUTCOME_SUCCESS|",
	}
	events := f.auditEvents(t)
	var got []string
	for _, e := range events {
		got = append(got, strings.Join([]string{e.GetAction(), e.GetActor(), e.GetTarget(), e.GetOutcome().String(), e.GetDetail()}, "|"))
		if e.GetSourceService() != "issuer-auth" || e.GetRequestId() == "" || e.GetTime() == nil {
			t.Errorf("event %+v", e)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestAuditQueryNeedsAdmin opens the audit store to the admin session
// and the admin service token only. A session of this service, even
// with the issuer-admin role, is refused.
func TestAuditQueryNeedsAdmin(t *testing.T) {
	f := newFixture(t)
	f.idp.Claims["realm_access"] = map[string]any{"roles": []any{"issuer-admin"}}
	ctx := context.Background()
	staff := f.signIn(t)
	// The staff session is an issuer admin: it opens the provider RPCs.
	providers := adminv1connect.NewAdminServiceClient(f.srv.Client(), f.srv.URL, withBearer(staff))
	if _, err := providers.ListAuthProviders(ctx, connect.NewRequest(&adminv1.ListAuthProvidersRequest{})); err != nil {
		t.Fatalf("the issuer admin session: %v", err)
	}
	query := func(token string) error {
		client := auditv1connect.NewAuditServiceClient(f.srv.Client(), f.srv.URL, withBearer(token))
		_, err := client.Query(ctx, connect.NewRequest(&auditv1.QueryRequest{}))
		return err
	}
	for name, token := range map[string]string{
		"admin session":       f.adminSigner.Token(t, "kc|root", "super-admin"),
		"admin service token": "admin-token",
	} {
		if err := query(token); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, token := range map[string]string{
		"issuer admin session": staff,
		"another admin key":    staffsessiontest.NewWithIssuer(t, "https://admin.test", oidcflow.AdminAudience, time.Now()).Token(t, "kc|eve", "super-admin"),
		"no token":             "",
	} {
		if err := query(token); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
}
