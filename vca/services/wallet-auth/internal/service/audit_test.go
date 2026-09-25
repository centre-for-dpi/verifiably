// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	auditv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/audit/v1/auditv1connect"
	walletauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
)

// auditQuery reads every event of the service with a bearer token.
func (f *fixture) auditQuery(t *testing.T, token string) ([]*auditv1.AuditEvent, error) {
	t.Helper()
	client := auditv1connect.NewAuditServiceClient(f.srv.Client(), f.srv.URL, withBearer(token))
	res, err := client.Query(context.Background(), connect.NewRequest(&auditv1.QueryRequest{}))
	if err != nil {
		return nil, err
	}
	return res.Msg.GetEvents(), nil
}

// TestSignInWritesAuditEvent covers the holder events: the first sign
// in makes the wallet and counts as a registration, a later sign in, a
// failed sign in, and a sign out. The actor is the salted subject hash,
// never the subject of the provider.
func TestSignInWritesAuditEvent(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	first, _ := f.login(t)
	second, _ := f.login(t)
	start, err := f.client.LoginStart(ctx, connect.NewRequest(&walletauthv1.LoginStartRequest{ProviderId: "esignet"}))
	if err != nil {
		t.Fatalf("LoginStart: %v", err)
	}
	if _, cerr := f.client.LoginCallback(ctx, connect.NewRequest(&walletauthv1.LoginCallbackRequest{State: start.Msg.GetState(), Error: "access_denied"})); cerr == nil {
		t.Fatal("the provider error passed")
	}
	if _, lerr := f.client.Logout(ctx, connect.NewRequest(&walletauthv1.LogoutRequest{SessionToken: second.SessionToken})); lerr != nil {
		t.Fatalf("Logout: %v", lerr)
	}
	holder := first.Claims.Subject
	if holder == "" || strings.Contains(holder, "|") || holder != second.Claims.Subject {
		t.Fatalf("subjects %q %q", holder, second.Claims.Subject)
	}
	want := []string{
		"auth.Logout|" + holder + "|esignet|OUTCOME_SUCCESS|",
		"auth.Login||esignet|OUTCOME_FAILURE|" + msg.T("audit.reason.provider"),
		"auth.Login|" + holder + "|esignet|OUTCOME_SUCCESS|",
		"auth.Register|" + holder + "|esignet|OUTCOME_SUCCESS|",
	}
	events, err := f.auditQuery(t, f.adminSigner.Token(t, "kc|root", "super-admin"))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var got []string
	for _, e := range events {
		got = append(got, strings.Join([]string{e.GetAction(), e.GetActor(), e.GetTarget(), e.GetOutcome().String(), e.GetDetail()}, "|"))
		if e.GetSourceService() != "wallet-auth" || e.GetRequestId() == "" {
			t.Errorf("event %+v", e)
		}
		if strings.Contains(e.GetActor(), f.idp.Issuer()) {
			t.Errorf("the actor names the provider subject: %q", e.GetActor())
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestAuditQueryNeedsAdmin opens the audit store to the admin session
// and the admin service token only, never to a holder session.
func TestAuditQueryNeedsAdmin(t *testing.T) {
	f := newFixture(t)
	holder, _ := f.login(t)
	for name, token := range map[string]string{
		"admin session":       f.adminSigner.Token(t, "kc|root", "super-admin"),
		"admin service token": "admin-token",
	} {
		if _, err := f.auditQuery(t, token); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, token := range map[string]string{
		"holder session":    holder.SessionToken,
		"another admin key": staffsessiontest.NewWithIssuer(t, "https://admin.test", oidcflow.AdminAudience, time.Now()).Token(t, "kc|eve", "super-admin"),
		"no token":          "",
	} {
		if _, err := f.auditQuery(t, token); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
}
