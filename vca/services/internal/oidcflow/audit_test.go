// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
)

// TestAuditResultNamesTheFailureWithoutTheError keeps provider text
// and claim values out of the audit detail (ADR-039 decision 3).
func TestAuditResultNamesTheFailureWithoutTheError(t *testing.T) {
	ok := oidcflow.AuditResult(auditlog.Entry{Action: oidcflow.AuditLogin, Actor: "a"}, nil)
	if !ok.OK || ok.Detail != "" || ok.Actor != "a" {
		t.Fatalf("success = %+v", ok)
	}
	seen := map[string]bool{}
	for _, err := range []error{
		oidcflow.ErrStateUnknown, oidcflow.ErrProviderError, oidcflow.ErrProviderNotFound,
		oidcflow.ErrProviderDisabled, oidcflow.ErrRoleDenied, oidcflow.ErrNonce, oidcflow.ErrUpstream,
		oidcflow.ErrSessionInvalid, oidcflow.ErrRegisterUnsupported, errors.New("secret text"),
	} {
		got := oidcflow.AuditResult(auditlog.Entry{Action: oidcflow.AuditLogin}, fmt.Errorf("%w: the user secret", err))
		if got.OK || got.Detail == "" || strings.Contains(got.Detail, "secret") || strings.HasPrefix(got.Detail, "audit.") {
			t.Errorf("%v: entry = %+v", err, got)
		}
		seen[got.Detail] = true
	}
	if len(seen) != 10 {
		t.Errorf("reasons = %d, want 10 distinct", len(seen))
	}
	if revoked := oidcflow.AuditResult(auditlog.Entry{}, oidcflow.ErrSessionRevoked); revoked.Detail != oidcflow.AuditResult(auditlog.Entry{}, oidcflow.ErrSessionInvalid).Detail {
		t.Errorf("revoked = %q", revoked.Detail)
	}
}

// TestAuditAuthorizerOpensToTheAdminOnly accepts the admin token and an
// admin session, and refuses an issuer session and no token.
func TestAuditAuthorizerOpensToTheAdminOnly(t *testing.T) {
	admin := staffsessiontest.NewWithIssuer(t, "https://admin.test", oidcflow.AdminAudience, time.Now())
	srv := admin.Server(t)
	auth := oidcflow.AuditAuthorizer("admin-token", srv.URL+"/.well-known/jwks.json", oidcflow.NewCache(srv.Client(), 0))
	ctx := context.Background()
	if err := auth(ctx, bearer("admin-token")); err != nil {
		t.Errorf("admin token: %v", err)
	}
	if err := auth(ctx, bearer(admin.Token(t, "kc|root", "super-admin"))); err != nil {
		t.Errorf("admin session: %v", err)
	}
	issuer := staffsessiontest.NewWithIssuer(t, "https://admin.test", "vca-issuer", time.Now())
	for name, h := range map[string]http.Header{
		"issuer session": bearer(issuer.Token(t, "kc|ada", "issuer-admin")),
		"wrong token":    bearer("other"),
		"no token":       {},
	} {
		if err := auth(ctx, h); err == nil {
			t.Errorf("%s passed", name)
		}
	}
	none := oidcflow.AuditAuthorizer("", "", nil)
	if err := none(ctx, bearer("")); err == nil {
		t.Error("an empty configuration let a call pass")
	}
}
