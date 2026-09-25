// SPDX-License-Identifier: Apache-2.0

package oidcflow_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
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
