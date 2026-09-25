// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"errors"

	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
)

// The audit actions of the sign in services (ADR-039 decision 1). The
// three auth services write the same names, so one filter finds every
// sign in of the deployment.
const (
	// AuditLogin is a sign in, which succeeds or fails.
	AuditLogin = "auth.Login"
	// AuditRegister is a sign in whose first step was the register
	// action of the provider.
	AuditRegister = "auth.Register"
	// AuditLogout is a sign out.
	AuditLogout = "auth.Logout"
)

// AuditResult sets the outcome of a sign in entry from err. A failure
// gets a fixed reason from the message catalogue and never the text of
// err, which can hold provider text or a claim value (ADR-039 decision 3).
func AuditResult(e auditlog.Entry, err error) auditlog.Entry {
	e.OK = err == nil
	if err != nil {
		e.Detail = msg.T(failureKey(err))
	}
	return e
}

// failureKey returns the catalogue key of the reason of a failure.
func failureKey(err error) string {
	switch {
	case errors.Is(err, ErrStateUnknown):
		return "audit.reason.state"
	case errors.Is(err, ErrProviderError):
		return "audit.reason.provider"
	case errors.Is(err, ErrProviderNotFound):
		return "audit.reason.unknown_provider"
	case errors.Is(err, ErrProviderDisabled):
		return "audit.reason.disabled"
	case errors.Is(err, ErrRoleDenied):
		return "audit.reason.role"
	case errors.Is(err, ErrNonce):
		return "audit.reason.nonce"
	case errors.Is(err, ErrUpstream):
		return "audit.reason.upstream"
	case errors.Is(err, ErrSessionInvalid), errors.Is(err, ErrSessionRevoked):
		return "audit.reason.session"
	case errors.Is(err, ErrRegisterUnsupported):
		return "audit.reason.register"
	default:
		return "audit.reason.other"
	}
}
