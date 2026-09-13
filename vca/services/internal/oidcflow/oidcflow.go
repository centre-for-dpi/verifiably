// SPDX-License-Identifier: Apache-2.0

// Package oidcflow holds the parts of an OpenID Connect login that the
// issuer-auth and wallet-auth services share: provider records, discovery
// and JWKS caches, the authorization code flow with PKCE, session JWTs,
// a deny list, CSRF tokens, and plain HTTP login handlers.
//
// The pure parts (PKCE, discovery parsing, token checks) live in
// core/oidc and core/jose. This package adds the HTTP calls and the
// state that a service keeps between the start and the end of a login.
package oidcflow

import (
	"errors"
	"fmt"

	"connectrpc.com/connect"
)

// Errors that the flow and the handlers return.
var (
	// ErrProviderNotFound reports an unknown provider id.
	ErrProviderNotFound = errors.New("oidcflow: provider not found")
	// ErrProviderDisabled reports a provider that does not accept logins.
	ErrProviderDisabled = errors.New("oidcflow: provider is disabled")
	// ErrInvalidProvider reports a provider record that fails validation.
	ErrInvalidProvider = errors.New("oidcflow: invalid provider")
	// ErrStateUnknown reports a callback state with no pending login.
	ErrStateUnknown = errors.New("oidcflow: unknown or expired login state")
	// ErrProviderError reports an error code that the provider returned.
	ErrProviderError = errors.New("oidcflow: provider returned an error")
	// ErrNonce reports an ID token whose nonce does not match the login.
	ErrNonce = errors.New("oidcflow: nonce mismatch")
	// ErrSessionInvalid reports a session token that fails verification.
	ErrSessionInvalid = errors.New("oidcflow: session token is not valid")
	// ErrSessionRevoked reports a session that Logout ended.
	ErrSessionRevoked = errors.New("oidcflow: session was revoked")
	// ErrReturnTo reports a return_to value that is not a relative path.
	ErrReturnTo = errors.New("oidcflow: return_to must be a relative path")
	// ErrRoleDenied reports a login whose claims map to no role.
	ErrRoleDenied = errors.New("oidcflow: no role for this subject")
	// ErrUnauthorized reports a request without a valid credential.
	ErrUnauthorized = errors.New("oidcflow: unauthorized")
	// ErrForbidden reports a request whose credential lacks the role.
	ErrForbidden = errors.New("oidcflow: forbidden")
	// ErrUpstream reports that the provider could not be reached.
	ErrUpstream = errors.New("oidcflow: provider unreachable")
	// ErrCSRF reports a POST without a valid synchronizer token.
	ErrCSRF = errors.New("oidcflow: csrf token missing or not valid")
	// ErrSecret reports a client secret reference that cannot be read.
	ErrSecret = errors.New("oidcflow: client secret not available")
)

// ConnectError maps an error of this package to a Connect error.
// Errors that the package does not know become CodeInternal.
func ConnectError(err error) *connect.Error {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return ce
	}
	return connect.NewError(connectCode(err), err)
}

func connectCode(err error) connect.Code {
	switch {
	case errors.Is(err, ErrProviderNotFound):
		return connect.CodeNotFound
	case errors.Is(err, ErrProviderDisabled), errors.Is(err, ErrRoleDenied):
		return connect.CodeFailedPrecondition
	case errors.Is(err, ErrInvalidProvider), errors.Is(err, ErrReturnTo), errors.Is(err, ErrStateUnknown), errors.Is(err, ErrCSRF):
		return connect.CodeInvalidArgument
	case errors.Is(err, ErrSessionInvalid), errors.Is(err, ErrSessionRevoked), errors.Is(err, ErrNonce), errors.Is(err, ErrUnauthorized):
		return connect.CodeUnauthenticated
	case errors.Is(err, ErrForbidden):
		return connect.CodePermissionDenied
	case errors.Is(err, ErrUpstream), errors.Is(err, ErrProviderError):
		return connect.CodeUnavailable
	}
	return connect.CodeInternal
}

// HTTPStatus maps an error of this package to an HTTP status code.
func HTTPStatus(err error) int {
	switch connectCode(err) {
	case connect.CodeNotFound:
		return 404
	case connect.CodeInvalidArgument, connect.CodeFailedPrecondition:
		return 400
	case connect.CodeUnauthenticated:
		return 401
	case connect.CodePermissionDenied:
		return 403
	case connect.CodeUnavailable:
		return 502
	}
	return 500
}

// wrap adds a prefix to err and keeps the sentinel for errors.Is.
func wrap(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, args...))
}
