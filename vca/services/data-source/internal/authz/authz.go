// SPDX-License-Identifier: Apache-2.0

// Package authz reads the staff principal of a request and checks the
// role rules of a source (ADR-015 decision 3, ADR-012 decision 3).
//
// A request carries a session JWT from issuer-auth in the Authorization
// header. The JWT has a roles claim. The interceptor checks the JWT with
// the staff guard of the service, against the key set of issuer-auth,
// and puts a Principal on the context. The pages of the service put the
// principal of the page session there too.
package authz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
)

// Role names as issuer-auth writes them in session tokens.
const (
	Admin    = staffsession.IssuerAdminRole
	Operator = staffsession.IssuerOperatorRole
	Viewer   = "issuer-viewer"
)

// Errors the package returns.
var (
	ErrNoSession = errors.New("authz: the request has no session")
	ErrDenied    = errors.New("authz: the session lacks the role")
)

// Principal is the caller of a request.
type Principal struct {
	Subject string
	Tenant  string
	Roles   []string
}

// HasRole reports whether p holds role.
func (p Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Allowed reports whether p may do an action that rule permits.
// An admin may do everything. Another principal needs one of the roles
// in rule. An empty rule permits only admins.
func (p Principal) Allowed(rule []string) bool {
	if p.HasRole(Admin) {
		return true
	}
	for _, r := range rule {
		if p.HasRole(r) {
			return true
		}
	}
	return false
}

type ctxKey struct{}

// WithPrincipal returns a context that carries p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// From returns the principal of ctx. ok is false when there is none.
func From(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Require returns the principal of ctx or a Connect unauthenticated error.
func Require(ctx context.Context) (Principal, error) {
	p, ok := From(ctx)
	if !ok {
		return Principal{}, connect.NewError(connect.CodeUnauthenticated, ErrNoSession)
	}
	return p, nil
}

// Verifier turns a bearer token into a principal.
type Verifier func(ctx context.Context, token string) (Principal, error)

// FromSession returns the principal of a staff session.
func FromSession(s staffsession.Session) Principal {
	return Principal{Subject: s.Subject, Tenant: s.Tenant, Roles: s.Roles}
}

// SessionVerifier checks a session of issuer-auth with the verify call of
// the staff guard of the service, so the RPCs and the pages trust one key
// set (ADR-036 decision 3). No header can stand in for the session.
func SessionVerifier(verify func(ctx context.Context, token string) (staffsession.Session, error)) Verifier {
	return func(ctx context.Context, token string) (Principal, error) {
		s, err := verify(ctx, token)
		if err != nil {
			return Principal{}, fmt.Errorf("%w: %w", ErrNoSession, err)
		}
		return FromSession(s), nil
	}
}

// Interceptor returns a Connect interceptor that reads the bearer token
// of a request, checks it with verify, and puts the principal on the
// context. A request with no valid session gets an unauthenticated error.
func Interceptor(verify Verifier) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			p, err := principalOf(ctx, req.Header(), verify)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}
			return next(WithPrincipal(ctx, p), req)
		}
	}
}

func principalOf(ctx context.Context, h http.Header, verify Verifier) (Principal, error) {
	auth := h.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "Bearer ") {
		return Principal{}, ErrNoSession
	}
	return verify(ctx, strings.TrimSpace(auth[7:]))
}
