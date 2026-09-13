// SPDX-License-Identifier: Apache-2.0

// Package authz reads the staff principal of a request and checks the
// role rules of a source (ADR-015 decision 3, ADR-012 decision 3).
//
// A request carries a session JWT from issuer-auth in the Authorization
// header. The JWT has a roles claim. The interceptor verifies the JWT
// against the JWKS of issuer-auth and puts a Principal on the context.
// In header mode, for a deployment where a gateway already verified the
// session, the interceptor reads the X-VCA-Roles header instead.
package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
)

// Role names as issuer-auth writes them in session tokens.
const (
	Admin    = "issuer-admin"
	Operator = "issuer-operator"
	Viewer   = "issuer-viewer"
)

// Header names of header mode.
const (
	HeaderRoles   = "X-VCA-Roles"
	HeaderSubject = "X-VCA-Subject"
	HeaderTenant  = "X-VCA-Tenant"
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
type Verifier func(token string) (Principal, error)

// claims are the fields of the session JWT the service reads.
type claims struct {
	Subject   string   `json:"sub"`
	ExpiresAt int64    `json:"exp"`
	Roles     []string `json:"roles"`
	Tenant    string   `json:"tenant"`
}

// JWKSVerifier verifies ES256 or EdDSA session tokens against set.
func JWKSVerifier(set jose.JWKS, now func() time.Time) Verifier {
	return func(token string) (Principal, error) {
		raw, _, err := jose.VerifyWithJWKS(token, set, []jose.Algorithm{jose.ES256, jose.EdDSA})
		if err != nil {
			return Principal{}, fmt.Errorf("%w: %v", ErrNoSession, err)
		}
		var c claims
		if err := json.Unmarshal(raw, &c); err != nil {
			return Principal{}, fmt.Errorf("%w: claims: %v", ErrNoSession, err)
		}
		if !now().Before(time.Unix(c.ExpiresAt, 0)) {
			return Principal{}, fmt.Errorf("%w: expired", ErrNoSession)
		}
		return Principal{Subject: c.Subject, Tenant: c.Tenant, Roles: c.Roles}, nil
	}
}

// FromHeaders reads the principal of header mode. ok is false when the
// roles header is missing.
func FromHeaders(h http.Header) (Principal, bool) {
	raw := strings.TrimSpace(h.Get(HeaderRoles))
	if raw == "" {
		return Principal{}, false
	}
	var roles []string
	for _, r := range strings.Split(raw, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, r)
		}
	}
	return Principal{Subject: h.Get(HeaderSubject), Tenant: h.Get(HeaderTenant), Roles: roles}, true
}

// Interceptor returns a Connect interceptor. With a verifier, it reads
// the bearer token. With a nil verifier, it reads the headers of header
// mode. A request with no principal gets an unauthenticated error.
func Interceptor(verify Verifier) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			p, err := principalOf(req.Header(), verify)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}
			return next(WithPrincipal(ctx, p), req)
		}
	}
}

func principalOf(h http.Header, verify Verifier) (Principal, error) {
	if verify == nil {
		p, ok := FromHeaders(h)
		if !ok {
			return Principal{}, ErrNoSession
		}
		return p, nil
	}
	auth := h.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "Bearer ") {
		return Principal{}, ErrNoSession
	}
	return verify(strings.TrimSpace(auth[7:]))
}
