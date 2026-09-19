// SPDX-License-Identifier: Apache-2.0

// Package session reads the citizen session of a request. The wallet
// authentication service issues the session JWT (ADR-020 decision 2).
// This package checks the signature against the key set of that
// service, checks the expiry time, and puts a Citizen on the context.
//
// The package offers three entry points:
//
//   - Interceptor guards the Connect RPCs.
//   - Middleware guards the HTML pages.
//   - CSRF guards every POST with a synchronizer token.
//
// Every side effect comes in as a function value, so a test needs no
// network and no clock.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// CookieName carries the session JWT in the browser.
const CookieName = "vca_wallet_session"

// Errors the package returns.
var (
	// ErrNoSession reports a request with no usable session.
	ErrNoSession = errors.New("session: the request has no session")
	// ErrCSRF reports a POST with a missing or wrong token.
	ErrCSRF = errors.New("session: the form token is not valid")
)

// Citizen is the logged in citizen of a request.
type Citizen struct {
	// Subject is the pairwise subject, formed as iss|sub of the IdP.
	Subject string
	// WalletID is the wallet id at the holder backend.
	WalletID string
	// HolderDID is the holder DID, when one exists.
	HolderDID string
	// HasHolderKey says whether the browser registered a holder key.
	HasHolderKey bool
	// SessionID is the session id, which the CSRF token binds to.
	SessionID string
	// ExpiresAt is the time the session stops working.
	ExpiresAt time.Time
}

// WalletKey returns the store key of the wallet of the citizen. The
// browser storage of ADR-021 decision 4 keys its blobs by this value.
func (c Citizen) WalletKey() string {
	if c.WalletID != "" {
		return c.WalletID
	}
	return keySafe(c.Subject)
}

// keySafe maps a subject to a key segment the store accepts.
func keySafe(subject string) string {
	var b strings.Builder
	for _, r := range subject {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('.')
		}
	}
	return b.String()
}

type ctxKey struct{}

// With returns a context that carries c.
func With(ctx context.Context, c Citizen) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// From returns the citizen of ctx. ok is false when there is none.
func From(ctx context.Context) (Citizen, bool) {
	c, ok := ctx.Value(ctxKey{}).(Citizen)
	return c, ok
}

// Require returns the citizen of ctx or an unauthenticated error.
func Require(ctx context.Context) (Citizen, error) {
	c, ok := From(ctx)
	if !ok {
		return Citizen{}, connect.NewError(connect.CodeUnauthenticated, ErrNoSession)
	}
	return c, nil
}

// Verifier turns a session JWT into a citizen.
type Verifier func(token string) (Citizen, error)

// Keys returns the key set of the wallet authentication service.
type Keys func(ctx context.Context) (jose.JWKS, error)

// Options configure NewVerifier.
type Options struct {
	// Keys returns the key set. It is required.
	Keys Keys
	// Issuer is the issuer the token must name. Empty accepts every
	// issuer.
	Issuer string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// NewVerifier returns a verifier that checks ES256 and EdDSA tokens.
func NewVerifier(opts Options) (Verifier, error) {
	if opts.Keys == nil {
		return nil, errors.New("session: a key source is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return func(token string) (Citizen, error) {
		set, err := opts.Keys(context.Background())
		if err != nil {
			return Citizen{}, fmt.Errorf("%w: %w", ErrNoSession, err)
		}
		raw, _, err := jose.VerifyWithJWKS(token, set, []jose.Algorithm{jose.ES256, jose.EdDSA})
		if err != nil {
			return Citizen{}, fmt.Errorf("%w: %w", ErrNoSession, err)
		}
		var claims oidcflow.Claims
		if err := json.Unmarshal(raw, &claims); err != nil {
			return Citizen{}, fmt.Errorf("%w: the claims do not parse", ErrNoSession)
		}
		if opts.Issuer != "" && claims.Issuer != opts.Issuer {
			return Citizen{}, fmt.Errorf("%w: another issuer signed the token", ErrNoSession)
		}
		if claims.Subject == "" {
			return Citizen{}, fmt.Errorf("%w: the token names no subject", ErrNoSession)
		}
		exp := time.Unix(claims.ExpiresAt, 0)
		if !opts.Now().Before(exp) {
			return Citizen{}, fmt.Errorf("%w: the session expired", ErrNoSession)
		}
		sid := claims.SID
		if sid == "" {
			sid = claims.ID
		}
		return Citizen{
			Subject:      claims.Subject,
			WalletID:     claims.WalletID,
			HolderDID:    claims.HolderDID,
			HasHolderKey: claims.HasHolderKey,
			SessionID:    sid,
			ExpiresAt:    exp,
		}, nil
	}, nil
}

// CachedKeys returns a key source that fetches the JWKS of url and
// keeps it for ttl. The fetch function does the HTTP GET.
func CachedKeys(url string, ttl time.Duration, fetch func(context.Context, string) ([]byte, error),
	now func() time.Time) Keys {
	if now == nil {
		now = time.Now
	}
	var (
		mu      sync.Mutex
		set     jose.JWKS
		expires time.Time
	)
	return func(ctx context.Context) (jose.JWKS, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(set.Keys) > 0 && now().Before(expires) {
			return set, nil
		}
		raw, err := fetch(ctx, url)
		if err != nil {
			return jose.JWKS{}, fmt.Errorf("session: read %s: %w", url, err)
		}
		parsed, err := jose.ParseJWKS(raw)
		if err != nil {
			return jose.JWKS{}, fmt.Errorf("session: %s: %w", url, err)
		}
		set, expires = parsed, now().Add(ttl)
		return set, nil
	}
}

// StaticKeys returns a key source that always returns set.
func StaticKeys(set jose.JWKS) Keys {
	return func(context.Context) (jose.JWKS, error) { return set, nil }
}

// TokenOf reads the session JWT of a request. It reads the
// Authorization header first and the session cookie second.
func TokenOf(h http.Header, cookie func(string) (*http.Cookie, error)) string {
	auth := h.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if cookie == nil {
		return ""
	}
	c, err := cookie(CookieName)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}

// Interceptor returns a Connect interceptor that needs a session.
func Interceptor(verify Verifier) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			if verify == nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, ErrNoSession)
			}
			token := TokenOf(req.Header(), nil)
			if token == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, ErrNoSession)
			}
			citizen, err := verify(token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}
			return next(With(ctx, citizen), req)
		}
	}
}

// Middleware returns an HTTP middleware that needs a session. A request
// with no session gets the login page, which loginPath names.
func Middleware(verify Verifier, loginPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ""
			if verify != nil {
				token = TokenOf(r.Header, r.Cookie)
			}
			if token == "" {
				redirect(w, r, loginPath)
				return
			}
			citizen, err := verify(token)
			if err != nil {
				redirect(w, r, loginPath)
				return
			}
			next.ServeHTTP(w, r.WithContext(With(r.Context(), citizen)))
		})
	}
}

// redirect sends the browser to the login page, or answers 401 when
// the deployment has no login page.
func redirect(w http.ResponseWriter, r *http.Request, loginPath string) {
	if loginPath == "" {
		http.Error(w, "log in first", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, loginPath, http.StatusSeeOther)
}

// Guard is the CSRF synchronizer token of the POST pages.
type Guard struct {
	csrf oidcflow.CSRF
}

// NewGuard returns a guard for key. The key needs 16 bytes or more.
func NewGuard(key []byte) (Guard, error) {
	c, err := oidcflow.NewCSRF(key)
	if err != nil {
		return Guard{}, fmt.Errorf("session: %w", err)
	}
	return Guard{csrf: c}, nil
}

// Token returns a new form token for the citizen.
func (g Guard) Token(c Citizen) string { return g.csrf.Token(g.bind(c)) }

// Check reports whether the request carries a token of the citizen.
func (g Guard) Check(r *http.Request, c Citizen) error {
	if !g.csrf.Check(g.bind(c), oidcflow.CSRFFromRequest(r)) {
		return ErrCSRF
	}
	return nil
}

// Field is the name of the hidden form field of the token.
const Field = oidcflow.CSRFField

// bind returns the value the token binds to. A session with no id binds
// to the subject, so the token still belongs to one citizen.
func (g Guard) bind(c Citizen) string {
	if c.SessionID != "" {
		return c.SessionID
	}
	return c.Subject
}
