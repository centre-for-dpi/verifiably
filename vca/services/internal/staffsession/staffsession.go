// SPDX-License-Identifier: Apache-2.0

// Package staffsession guards the staff pages of the issuer and the
// verifier (ADR-036 decisions 2 and 3). The auth service of the role
// signs a session JWT at login. This package checks that token against
// the key set of the auth service, checks the audience and the expiry,
// puts the session on the request context, and binds every POST to the
// session with a synchronizer token (ADR-010 decision 7).
//
// A page request without a session goes to the sign in chooser of the
// pair with return_to. Any other request without a session gets 401.
// Every side effect comes in as a function value, so a test needs no
// network and no clock.
package staffsession

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// The audience of the session JWTs of each staff role and the cookie
// that carries them. The auth services put the same values in their
// tokens (ADR-036 decision 1).
const (
	IssuerAudience   = "vca-issuer"
	IssuerCookie     = "vca_issuer_session"
	VerifierAudience = "vca-verifier"
	VerifierCookie   = "vca_verifier_session"
)

// Field is the form field that carries the synchronizer token.
const Field = oidcflow.CSRFField

// Header is the request header that carries the synchronizer token.
const Header = oidcflow.CSRFHeader

// DefaultMaxFormBytes caps the body the guard reads for the token.
const DefaultMaxFormBytes = 1 << 20

// DefaultKeysTTL is how long a fetched key set stays fresh.
const DefaultKeysTTL = 10 * time.Minute

// refetchHold is the least time between two forced key fetches, so a
// flood of bad tokens does not flood the auth service.
const refetchHold = 30 * time.Second

// The issuer role names that issuer-auth puts in a session token
// (ADR-012 decision 3). An operator issues and revokes. An admin does
// that and manages the issuer as well.
const (
	IssuerAdminRole    = "issuer-admin"
	IssuerOperatorRole = "issuer-operator"
)

// Errors the package returns.
var (
	// ErrNoSession reports a request with no usable session.
	ErrNoSession = errors.New("staffsession: the request has no session")
	// ErrCSRF reports a POST with a missing or wrong token.
	ErrCSRF = errors.New("staffsession: the form token is not valid")
)

// Realm is the session realm of a staff role: the audience of its
// session JWTs and the cookie that carries them.
type Realm struct {
	Audience string
	Cookie   string
}

// IssuerRealm returns the realm of the issuer staff.
func IssuerRealm() Realm { return Realm{Audience: IssuerAudience, Cookie: IssuerCookie} }

// VerifierRealm returns the realm of the verifier staff.
func VerifierRealm() Realm { return Realm{Audience: VerifierAudience, Cookie: VerifierCookie} }

// RealmOf returns the realm of a staff role. The holder and the admin
// have no staff realm, so ok is false for them.
func RealmOf(role commonv1.Role) (Realm, bool) {
	switch role {
	case commonv1.Role_ROLE_ISSUER:
		return IssuerRealm(), true
	case commonv1.Role_ROLE_VERIFIER:
		return VerifierRealm(), true
	default:
		return Realm{}, false
	}
}

// Session is the signed in staff member of a request.
type Session struct {
	// Subject is the pairwise subject, formed as iss|sub of the IdP.
	Subject string
	// Name is the display name, when the auth service keeps one.
	Name string
	// Roles are the role names the subject holds.
	Roles []string
	// Provider is the provider id that authenticated the subject.
	Provider string
	// Tenant is the tenant id, when the auth service keeps one.
	Tenant string
	// ID is the session id, which the synchronizer token binds to.
	ID string
	// ExpiresAt is the time the session stops working.
	ExpiresAt time.Time
	// CSRF is the synchronizer token for the next POST of this page.
	// The guard fills it on every request it lets through.
	CSRF string
}

// HasRole reports whether the session carries role.
func (s Session) HasRole(role string) bool {
	for _, r := range s.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type ctxKey struct{}

// With returns a context that carries s.
func With(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// User returns the session of ctx. ok is false when there is none.
func User(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(Session)
	return s, ok
}

// Require returns the session of ctx or an unauthenticated error.
func Require(ctx context.Context) (Session, error) {
	s, ok := User(ctx)
	if !ok {
		return Session{}, connect.NewError(connect.CodeUnauthenticated, ErrNoSession)
	}
	return s, nil
}

// HiddenField returns the hidden input that carries the synchronizer
// token of the session of ctx. A page puts it inside every form that
// posts. Without a session it returns nothing.
func HiddenField(ctx context.Context) template.HTML {
	s, ok := User(ctx)
	if !ok || s.CSRF == "" {
		return ""
	}
	return template.HTML(`<input type="hidden" name="` + Field + `" value="` + template.HTMLEscapeString(s.CSRF) + `">`) //nolint:gosec // the value is escaped
}

// Keys returns the key set of the auth service. refresh asks for a
// fresh copy, which handles a key rotation at the auth service.
type Keys func(ctx context.Context, refresh bool) (jose.JWKS, error)

// StaticKeys returns a key source that always returns set.
func StaticKeys(set jose.JWKS) Keys {
	return func(context.Context, bool) (jose.JWKS, error) { return set, nil }
}

// FileKeys reads a JWKS file once. read defaults to os.ReadFile.
func FileKeys(path string, read func(string) ([]byte, error)) (Keys, error) {
	if read == nil {
		read = os.ReadFile
	}
	raw, err := read(path)
	if err != nil {
		return nil, fmt.Errorf("staffsession: read %s: %w", path, err)
	}
	set, err := jose.ParseJWKS(raw)
	if err != nil {
		return nil, fmt.Errorf("staffsession: %s: %w", path, err)
	}
	return StaticKeys(set), nil
}

// CachedKeys returns a key source that fetches the JWKS at url with
// client and keeps it for ttl. A refresh inside the hold time after the
// last fetch returns the cached set. A nil client selects a client with
// a 10 second timeout. A zero ttl selects DefaultKeysTTL.
func CachedKeys(url string, ttl time.Duration, client *http.Client, now func() time.Time) Keys {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl <= 0 {
		ttl = DefaultKeysTTL
	}
	if now == nil {
		now = time.Now
	}
	var (
		mu      sync.Mutex
		set     jose.JWKS
		fetched time.Time
		loaded  bool
	)
	return func(ctx context.Context, refresh bool) (jose.JWKS, error) {
		mu.Lock()
		defer mu.Unlock()
		t := now()
		fresh := loaded && t.Before(fetched.Add(ttl))
		held := loaded && t.Before(fetched.Add(refetchHold))
		if fresh && (!refresh || held) {
			return set, nil
		}
		parsed, err := fetch(ctx, client, url)
		if err != nil {
			return jose.JWKS{}, err
		}
		set, fetched, loaded = parsed, t, true
		return set, nil
	}
}

// fetch reads and parses one key set.
func fetch(ctx context.Context, client *http.Client, url string) (jose.JWKS, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return jose.JWKS{}, fmt.Errorf("staffsession: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return jose.JWKS{}, fmt.Errorf("staffsession: read %s: %w", url, err)
	}
	defer func() { anyval.Discard(res.Body.Close()) }()
	raw, err := io.ReadAll(io.LimitReader(res.Body, DefaultMaxFormBytes))
	if err != nil {
		return jose.JWKS{}, fmt.Errorf("staffsession: read %s: %w", url, err)
	}
	if res.StatusCode != http.StatusOK {
		return jose.JWKS{}, fmt.Errorf("staffsession: GET %s returned %d", url, res.StatusCode)
	}
	set, err := jose.ParseJWKS(raw)
	if err != nil {
		return jose.JWKS{}, fmt.Errorf("staffsession: %s: %w", url, err)
	}
	return set, nil
}

// Options configure a Guard.
type Options struct {
	// Keys returns the key set of the auth service. Required.
	Keys Keys
	// Audience is the aud claim every session must carry. Required.
	Audience string
	// Issuer is the iss claim every session must carry. Empty accepts
	// every issuer that the key set signs for.
	Issuer string
	// Cookie is the name of the session cookie. Required.
	Cookie string
	// LoginURL is the sign in chooser of the pair. A page request with
	// no session goes there with return_to. Empty answers 401 instead.
	LoginURL string
	// CSRFKey signs the synchronizer tokens. It needs 16 bytes or more.
	// Empty makes a random key for this process.
	CSRFKey []byte
	// Public lists paths that need no session: the path itself and
	// everything below it.
	Public []string
	// MaxFormBytes caps the body the guard reads for the token of a
	// POST. Zero means DefaultMaxFormBytes.
	MaxFormBytes int64
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Guard checks the session and the synchronizer token of a request.
type Guard struct {
	opts Options
	csrf oidcflow.CSRF
}

// New returns a guard. It checks the required options.
func New(opts Options) (*Guard, error) {
	if opts.Keys == nil {
		return nil, errors.New("staffsession: a key source is required")
	}
	if opts.Audience == "" {
		return nil, errors.New("staffsession: an audience is required")
	}
	if opts.Cookie == "" {
		return nil, errors.New("staffsession: a cookie name is required")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxFormBytes <= 0 {
		opts.MaxFormBytes = DefaultMaxFormBytes
	}
	key := opts.CSRFKey
	if len(key) == 0 {
		key = make([]byte, 32)
		anyval.Must(rand.Read(key))
	}
	csrf, err := oidcflow.NewCSRF(key)
	if err != nil {
		return nil, fmt.Errorf("staffsession: %w", err)
	}
	return &Guard{opts: opts, csrf: csrf}, nil
}

// Verify turns a session JWT into a session. A token the cached key set
// does not sign for makes the guard fetch the key set once more, so a
// key rotation at the auth service needs no restart here.
func (g *Guard) Verify(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, fmt.Errorf("%w: no token", ErrNoSession)
	}
	set, err := g.opts.Keys(ctx, false)
	if err != nil {
		return Session{}, fmt.Errorf("%w: %w", ErrNoSession, err)
	}
	raw, _, err := jose.VerifyWithJWKS(token, set, jose.SigningAlgorithms)
	if err != nil {
		set, err = g.opts.Keys(ctx, true)
		if err != nil {
			return Session{}, fmt.Errorf("%w: %w", ErrNoSession, err)
		}
		if raw, _, err = jose.VerifyWithJWKS(token, set, jose.SigningAlgorithms); err != nil {
			return Session{}, fmt.Errorf("%w: %w", ErrNoSession, err)
		}
	}
	var claims oidcflow.Claims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Session{}, fmt.Errorf("%w: the claims do not parse", ErrNoSession)
	}
	return g.session(claims)
}

// session checks the claims and builds the session.
func (g *Guard) session(claims oidcflow.Claims) (Session, error) {
	if g.opts.Issuer != "" && claims.Issuer != g.opts.Issuer {
		return Session{}, fmt.Errorf("%w: another issuer signed the token", ErrNoSession)
	}
	if !hasAudience(claims.Audience, g.opts.Audience) {
		return Session{}, fmt.Errorf("%w: the token is for another audience", ErrNoSession)
	}
	if claims.Subject == "" {
		return Session{}, fmt.Errorf("%w: the token names no subject", ErrNoSession)
	}
	exp := claims.Expiry()
	if !g.opts.Now().Before(exp) {
		return Session{}, fmt.Errorf("%w: the session expired", ErrNoSession)
	}
	sid := claims.SID
	if sid == "" {
		sid = claims.ID
	}
	return Session{
		Subject: claims.Subject, Name: claims.Name, Roles: claims.Roles, Provider: claims.Provider,
		Tenant: claims.Tenant, ID: sid, ExpiresAt: exp,
	}, nil
}

// hasAudience reports whether aud lists want.
func hasAudience(aud []string, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}

// Token returns a new synchronizer token for s.
func (g *Guard) Token(s Session) string { return g.csrf.Token(bind(s)) }

// Check reports whether r carries a synchronizer token of s, in the
// header or in the form field.
func (g *Guard) Check(r *http.Request, s Session) error {
	if !g.csrf.Check(bind(s), oidcflow.CSRFFromRequest(r)) {
		return ErrCSRF
	}
	return nil
}

// bind returns the value a token binds to. A session with no id binds
// to the subject, so the token still belongs to one person.
func bind(s Session) string {
	if s.ID != "" {
		return s.ID
	}
	return s.Subject
}

// Wrap returns next behind the guard.
func (g *Guard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.public(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		s, err := g.Verify(r.Context(), oidcflow.TokenFromRequest(r, g.opts.Cookie))
		if err != nil {
			g.deny(w, r)
			return
		}
		if !safeMethod(r.Method) {
			if status, ok := g.checkForm(w, r, s); !ok {
				http.Error(w, http.StatusText(status), status)
				return
			}
		}
		s.CSRF = g.Token(s)
		next.ServeHTTP(w, r.WithContext(With(r.Context(), s)))
	})
}

// public reports whether path needs no session.
func (g *Guard) public(path string) bool {
	for _, p := range g.opts.Public {
		p = strings.TrimRight(p, "/")
		if p == "" {
			continue
		}
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// safeMethod reports whether a method changes nothing, so it needs no
// synchronizer token.
func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// checkForm reads the synchronizer token of a request that changes
// state. It returns the status to answer when the token is missing or
// wrong, or when the body is too large to read.
func (g *Guard) checkForm(w http.ResponseWriter, r *http.Request, s Session) (int, bool) {
	if r.Header.Get(Header) == "" {
		r.Body = http.MaxBytesReader(w, r.Body, g.opts.MaxFormBytes)
		if err := parseForm(r, g.opts.MaxFormBytes); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				return http.StatusRequestEntityTooLarge, false
			}
			return http.StatusBadRequest, false
		}
	}
	if err := g.Check(r, s); err != nil {
		return http.StatusForbidden, false
	}
	return 0, true
}

// parseForm parses a form body of either encoding. Any other body is
// left alone, since it cannot carry the field.
func parseForm(r *http.Request, maxMemory int64) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil //nolint:nilerr // no media type means no form to read
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		return r.ParseForm()
	case "multipart/form-data":
		return r.ParseMultipartForm(maxMemory)
	}
	return nil
}

// deny answers a request without a session: a page request goes to the
// sign in chooser with return_to, an htmx request gets the redirect in
// HX-Redirect with 401, and any other request gets 401.
func (g *Guard) deny(w http.ResponseWriter, r *http.Request) {
	target := g.loginURL(r)
	if target == "" || !safeMethod(r.Method) {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if components.IsHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// loginURL returns the chooser address with return_to set to the
// request, or "" when the guard has no login URL.
func (g *Guard) loginURL(r *http.Request) string {
	if g.opts.LoginURL == "" {
		return ""
	}
	back := r.URL.RequestURI()
	if !oidcflow.ValidReturnTo(back) {
		back = "/"
	}
	sep := "?"
	if strings.Contains(g.opts.LoginURL, "?") {
		sep = "&"
	}
	return g.opts.LoginURL + sep + "return_to=" + url.QueryEscape(back)
}
