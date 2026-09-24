// SPDX-License-Identifier: Apache-2.0

// Package login authenticates super admins with OpenID Connect only
// (ADR-010 decisions 1, 2, 4, 6, and 7). The package has no password
// path at all.
//
// The login runs the authorization code flow with PKCE of the shared
// oidcflow library. The service issues an ES256 session JWT and
// publishes its public key, so other services can check a super admin
// call without a session table.
//
// The first super admin is bound by a one time bootstrap token. The
// token is consumed on the first OpenID Connect login and binds the iss
// and sub claims to the super admin role.
package login

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/oidc"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/audit"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// Roles of an admin session.
const (
	// RoleAdmin is the deployment role of the admin service (ADR-007).
	RoleAdmin = "admin"
	// RoleSuperAdmin marks a bound super admin (ADR-010 decision 4).
	RoleSuperAdmin = "super-admin"
)

// Audience is the aud claim of every admin session JWT.
const Audience = "vca-admin"

// BootstrapField is the query field that carries the bootstrap token on
// a browser login and the form field on a CLI login.
const BootstrapField = "bootstrap_token"

// Errors of the package.
var (
	// ErrNotAdmin reports a subject that holds no super admin role.
	ErrNotAdmin = errors.New("login: the subject is not a super admin")
	// ErrNoIDToken reports a request without an ID token.
	ErrNoIDToken = errors.New("login: an id token is required")
)

// Deps are the collaborators of the service.
type Deps struct {
	// Cfg is the service configuration.
	Cfg config.Config
	// Flow runs the authorization code flow.
	Flow *oidcflow.Flow
	// Cache reads provider metadata and key sets.
	Cache *oidcflow.Cache
	// Providers holds the registered providers.
	Providers *oidcflow.Registry
	// Pending keeps started logins.
	Pending oidcflow.PendingStore
	// Signer issues and checks session JWTs.
	Signer *oidcflow.Signer
	// CSRF makes and checks synchronizer tokens.
	CSRF oidcflow.CSRF
	// Records holds the admin bindings and the bootstrap token.
	Records *records.Store
	// Audit receives one record for each login and each logout.
	Audit *audit.Log
	// Client calls the provider endpoints of the device grant.
	Client *http.Client
	// Now returns the current time.
	Now func() time.Time
}

// Service runs the admin logins.
type Service struct {
	d Deps
	// mu guards the maps below.
	mu sync.Mutex
	// bootstraps holds the bootstrap token of a started login by state.
	bootstraps map[string]pendingToken
	// loopbacks holds the CLI port of a started login by state.
	loopbacks map[string]pendingLoopback
	// codes holds the one time codes the loopback helper issues.
	codes map[string]issuedCode
	// hints holds the provider ID token of a session, for logout.
	hints map[string]issuedHint
}

type pendingToken struct {
	token   string
	expires time.Time
}

type pendingLoopback struct {
	port    string
	expires time.Time
}

type issuedCode struct {
	token   string
	claims  oidcflow.Claims
	expires time.Time
}

type issuedHint struct {
	idToken string
	expires time.Time
}

// New returns a service. It fills the optional dependencies.
func New(d Deps) (*Service, error) {
	if d.Flow == nil || d.Providers == nil || d.Signer == nil || d.Records == nil {
		return nil, errors.New("login: the flow, the providers, the signer, and the records are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Pending == nil {
		d.Pending = oidcflow.NewMemoryPending(d.Now)
	}
	if d.Cache == nil {
		d.Cache = oidcflow.NewCache(d.Client, 0)
	}
	if d.Client == nil {
		d.Client = &http.Client{Timeout: d.Cfg.Timeout}
	}
	return &Service{
		d:          d,
		bootstraps: map[string]pendingToken{},
		loopbacks:  map[string]pendingLoopback{},
		codes:      map[string]issuedCode{},
		hints:      map[string]issuedHint{},
	}, nil
}

// Signer returns the session signer. The app mounts its JWKS handler.
func (s *Service) Signer() *oidcflow.Signer { return s.d.Signer }

// CSRF returns the synchronizer token maker (ADR-010 decision 7).
func (s *Service) CSRF() oidcflow.CSRF { return s.d.CSRF }

// Providers returns the provider registry.
func (s *Service) Providers() *oidcflow.Registry { return s.d.Providers }

// Flow returns the login flow, which reads provider metadata.
func (s *Service) Flow() *oidcflow.Flow { return s.d.Flow }

// Handlers returns the shared login endpoints. The cookie carries
// SameSite=Lax and HttpOnly.
func (s *Service) Handlers() oidcflow.Handlers {
	return oidcflow.Handlers{
		Logins:         s,
		Cookie:         oidcflow.Cookie{Name: s.d.Cfg.CookieName, Secure: !s.d.Cfg.InsecureCookie},
		CSRF:           s.d.CSRF,
		LogoutRedirect: s.d.Cfg.LogoutRedirect,
	}
}

// Cookie returns the session cookie description.
func (s *Service) Cookie() oidcflow.Cookie {
	return oidcflow.Cookie{Name: s.d.Cfg.CookieName, Secure: !s.d.Cfg.InsecureCookie}
}

// Start implements oidcflow.Logins. It starts a browser login. A
// bootstrap token in the query binds the first super admin at the end
// of the login.
func (s *Service) Start(ctx context.Context, providerID, returnTo string) (string, error) {
	_, u, err := s.begin(ctx, providerID, returnTo, "", "", false)
	return u, err
}

// Register implements signin.Registrar (ADR-035 decision 3). It starts
// a registration at the provider; the callback finishes it like a
// login. The first admin registers with a bootstrap token through
// RegisterStart instead (ADR-035 decision 6).
func (s *Service) Register(ctx context.Context, providerID, returnTo string) (string, error) {
	_, u, err := s.begin(ctx, providerID, returnTo, "", "", true)
	return u, err
}

// begin starts a login, or a registration when register is set, and
// remembers the bootstrap token and the CLI port of the state.
func (s *Service) begin(ctx context.Context, providerID, returnTo, bootstrapToken, port string, register bool) (oidcflow.Pending, string, error) {
	p, err := s.provider(ctx, providerID)
	if err != nil {
		return oidcflow.Pending{}, "", err
	}
	start := s.d.Flow.Begin
	if register {
		start = s.d.Flow.BeginRegister
	}
	pend, u, err := start(ctx, p, s.d.Cfg.RedirectURI, returnTo)
	if err != nil {
		return oidcflow.Pending{}, "", err
	}
	if err := s.d.Pending.Put(pend); err != nil {
		return oidcflow.Pending{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if bootstrapToken != "" {
		s.bootstraps[pend.State] = pendingToken{token: bootstrapToken, expires: pend.ExpiresAt}
	}
	if port != "" {
		s.loopbacks[pend.State] = pendingLoopback{port: port, expires: pend.ExpiresAt}
	}
	return pend, u, nil
}

// provider returns one provider, or the only enabled provider when the
// caller names none.
func (s *Service) provider(_ context.Context, providerID string) (oidcflow.Provider, error) {
	if providerID != "" {
		return s.d.Providers.Get(providerID)
	}
	enabled := s.d.Providers.Enabled()
	if len(enabled) == 1 {
		return enabled[0], nil
	}
	return oidcflow.Provider{}, oidcflow.ErrProviderNotFound
}

// Complete implements oidcflow.Logins. It ends the code flow, applies
// the bootstrap token when the login carried one, and issues the
// session JWT.
func (s *Service) Complete(ctx context.Context, state, code, providerError string) (string, oidcflow.Claims, string, error) {
	pend, ok := s.d.Pending.Take(state)
	if !ok {
		return "", oidcflow.Claims{}, "", oidcflow.ErrStateUnknown
	}
	bootstrapToken := s.takeBootstrap(state)
	if providerError != "" {
		return "", oidcflow.Claims{}, "", oidcflow.ErrProviderError
	}
	p, err := s.d.Providers.Get(pend.ProviderID)
	if err != nil {
		return "", oidcflow.Claims{}, "", err
	}
	res, err := s.d.Flow.Complete(ctx, p, pend, code)
	if err != nil {
		return "", oidcflow.Claims{}, "", err
	}
	token, claims, err := s.session(ctx, p, res.Issuer, res.Subject, name(res.Claims), bootstrapToken, res.IDToken)
	if err != nil {
		return "", oidcflow.Claims{}, "", err
	}
	return token, claims, pend.ReturnTo, nil
}

// session binds or checks the super admin role and signs the session.
func (s *Service) session(ctx context.Context, p oidcflow.Provider, issuer, subject, displayName, bootstrapToken, idToken string) (string, oidcflow.Claims, error) {
	if issuer == "" || subject == "" {
		return "", oidcflow.Claims{}, oidcflow.ErrSessionInvalid
	}
	if bootstrapToken != "" && !s.d.Records.IsAdmin(ctx, issuer, subject) {
		if err := s.bind(ctx, issuer, subject, bootstrapToken); err != nil {
			return "", oidcflow.Claims{}, err
		}
	}
	if !s.d.Records.IsAdmin(ctx, issuer, subject) {
		s.log(ctx, oidcflow.PairwiseSubject(issuer, subject), "admin.Login", "", false)
		return "", oidcflow.Claims{}, ErrNotAdmin
	}
	token, claims, err := s.d.Signer.Issue(oidcflow.Claims{
		Subject:  oidcflow.PairwiseSubject(issuer, subject),
		Roles:    []string{RoleAdmin, RoleSuperAdmin},
		Provider: p.ID,
		Name:     displayName,
	})
	if err != nil {
		return "", oidcflow.Claims{}, err
	}
	s.putHint(claims.SID, idToken, claims.Expiry())
	s.log(ctx, claims.Subject, "admin.Login", p.ID, true)
	return token, claims, nil
}

// Bind consumes the bootstrap token and binds one subject to the super
// admin role (ADR-010 decision 4).
func (s *Service) bind(ctx context.Context, issuer, subject, bootstrapToken string) error {
	if err := s.d.Records.ConsumeBootstrap(ctx, bootstrapToken); err != nil {
		s.log(ctx, oidcflow.PairwiseSubject(issuer, subject), "admin.OnboardAdmin", "", false)
		return err
	}
	if _, err := s.d.Records.BindAdmin(ctx, issuer, subject); err != nil {
		return err
	}
	s.log(ctx, oidcflow.PairwiseSubject(issuer, subject), "admin.OnboardAdmin", subject, true)
	return nil
}

// OnboardAdmin binds the first super admin from an ID token that a CLI
// or a portal login already obtained. It checks the token against the
// provider before it binds the claims.
func (s *Service) OnboardAdmin(ctx context.Context, providerID, idToken, bootstrapToken string) (records.Admin, error) {
	if strings.TrimSpace(idToken) == "" {
		return records.Admin{}, ErrNoIDToken
	}
	p, err := s.provider(ctx, providerID)
	if err != nil {
		return records.Admin{}, err
	}
	claims, err := s.VerifyIDToken(ctx, p, idToken)
	if err != nil {
		return records.Admin{}, err
	}
	issuer := claimString(claims, "iss")
	subject := claimString(claims, "sub")
	if issuer == "" || subject == "" {
		return records.Admin{}, oidcflow.ErrSessionInvalid
	}
	if err := s.bind(ctx, issuer, subject, bootstrapToken); err != nil {
		return records.Admin{}, err
	}
	return records.Admin{Issuer: strings.TrimRight(issuer, "/"), Subject: subject}, nil
}

// VerifyIDToken checks an ID token against the provider metadata and
// the provider key set. It does not check a nonce, because the caller
// obtained the token in its own login.
func (s *Service) VerifyIDToken(ctx context.Context, p oidcflow.Provider, idToken string) (map[string]any, error) {
	meta, err := s.d.Flow.Metadata(ctx, p)
	if err != nil {
		return nil, err
	}
	keys, err := s.d.Cache.JWKS(ctx, meta.JWKSURI, false)
	if err != nil {
		return nil, err
	}
	opts := oidc.TokenOptions{Issuers: []string{meta.Issuer}, ClientID: p.ClientID, Now: s.d.Now()}
	claims, err := oidc.VerifyToken(idToken, keys, opts)
	if err != nil {
		// A rotated key is not in the cache, so read the set again.
		keys, refresh := s.d.Cache.JWKS(ctx, meta.JWKSURI, true)
		if refresh != nil {
			return nil, refresh
		}
		if claims, err = oidc.VerifyToken(idToken, keys, opts); err != nil {
			return nil, oidcflow.ErrSessionInvalid
		}
	}
	return claims, nil
}

// End implements oidcflow.Logins. It revokes the session and returns
// the provider logout URL when the provider has one.
func (s *Service) End(ctx context.Context, token string) (string, error) {
	claims, err := s.d.Signer.Revoke(token)
	if err != nil {
		return "", err
	}
	s.log(ctx, claims.Subject, "admin.Logout", claims.Provider, true)
	p, ok := s.knownProvider(claims.Provider)
	if !ok {
		return "", nil
	}
	post := ""
	if s.d.Cfg.LogoutRedirect != "" {
		post = s.d.Cfg.PublicURL + s.d.Cfg.LogoutRedirect
	}
	return s.logoutURL(ctx, p, claims.SID, post), nil
}

// knownProvider returns one provider record. A record that is missing,
// or a store fault, gives false.
func (s *Service) knownProvider(id string) (oidcflow.Provider, bool) {
	p, err := s.d.Providers.Get(id)
	if err != nil {
		return oidcflow.Provider{}, false
	}
	return p, true
}

// logoutURL returns the logout URL of the provider. A provider with no
// logout endpoint, or a fault, gives an empty string.
func (s *Service) logoutURL(ctx context.Context, p oidcflow.Provider, sid, post string) string {
	u, err := s.d.Flow.LogoutURL(ctx, p, s.takeHint(sid), post)
	if err != nil {
		return ""
	}
	return u
}

// Session implements oidcflow.Logins.
func (s *Service) Session(_ context.Context, token string) (oidcflow.Claims, error) {
	return s.d.Signer.Verify(token)
}

// Identity is the caller of an RPC or a page.
type Identity struct {
	// Actor is iss|sub for a session, or apikey:<id> for a key.
	Actor string
	// Roles are the roles the credential grants.
	Roles []string
	// Session holds the claims when the credential is a session JWT.
	Session oidcflow.Claims
	// KeyID is the API key id when the credential is a key.
	KeyID string
}

// IsSuperAdmin reports whether the identity may run an admin RPC.
func (i Identity) IsSuperAdmin() bool {
	for _, r := range i.Roles {
		if r == RoleSuperAdmin {
			return true
		}
	}
	return false
}

// Authenticate reads the credential of a request. It accepts an admin
// session JWT and an admin API key. It never reads a token from the
// query string (RFC 9700 section 4.3.2).
func (s *Service) Authenticate(ctx context.Context, h http.Header) (Identity, error) {
	raw := oidcflow.TokenFromRequest(&http.Request{Header: h}, s.d.Cfg.CookieName)
	if raw == "" {
		return Identity{}, oidcflow.ErrUnauthorized
	}
	if strings.HasPrefix(raw, records.SecretPrefix) {
		key, err := s.d.Records.Authenticate(ctx, raw)
		if err != nil {
			return Identity{}, oidcflow.ErrUnauthorized
		}
		id := Identity{Actor: "apikey:" + key.ID, KeyID: key.ID}
		for _, role := range key.Roles {
			id.Roles = append(id.Roles, role)
			if role == RoleAdmin {
				id.Roles = append(id.Roles, RoleSuperAdmin)
			}
		}
		if !id.IsSuperAdmin() {
			return Identity{}, oidcflow.ErrForbidden
		}
		return id, nil
	}
	claims, err := s.d.Signer.Verify(raw)
	if err != nil {
		return Identity{}, err
	}
	id := Identity{Actor: claims.Subject, Roles: claims.Roles, Session: claims}
	if !id.IsSuperAdmin() {
		return Identity{}, oidcflow.ErrForbidden
	}
	return id, nil
}

// Authorizer returns an oidcflow.Authorizer over Authenticate, so the
// service can guard the provider RPCs with the shared helper.
func (s *Service) Authorizer() oidcflow.Authorizer {
	return func(ctx context.Context, h http.Header) error {
		_, err := s.Authenticate(ctx, h)
		return err
	}
}

// CheckCSRF checks the synchronizer token of a browser POST against the
// session of the request (ADR-010 decision 7).
func (s *Service) CheckCSRF(ctx context.Context, r *http.Request) (Identity, error) {
	id, err := s.Authenticate(ctx, r.Header)
	if err != nil {
		return Identity{}, err
	}
	if !s.d.CSRF.Check(id.Session.SID, oidcflow.CSRFFromRequest(r)) {
		return Identity{}, oidcflow.ErrCSRF
	}
	return id, nil
}

// CSRFToken returns a fresh synchronizer token for one session.
func (s *Service) CSRFToken(sid string) string { return s.d.CSRF.Token(sid) }

// log writes one audit record and ignores a store fault, because a
// failed log must not fail a login.
func (s *Service) log(ctx context.Context, actor, action, target string, ok bool) {
	if s.d.Audit == nil {
		return
	}
	_, ignored := s.d.Audit.Append(ctx, audit.Entry{Actor: actor, Action: action, Target: target, OK: ok})
	_ = ignored
}

func (s *Service) takeBootstrap(state string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.d.Now()
	for k, v := range s.bootstraps {
		if now.After(v.expires) {
			delete(s.bootstraps, k)
		}
	}
	v, ok := s.bootstraps[state]
	delete(s.bootstraps, state)
	if !ok || now.After(v.expires) {
		return ""
	}
	return v.token
}

func (s *Service) putHint(sid, idToken string, exp time.Time) {
	if idToken == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.d.Now()
	for k, v := range s.hints {
		if now.After(v.expires) {
			delete(s.hints, k)
		}
	}
	s.hints[sid] = issuedHint{idToken: idToken, expires: exp}
}

func (s *Service) takeHint(sid string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.hints[sid]
	delete(s.hints, sid)
	return v.idToken
}

// name returns the display name of a claim set.
func name(claims map[string]any) string {
	if v := claimString(claims, "name"); v != "" {
		return v
	}
	return claimString(claims, "preferred_username")
}

// claimString returns one claim as a string. A missing claim, or a claim
// of another type, gives an empty string.
func claimString(claims map[string]any, key string) string {
	value, ok := claims[key].(string)
	if !ok {
		return ""
	}
	return value
}
