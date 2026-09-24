// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.walletauth.v1.WalletAuthService and the
// provider RPCs of the admin contract for the wallet role.
package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	walletauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/grants"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/limits"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/wallets"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// Deps are the collaborators of the service.
type Deps struct {
	Flow      *oidcflow.Flow
	Providers *oidcflow.Registry
	Wallets   *wallets.Registry
	Registrar wallets.Registrar
	Grants    *grants.Vault
	Limiter   limits.Limiter
	Pending   oidcflow.PendingStore
	Signer    *oidcflow.Signer
	CSRF      oidcflow.CSRF
	Now       func() time.Time
	// Kit renders the sign in chooser and Assets serves its stylesheet
	// (ADR-035). Both come from the theme file of the deployment.
	Kit    *components.Kit
	Assets http.Handler
}

// Service is the wallet-auth service.
type Service struct {
	cfg config.Config
	d   Deps
}

// New returns a service. Nil Pending, Registrar, and Now get defaults.
func New(cfg config.Config, d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Pending == nil {
		d.Pending = oidcflow.NewMemoryPending(d.Now)
	}
	if d.Registrar == nil {
		d.Registrar = wallets.LocalRegistrar{}
	}
	return &Service{cfg: cfg, d: d}
}

// Config returns the configuration.
func (s *Service) Config() config.Config { return s.cfg }

// Signer returns the session signer.
func (s *Service) Signer() *oidcflow.Signer { return s.d.Signer }

// Providers returns the provider registry.
func (s *Service) Providers() *oidcflow.Registry { return s.d.Providers }

// Wallets returns the wallet registry.
func (s *Service) Wallets() *wallets.Registry { return s.d.Wallets }

// Flow returns the login flow, which reads provider metadata.
func (s *Service) Flow() *oidcflow.Flow { return s.d.Flow }

// Kit returns the component kit of the sign in pages.
func (s *Service) Kit() *components.Kit { return s.d.Kit }

// Assets returns the handler of the kit assets.
func (s *Service) Assets() http.Handler { return s.d.Assets }

// Limiter returns the login rate limiter.
func (s *Service) Limiter() limits.Limiter { return s.d.Limiter }

// Handlers returns the plain HTTP login handlers.
func (s *Service) Handlers() oidcflow.Handlers {
	return oidcflow.Handlers{
		Logins:         s,
		Cookie:         oidcflow.Cookie{Name: s.cfg.CookieName, Secure: !s.cfg.InsecureCookie},
		CSRF:           s.d.CSRF,
		LogoutRedirect: s.cfg.LogoutRedirect,
	}
}

// Admin returns the provider RPCs of the admin contract for this
// deployment (ADR-012 decision 5).
func (s *Service) Admin() oidcflow.AdminProviders {
	return oidcflow.AdminProviders{
		Registry:          s.d.Providers,
		Authorize:         oidcflow.BearerAuthorizer(s.cfg.AdminToken),
		Roles:             []string{"holder"},
		InternalAuthority: s.cfg.ProviderInternalAuthority,
	}
}

// ListProviders implements WalletAuthServiceHandler.
func (s *Service) ListProviders(ctx context.Context, _ *connect.Request[walletauthv1.ListProvidersRequest]) (*connect.Response[walletauthv1.ListProvidersResponse], error) {
	res := &walletauthv1.ListProvidersResponse{}
	for _, p := range s.d.Providers.Enabled() {
		out := &walletauthv1.Provider{Id: p.ID, DisplayName: p.DisplayName, LogoUri: p.LogoURI}
		if m, err := s.d.Flow.Metadata(ctx, p); err == nil {
			out.Issuer = m.Issuer
		}
		res.Providers = append(res.Providers, out)
	}
	return connect.NewResponse(res), nil
}

// LoginStart implements WalletAuthServiceHandler.
func (s *Service) LoginStart(ctx context.Context, req *connect.Request[walletauthv1.LoginStartRequest]) (*connect.Response[walletauthv1.LoginStartResponse], error) {
	if err := s.allow(ctx, req.Peer().Addr); err != nil {
		return nil, err
	}
	pend, u, err := s.start(ctx, req.Msg.GetProviderId(), req.Msg.GetReturnTo())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	return connect.NewResponse(&walletauthv1.LoginStartResponse{AuthorizationUrl: u, State: pend.State, ExpiresAt: timestamppb.New(pend.ExpiresAt)}), nil
}

// allow applies the login rate limit to one client address.
func (s *Service) allow(ctx context.Context, addr string) error {
	if s.d.Limiter == nil {
		return nil
	}
	ok, err := s.d.Limiter.Allow(ctx, limits.Host(addr))
	if err != nil {
		return connect.NewError(connect.CodeUnavailable, err)
	}
	if !ok {
		return connect.NewError(connect.CodeResourceExhausted, limits.ErrLimited)
	}
	return nil
}

func (s *Service) start(ctx context.Context, providerID, returnTo string) (oidcflow.Pending, string, error) {
	p, err := s.d.Providers.Get(providerID)
	if err != nil {
		return oidcflow.Pending{}, "", err
	}
	pend, u, err := s.d.Flow.Begin(ctx, p, s.cfg.RedirectURI, returnTo)
	if err != nil {
		return oidcflow.Pending{}, "", err
	}
	if err := s.d.Pending.Put(pend); err != nil {
		return oidcflow.Pending{}, "", err
	}
	return pend, u, nil
}

// LoginCallback implements WalletAuthServiceHandler.
func (s *Service) LoginCallback(ctx context.Context, req *connect.Request[walletauthv1.LoginCallbackRequest]) (*connect.Response[walletauthv1.LoginCallbackResponse], error) {
	token, claims, returnTo, created, err := s.complete(ctx, req.Msg.GetState(), req.Msg.GetCode(), req.Msg.GetError())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	return connect.NewResponse(&walletauthv1.LoginCallbackResponse{SessionToken: token, Session: toProto(claims), ReturnTo: returnTo, NewWallet: created}), nil
}

// Introspect implements WalletAuthServiceHandler.
func (s *Service) Introspect(_ context.Context, req *connect.Request[walletauthv1.IntrospectRequest]) (*connect.Response[walletauthv1.IntrospectResponse], error) {
	claims, ok := s.session(req.Msg.GetSessionToken())
	if !ok {
		return connect.NewResponse(&walletauthv1.IntrospectResponse{Active: false}), nil
	}
	return connect.NewResponse(&walletauthv1.IntrospectResponse{Active: true, Session: toProto(claims)}), nil
}

// Logout implements WalletAuthServiceHandler.
func (s *Service) Logout(ctx context.Context, req *connect.Request[walletauthv1.LogoutRequest]) (*connect.Response[walletauthv1.LogoutResponse], error) {
	u, err := s.End(ctx, req.Msg.GetSessionToken())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	return connect.NewResponse(&walletauthv1.LogoutResponse{ProviderLogoutUrl: u}), nil
}

// GetAuthorizationGrant implements WalletAuthServiceHandler. It returns
// the IdP access token of the session bound to one credential issuer
// (ADR-020 decision 3).
func (s *Service) GetAuthorizationGrant(_ context.Context, req *connect.Request[walletauthv1.GetAuthorizationGrantRequest]) (*connect.Response[walletauthv1.GetAuthorizationGrantResponse], error) {
	claims, err := s.d.Signer.Verify(req.Msg.GetSessionToken())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	issuer := req.Msg.GetCredentialIssuer()
	if u, serr := url.Parse(issuer); serr != nil || u.Scheme == "" || u.Host == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("credential_issuer must be an absolute URL"))
	}
	g, err := s.d.Grants.Take(claims.SID, issuer)
	switch {
	case errors.Is(err, grants.ErrBound):
		return nil, connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, grants.ErrNotFound), errors.Is(err, grants.ErrExpired):
		return nil, connect.NewError(connect.CodeFailedPrecondition, err)
	case err != nil:
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&walletauthv1.GetAuthorizationGrantResponse{
		Grant:     g.AccessToken,
		GrantType: s.cfg.GrantType,
		ExpiresAt: timestamppb.New(g.ExpiresAt),
	}), nil
}

// Start implements oidcflow.Logins.
func (s *Service) Start(ctx context.Context, providerID, returnTo string) (string, error) {
	_, u, err := s.start(ctx, providerID, returnTo)
	return u, err
}

// Register implements signin.Registrar (ADR-035 decision 3). It starts
// a pending login whose first step is the register action of the
// provider, so the callback finishes it like a login.
func (s *Service) Register(ctx context.Context, providerID, returnTo string) (string, error) {
	p, err := s.d.Providers.Get(providerID)
	if err != nil {
		return "", err
	}
	pend, u, err := s.d.Flow.BeginRegister(ctx, p, s.cfg.RedirectURI, returnTo)
	if err != nil {
		return "", err
	}
	if err := s.d.Pending.Put(pend); err != nil {
		return "", err
	}
	return u, nil
}

// Complete implements oidcflow.Logins.
func (s *Service) Complete(ctx context.Context, state, code, providerError string) (string, oidcflow.Claims, string, error) {
	token, claims, returnTo, _, err := s.complete(ctx, state, code, providerError)
	return token, claims, returnTo, err
}

// complete exchanges the code, finds or creates the wallet, seals the
// IdP tokens, and issues the session JWT.
func (s *Service) complete(ctx context.Context, state, code, providerError string) (string, oidcflow.Claims, string, bool, error) {
	pend, ok := s.d.Pending.Take(state)
	if !ok {
		return "", oidcflow.Claims{}, "", false, oidcflow.ErrStateUnknown
	}
	if providerError != "" {
		return "", oidcflow.Claims{}, "", false, fmt.Errorf("%w: %s", oidcflow.ErrProviderError, providerError)
	}
	p, err := s.d.Providers.Get(pend.ProviderID)
	if err != nil {
		return "", oidcflow.Claims{}, "", false, err
	}
	res, err := s.d.Flow.Complete(ctx, p, pend, code)
	if err != nil {
		return "", oidcflow.Claims{}, "", false, err
	}
	key := oidcflow.HashSubject(s.cfg.Salt, oidcflow.PairwiseSubject(res.Issuer, res.Subject))
	w, created, err := s.d.Wallets.Ensure(ctx, key, s.d.Registrar)
	if err != nil {
		return "", oidcflow.Claims{}, "", false, err
	}
	token, claims, err := s.d.Signer.Issue(oidcflow.Claims{
		Subject:      key,
		Provider:     p.ID,
		WalletID:     w.WalletID,
		HolderDID:    w.HolderDID,
		HasHolderKey: w.KeyThumbprint != "",
	})
	if err != nil {
		return "", oidcflow.Claims{}, "", false, err
	}
	exp := res.TokenExpiresAt
	if exp.IsZero() {
		exp = claims.Expiry()
	}
	if err := s.d.Grants.Put(claims.SID, grants.Grant{AccessToken: res.AccessToken, IDToken: res.IDToken, ExpiresAt: exp}); err != nil {
		return "", oidcflow.Claims{}, "", false, err
	}
	return token, claims, pend.ReturnTo, created, nil
}

// End implements oidcflow.Logins. It revokes the session, drops the
// sealed tokens, and returns the RP initiated logout URL when the
// provider has one (ADR-020 decision 5).
func (s *Service) End(ctx context.Context, token string) (string, error) {
	claims, err := s.d.Signer.Revoke(token)
	if err != nil {
		return "", err
	}
	hint := s.d.Grants.IDToken(claims.SID)
	ignored := s.d.Grants.Delete(claims.SID)
	_ = ignored
	p, ok := s.knownProvider(claims.Provider)
	if !ok {
		return "", nil
	}
	post := ""
	if s.cfg.LogoutRedirect != "" {
		post = s.cfg.PublicBaseURL + s.cfg.LogoutRedirect
	}
	return s.logoutURL(ctx, p, hint, post), nil
}

// session returns the claims of a session token. A token that does not
// verify gives false.
func (s *Service) session(token string) (oidcflow.Claims, bool) {
	claims, err := s.d.Signer.Verify(token)
	if err != nil {
		return oidcflow.Claims{}, false
	}
	return claims, true
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
func (s *Service) logoutURL(ctx context.Context, p oidcflow.Provider, hint, post string) string {
	u, err := s.d.Flow.LogoutURL(ctx, p, hint, post)
	if err != nil {
		return ""
	}
	return u
}

// Session implements oidcflow.Logins.
func (s *Service) Session(_ context.Context, token string) (oidcflow.Claims, error) {
	return s.d.Signer.Verify(token)
}

func toProto(c oidcflow.Claims) *walletauthv1.Session {
	return &walletauthv1.Session{
		Id:              c.ID,
		PairwiseSubject: c.Subject,
		WalletId:        c.WalletID,
		HolderDid:       c.HolderDID,
		HasHolderKey:    c.HasHolderKey,
		IssuedAt:        timestamppb.New(time.Unix(c.IssuedAt, 0)),
		ExpiresAt:       timestamppb.New(c.Expiry()),
		ProviderId:      c.Provider,
	}
}
