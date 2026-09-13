// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.issuerauth.v1.IssuerAuthService, the
// provider and API key RPCs of the admin contract, and the OAuth 2.0
// token endpoint for machine clients.
package service

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	issuerauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/roles"
)

// Deps are the collaborators of the service.
type Deps struct {
	Flow      *oidcflow.Flow
	Providers *oidcflow.Registry
	Mappings  *roles.Mappings
	Clients   *clients.Registry
	Pending   oidcflow.PendingStore
	Signer    *oidcflow.Signer
	CSRF      oidcflow.CSRF
	Now       func() time.Time
}

// Service is the issuer-auth service.
type Service struct {
	cfg   config.Config
	d     Deps
	hints *hintStore
}

// New returns a service. Nil Pending and Now get memory defaults.
func New(cfg config.Config, d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Pending == nil {
		d.Pending = oidcflow.NewMemoryPending(d.Now)
	}
	return &Service{cfg: cfg, d: d, hints: newHintStore(d.Now)}
}

// Config returns the configuration.
func (s *Service) Config() config.Config { return s.cfg }

// Signer returns the session signer.
func (s *Service) Signer() *oidcflow.Signer { return s.d.Signer }

// CSRF returns the synchronizer token maker.
func (s *Service) CSRF() oidcflow.CSRF { return s.d.CSRF }

// Providers returns the provider registry.
func (s *Service) Providers() *oidcflow.Registry { return s.d.Providers }

// Handlers returns the plain HTTP login handlers.
func (s *Service) Handlers() oidcflow.Handlers {
	return oidcflow.Handlers{
		Logins:         s,
		Cookie:         oidcflow.Cookie{Name: s.cfg.CookieName, Secure: !s.cfg.InsecureCookie},
		CSRF:           s.d.CSRF,
		LogoutRedirect: s.cfg.LogoutRedirect,
	}
}

// AdminAuthorizer allows the admin service token and sessions that
// carry the issuer-admin role.
func (s *Service) AdminAuthorizer() oidcflow.Authorizer {
	return oidcflow.AnyAuthorizer(oidcflow.BearerAuthorizer(s.cfg.AdminToken), s.sessionAuthorizer(roles.Admin))
}

func (s *Service) sessionAuthorizer(role string) oidcflow.Authorizer {
	return func(_ context.Context, h http.Header) error {
		r := &http.Request{Header: h}
		claims, err := s.d.Signer.Verify(oidcflow.TokenFromRequest(r, ""))
		if err != nil {
			return err
		}
		if !claims.HasRole(role) {
			return oidcflow.ErrForbidden
		}
		return nil
	}
}

// ListProviders implements IssuerAuthServiceHandler.
func (s *Service) ListProviders(ctx context.Context, _ *connect.Request[issuerauthv1.ListProvidersRequest]) (*connect.Response[issuerauthv1.ListProvidersResponse], error) {
	res := &issuerauthv1.ListProvidersResponse{}
	for _, p := range s.d.Providers.Enabled() {
		out := &issuerauthv1.Provider{Id: p.ID, DisplayName: p.DisplayName}
		if m, err := s.d.Flow.Metadata(ctx, p); err == nil {
			out.Issuer = m.Issuer
		}
		res.Providers = append(res.Providers, out)
	}
	return connect.NewResponse(res), nil
}

// LoginStart implements IssuerAuthServiceHandler.
func (s *Service) LoginStart(ctx context.Context, req *connect.Request[issuerauthv1.LoginStartRequest]) (*connect.Response[issuerauthv1.LoginStartResponse], error) {
	pend, u, err := s.start(ctx, req.Msg.GetProviderId(), req.Msg.GetReturnTo())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	return connect.NewResponse(&issuerauthv1.LoginStartResponse{AuthorizationUrl: u, State: pend.State, ExpiresAt: timestamppb.New(pend.ExpiresAt)}), nil
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

// LoginCallback implements IssuerAuthServiceHandler.
func (s *Service) LoginCallback(ctx context.Context, req *connect.Request[issuerauthv1.LoginCallbackRequest]) (*connect.Response[issuerauthv1.LoginCallbackResponse], error) {
	token, claims, returnTo, err := s.Complete(ctx, req.Msg.GetState(), req.Msg.GetCode(), req.Msg.GetError())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	return connect.NewResponse(&issuerauthv1.LoginCallbackResponse{SessionToken: token, Session: toProto(claims), ReturnTo: returnTo}), nil
}

// Introspect implements IssuerAuthServiceHandler.
func (s *Service) Introspect(_ context.Context, req *connect.Request[issuerauthv1.IntrospectRequest]) (*connect.Response[issuerauthv1.IntrospectResponse], error) {
	claims, err := s.d.Signer.Verify(req.Msg.GetSessionToken())
	if err != nil {
		return connect.NewResponse(&issuerauthv1.IntrospectResponse{Active: false}), nil
	}
	return connect.NewResponse(&issuerauthv1.IntrospectResponse{Active: true, Session: toProto(claims)}), nil
}

// Logout implements IssuerAuthServiceHandler.
func (s *Service) Logout(ctx context.Context, req *connect.Request[issuerauthv1.LogoutRequest]) (*connect.Response[issuerauthv1.LogoutResponse], error) {
	u, err := s.End(ctx, req.Msg.GetSessionToken())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	return connect.NewResponse(&issuerauthv1.LogoutResponse{ProviderLogoutUrl: u}), nil
}

// GetRoleMapping implements IssuerAuthServiceHandler. Admin only.
func (s *Service) GetRoleMapping(ctx context.Context, req *connect.Request[issuerauthv1.GetRoleMappingRequest]) (*connect.Response[issuerauthv1.GetRoleMappingResponse], error) {
	if err := s.AdminAuthorizer()(ctx, req.Header()); err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	p, err := s.d.Providers.Get(req.Msg.GetProviderId())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	return connect.NewResponse(&issuerauthv1.GetRoleMappingResponse{Mapping: roles.ToProto(s.d.Mappings.Get(p.ID, p.RolesClaimPath))}), nil
}

// SetRoleMapping implements IssuerAuthServiceHandler. Admin only.
func (s *Service) SetRoleMapping(ctx context.Context, req *connect.Request[issuerauthv1.SetRoleMappingRequest]) (*connect.Response[issuerauthv1.SetRoleMappingResponse], error) {
	if err := s.AdminAuthorizer()(ctx, req.Header()); err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	p, err := s.d.Providers.Get(req.Msg.GetProviderId())
	if err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	m := roles.FromProto(req.Msg.GetMapping())
	if err := s.d.Mappings.Set(p.ID, m); err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	return connect.NewResponse(&issuerauthv1.SetRoleMappingResponse{Mapping: roles.ToProto(m)}), nil
}

// Start implements oidcflow.Logins.
func (s *Service) Start(ctx context.Context, providerID, returnTo string) (string, error) {
	_, u, err := s.start(ctx, providerID, returnTo)
	return u, err
}

// Complete implements oidcflow.Logins. It exchanges the code, maps the
// roles, and issues the session JWT.
func (s *Service) Complete(ctx context.Context, state, code, providerError string) (string, oidcflow.Claims, string, error) {
	pend, ok := s.d.Pending.Take(state)
	if !ok {
		return "", oidcflow.Claims{}, "", oidcflow.ErrStateUnknown
	}
	if providerError != "" {
		return "", oidcflow.Claims{}, "", fmt.Errorf("%w: %s", oidcflow.ErrProviderError, providerError)
	}
	p, err := s.d.Providers.Get(pend.ProviderID)
	if err != nil {
		return "", oidcflow.Claims{}, "", err
	}
	res, err := s.d.Flow.Complete(ctx, p, pend, code)
	if err != nil {
		return "", oidcflow.Claims{}, "", err
	}
	granted, err := roles.Apply(s.d.Mappings.Get(p.ID, p.RolesClaimPath), res.Claims)
	if err != nil {
		return "", oidcflow.Claims{}, "", err
	}
	name, _ := res.Claims["name"].(string)
	if name == "" {
		name, _ = res.Claims["preferred_username"].(string)
	}
	token, claims, err := s.d.Signer.Issue(oidcflow.Claims{
		Subject:  oidcflow.PairwiseSubject(res.Issuer, res.Subject),
		Roles:    granted,
		Provider: p.ID,
		Name:     name,
		Tenant:   s.cfg.TenantID,
	})
	if err != nil {
		return "", oidcflow.Claims{}, "", err
	}
	s.hints.put(claims.SID, res.IDToken, claims.Expiry())
	return token, claims, pend.ReturnTo, nil
}

// End implements oidcflow.Logins. It revokes the session and returns
// the RP initiated logout URL when the provider has one.
func (s *Service) End(ctx context.Context, token string) (string, error) {
	claims, err := s.d.Signer.Revoke(token)
	if err != nil {
		return "", err
	}
	p, err := s.d.Providers.Get(claims.Provider)
	if err != nil {
		return "", nil
	}
	post := ""
	if s.cfg.LogoutRedirect != "" {
		post = s.cfg.PublicBaseURL + s.cfg.LogoutRedirect
	}
	u, err := s.d.Flow.LogoutURL(ctx, p, s.hints.take(claims.SID), post)
	if err != nil {
		return "", nil
	}
	return u, nil
}

// Session implements oidcflow.Logins.
func (s *Service) Session(_ context.Context, token string) (oidcflow.Claims, error) {
	return s.d.Signer.Verify(token)
}

func toProto(c oidcflow.Claims) *issuerauthv1.Session {
	return &issuerauthv1.Session{
		Id:          c.ID,
		Subject:     c.Subject,
		DisplayName: c.Name,
		TenantId:    c.Tenant,
		Roles:       roles.Values(c.Roles),
		IssuedAt:    timestamppb.New(time.Unix(c.IssuedAt, 0)),
		ExpiresAt:   timestamppb.New(c.Expiry()),
		ProviderId:  c.Provider,
	}
}

// hintStore keeps the ID token of each session for id_token_hint.
type hintStore struct {
	now func() time.Time
	mu  sync.Mutex
	m   map[string]hint
}

type hint struct {
	token string
	exp   time.Time
}

func newHintStore(now func() time.Time) *hintStore {
	return &hintStore{now: now, m: map[string]hint{}}
}

func (h *hintStore) put(sid, token string, exp time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	t := h.now()
	for k, v := range h.m {
		if t.After(v.exp) {
			delete(h.m, k)
		}
	}
	h.m[sid] = hint{token: token, exp: exp}
}

func (h *hintStore) take(sid string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := h.m[sid]
	delete(h.m, sid)
	return v.token
}
