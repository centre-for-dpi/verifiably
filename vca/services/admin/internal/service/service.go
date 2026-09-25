// SPDX-License-Identifier: Apache-2.0

// Package service implements vca.admin.v1.AdminService (ADR-009
// decision 1). Every admin operation is an RPC here. The vca admin CLI
// and the admin portal are two clients of this one service.
//
// Every RPC checks the caller, does the work, and writes one audit
// record with the actor, the action, and the request id (ADR-009
// decision 6).
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/fanout"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/health"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/serve"
)

// DefaultPageSize is the page size of a list RPC without one.
const DefaultPageSize = 50

// MaxPageSize caps a page of a list RPC.
const MaxPageSize = 500

// ErrNoTrustRegistry reports a deployment without a trust registry URL.
var ErrNoTrustRegistry = errors.New("service: the trust registry URL is not configured")

// ErrNotPending reports an approval or a rejection of a trust entry that
// does not wait for review.
var ErrNotPending = errors.New("service: the trust entry is not pending review")

// Deps are the collaborators of the service.
type Deps struct {
	// Cfg is the service configuration.
	Cfg config.Config
	// Records holds the tenants, the keys, and the admin bindings.
	Records *records.Store
	// Audit is the append only log.
	Audit *auditlog.Log
	// Login authenticates the caller.
	Login *login.Service
	// Providers holds the OIDC provider records.
	Providers *oidcflow.Registry
	// Vault keeps the client secrets out of the provider records.
	Vault *onboard.Vault
	// Fetch calls the provider endpoints of an onboarding.
	Fetch onboard.Fetcher
	// Trust is the trust registry client. A nil client makes the trust
	// RPCs return FailedPrecondition.
	Trust trustv1connect.TrustServiceClient
	// Health probes the services of the deployment.
	Health *health.Prober
	// FanOut pushes a provider record to the auth service of every live
	// pair it names (ADR-035 decision 5). Nil pushes nothing.
	FanOut *fanout.FanOut
	// Stacks reaches the adapters of the stacks that run now, for the
	// tenants of a stack (ADR-037). Nil offers no stack.
	Stacks *stacks.Directory
	// Now returns the current time.
	Now func() time.Time
}

// Service implements adminv1connect.AdminServiceHandler.
type Service struct {
	d Deps
}

// New returns the service. It checks the required collaborators.
func New(d Deps) (*Service, error) {
	if d.Records == nil || d.Audit == nil || d.Login == nil || d.Providers == nil {
		return nil, errors.New("service: the records, the audit log, the login, and the providers are required")
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Vault == nil {
		d.Vault = onboard.NewVault(d.Cfg.StateDir)
	}
	if d.Fetch == nil {
		d.Fetch = &http.Client{Timeout: d.Cfg.Timeout}
	}
	if d.Health == nil {
		d.Health = health.New(nil, d.Cfg.Timeout, d.Now)
	}
	return &Service{d: d}, nil
}

// Ready reports whether the service can take traffic. It is ready when
// the record store answers.
func (s *Service) Ready() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := s.d.Records.CountAdmins(ctx)
	return err == nil
}

// Providers returns the provider registry. The portal reads it.
func (s *Service) Providers() *oidcflow.Registry { return s.d.Providers }

// guard checks the caller and returns the actor for the audit record.
func (s *Service) guard(ctx context.Context, h http.Header) (login.Identity, error) {
	id, err := s.d.Login.Authenticate(ctx, h)
	if err != nil {
		return login.Identity{}, oidcflow.ConnectError(err)
	}
	return id, nil
}

// write records one action that changed state and returns err unchanged.
func (s *Service) write(ctx context.Context, actor, action, target string, err error) error {
	_, ignored := s.d.Audit.Append(ctx, auditlog.Entry{
		Actor:     actor,
		Action:    action,
		RequestID: serve.RequestIDFrom(ctx),
		Target:    target,
		OK:        err == nil,
	})
	_ = ignored
	return err
}

// fail maps a package error to a Connect error.
func fail(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, records.ErrNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, records.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, records.ErrExists):
		return connect.NewError(connect.CodeAlreadyExists, err)
	case errors.Is(err, records.ErrBootstrapUsed), errors.Is(err, ErrNoTrustRegistry), errors.Is(err, ErrNotPending),
		errors.Is(err, stacks.ErrNotOffered):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, records.ErrBootstrapToken), errors.Is(err, login.ErrNotAdmin):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, login.ErrNoIDToken):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, onboard.ErrDiscovery), errors.Is(err, onboard.ErrRegistration),
		errors.Is(err, onboard.ErrClientID), errors.Is(err, onboard.ErrSecret):
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	return oidcflow.ConnectError(err)
}

// trust returns the trust registry client.
func (s *Service) trust() (trustv1connect.TrustServiceClient, error) {
	if s.d.Trust == nil {
		return nil, ErrNoTrustRegistry
	}
	return s.d.Trust, nil
}

// UpsertTrustEntry implements AdminServiceHandler. It forwards the
// entry to the trust registry (ADR-011).
func (s *Service) UpsertTrustEntry(ctx context.Context, req *connect.Request[adminv1.UpsertTrustEntryRequest]) (*connect.Response[adminv1.UpsertTrustEntryResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.UpsertTrustEntry", "", err))
	}
	res, err := client.UpsertEntry(ctx, connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: req.Msg.GetEntry()}))
	if serr := s.write(ctx, id.Actor, "admin.UpsertTrustEntry", identifierText(req.Msg.GetEntry().GetIdentifier()), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.UpsertTrustEntryResponse{Entry: res.Msg.GetEntry()}), nil
}

// GetTrustEntry implements AdminServiceHandler.
func (s *Service) GetTrustEntry(ctx context.Context, req *connect.Request[adminv1.GetTrustEntryRequest]) (*connect.Response[adminv1.GetTrustEntryResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.GetTrustEntry", "", err))
	}
	res, err := client.GetEntry(ctx, connect.NewRequest(&trustv1.GetEntryRequest{Identifier: req.Msg.GetIdentifier()}))
	if serr := s.write(ctx, id.Actor, "admin.GetTrustEntry", identifierText(req.Msg.GetIdentifier()), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.GetTrustEntryResponse{Entry: res.Msg.GetEntry()}), nil
}

// ListTrustEntries implements AdminServiceHandler.
func (s *Service) ListTrustEntries(ctx context.Context, req *connect.Request[adminv1.ListTrustEntriesRequest]) (*connect.Response[adminv1.ListTrustEntriesResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.ListTrustEntries", "", err))
	}
	res, err := client.ListEntries(ctx, connect.NewRequest(&trustv1.ListEntriesRequest{
		Page: req.Msg.GetPage(), Role: req.Msg.GetRole(), Status: req.Msg.GetStatus(),
	}))
	if serr := s.write(ctx, id.Actor, "admin.ListTrustEntries", "", err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.ListTrustEntriesResponse{
		Entries: res.Msg.GetEntries(), Page: res.Msg.GetPage(),
	}), nil
}

// pending reads one trust entry and checks that it waits for review.
func pending(ctx context.Context, client trustv1connect.TrustServiceClient, id *trustv1.TrustEntry_Identifier) (*trustv1.TrustEntry, error) {
	res, err := client.GetEntry(ctx, connect.NewRequest(&trustv1.GetEntryRequest{Identifier: id}))
	if err != nil {
		return nil, err
	}
	if res.Msg.GetEntry().GetStatus() != trustv1.Status_STATUS_PENDING {
		return nil, ErrNotPending
	}
	return res.Msg.GetEntry(), nil
}

// ApproveTrustEntry implements AdminServiceHandler. It sets a pending
// entry to active, so the registry publishes it (ADR-011 decision 1).
// The audit log records the decision, also when it fails.
func (s *Service) ApproveTrustEntry(ctx context.Context, req *connect.Request[adminv1.ApproveTrustEntryRequest]) (*connect.Response[adminv1.ApproveTrustEntryResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	target := identifierText(req.Msg.GetIdentifier())
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.ApproveTrustEntry", target, err))
	}
	var stored *trustv1.TrustEntry
	entry, err := pending(ctx, client, req.Msg.GetIdentifier())
	if err == nil {
		entry.Status = trustv1.Status_STATUS_ACTIVE
		var res *connect.Response[trustv1.UpsertEntryResponse]
		if res, err = client.UpsertEntry(ctx, connect.NewRequest(&trustv1.UpsertEntryRequest{Entry: entry})); err == nil {
			stored = res.Msg.GetEntry()
		}
	}
	if serr := s.write(ctx, id.Actor, "admin.ApproveTrustEntry", target, err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.ApproveTrustEntryResponse{Entry: stored}), nil
}

// RejectTrustEntry implements AdminServiceHandler. It removes a pending
// entry. The audit log records the decision, also when it fails.
func (s *Service) RejectTrustEntry(ctx context.Context, req *connect.Request[adminv1.RejectTrustEntryRequest]) (*connect.Response[adminv1.RejectTrustEntryResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	target := identifierText(req.Msg.GetIdentifier())
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.RejectTrustEntry", target, err))
	}
	if _, err = pending(ctx, client, req.Msg.GetIdentifier()); err == nil {
		_, err = client.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{Identifier: req.Msg.GetIdentifier()}))
	}
	if serr := s.write(ctx, id.Actor, "admin.RejectTrustEntry", target, err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.RejectTrustEntryResponse{}), nil
}

// AddTrustRegistry implements AdminServiceHandler. It forwards the
// registry to the trust registry, which reads and checks its list
// (ADR-011 decision 7).
func (s *Service) AddTrustRegistry(ctx context.Context, req *connect.Request[adminv1.AddTrustRegistryRequest]) (*connect.Response[adminv1.AddTrustRegistryResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.AddTrustRegistry", "", err))
	}
	res, err := client.AddRegistry(ctx, connect.NewRequest(&trustv1.AddRegistryRequest{Registry: req.Msg.GetRegistry()}))
	target := ""
	if err == nil {
		target = res.Msg.GetRegistry().GetId()
	}
	if serr := s.write(ctx, id.Actor, "admin.AddTrustRegistry", target, err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.AddTrustRegistryResponse{Registry: res.Msg.GetRegistry()}), nil
}

// ListTrustRegistries implements AdminServiceHandler.
func (s *Service) ListTrustRegistries(ctx context.Context, req *connect.Request[adminv1.ListTrustRegistriesRequest]) (*connect.Response[adminv1.ListTrustRegistriesResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.ListTrustRegistries", "", err))
	}
	res, err := client.ListRegistries(ctx, connect.NewRequest(&trustv1.ListRegistriesRequest{}))
	if serr := s.write(ctx, id.Actor, "admin.ListTrustRegistries", "", err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.ListTrustRegistriesResponse{
		Registries: res.Msg.GetRegistries(), Local: res.Msg.GetLocal(), JwksUrl: res.Msg.GetJwksUrl(),
	}), nil
}

// RemoveTrustRegistry implements AdminServiceHandler.
func (s *Service) RemoveTrustRegistry(ctx context.Context, req *connect.Request[adminv1.RemoveTrustRegistryRequest]) (*connect.Response[adminv1.RemoveTrustRegistryResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.RemoveTrustRegistry", req.Msg.GetId(), err))
	}
	_, err = client.RemoveRegistry(ctx, connect.NewRequest(&trustv1.RemoveRegistryRequest{Id: req.Msg.GetId()}))
	if serr := s.write(ctx, id.Actor, "admin.RemoveTrustRegistry", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.RemoveTrustRegistryResponse{}), nil
}

// SyncTrustRegistry implements AdminServiceHandler. A failed read is
// not an error: the registry carries the reason in last_error.
func (s *Service) SyncTrustRegistry(ctx context.Context, req *connect.Request[adminv1.SyncTrustRegistryRequest]) (*connect.Response[adminv1.SyncTrustRegistryResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.SyncTrustRegistry", req.Msg.GetId(), err))
	}
	res, err := client.SyncRegistry(ctx, connect.NewRequest(&trustv1.SyncRegistryRequest{Id: req.Msg.GetId()}))
	if serr := s.write(ctx, id.Actor, "admin.SyncTrustRegistry", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.SyncTrustRegistryResponse{Registry: res.Msg.GetRegistry()}), nil
}

// DeleteTrustEntry implements AdminServiceHandler.
func (s *Service) DeleteTrustEntry(ctx context.Context, req *connect.Request[adminv1.DeleteTrustEntryRequest]) (*connect.Response[adminv1.DeleteTrustEntryResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	client, err := s.trust()
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.DeleteTrustEntry", "", err))
	}
	_, err = client.DeleteEntry(ctx, connect.NewRequest(&trustv1.DeleteEntryRequest{Identifier: req.Msg.GetIdentifier()}))
	if serr := s.write(ctx, id.Actor, "admin.DeleteTrustEntry", identifierText(req.Msg.GetIdentifier()), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.DeleteTrustEntryResponse{}), nil
}

// CreateAuthProvider implements AdminServiceHandler. It reads the
// provider metadata and registers a client when the caller asks for
// dynamic client registration (ADR-010 decision 3).
func (s *Service) CreateAuthProvider(ctx context.Context, req *connect.Request[adminv1.CreateAuthProviderRequest]) (*connect.Response[adminv1.CreateAuthProviderResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	stored, err := s.onboardProvider(ctx, req.Msg.GetProvider(), req.Msg.GetDynamicRegistration())
	if serr := s.write(ctx, id.Actor, "admin.CreateAuthProvider", stored.ID, err); serr != nil {
		return nil, fail(serr)
	}
	pushes := s.push(ctx, id, req.Header(), stored)
	return connect.NewResponse(&adminv1.CreateAuthProviderResponse{Provider: oidcflow.ToAdminProto(stored), Pushes: pushes}), nil
}

// push sends a stored provider to the auth service of every live pair
// its roles and stacks name (ADR-035 decision 5). It forwards the admin
// session token of the caller; an API key has none, so every target
// then reports a failure. One audit record per target names the pair
// and the outcome, so a partial failure stays visible, and the answer
// carries the same outcome per target for the client.
func (s *Service) push(ctx context.Context, id login.Identity, h http.Header, p oidcflow.Provider) []*adminv1.PushResult {
	if s.d.FanOut == nil {
		return nil
	}
	token := ""
	if id.Session.Subject != "" {
		token = oidcflow.TokenFromRequest(&http.Request{Header: h}, s.d.Cfg.CookieName)
	}
	report := s.d.FanOut.Push(ctx, token, p)
	out := make([]*adminv1.PushResult, 0, len(report.Results))
	for _, r := range report.Results {
		// The RPC answer stays the stored record; the push outcome rides
		// beside it and in the audit log.
		anyval.Discard(s.write(ctx, id.Actor, "admin.PushAuthProvider", r.Target.Pair+" "+p.ID, r.Err))
		res := &adminv1.PushResult{Pair: r.Target.Pair, Ok: r.Err == nil, Created: r.Created}
		if r.Err != nil {
			res.Error = r.Err.Error()
		}
		out = append(out, res)
	}
	return out
}

// OnboardProvider implements AdminServiceHandler. It registers one OIDC
// provider from its issuer URL. It runs the same onboarding path as
// CreateAuthProvider (ADR-010 decision 3).
func (s *Service) OnboardProvider(ctx context.Context, req *connect.Request[adminv1.OnboardProviderRequest]) (*connect.Response[adminv1.OnboardProviderResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	provider := &adminv1.AuthProvider{
		DiscoveryUrl: req.Msg.GetIssuerUrl(),
		ClientId:     req.Msg.GetClientId(),
		ClientSecret: req.Msg.GetClientSecret(),
		Enabled:      true,
	}
	stored, err := s.onboardProvider(ctx, provider, req.Msg.GetDynamicRegistration())
	if serr := s.write(ctx, id.Actor, "admin.OnboardProvider", stored.ID, err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.OnboardProviderResponse{Provider: oidcflow.ToAdminProto(stored)}), nil
}

// onboardProvider runs the onboarding and stores the record.
func (s *Service) onboardProvider(ctx context.Context, m *adminv1.AuthProvider, dynamic bool) (oidcflow.Provider, error) {
	in := oidcflow.FromAdminProto(m)
	res, err := onboard.Run(ctx, s.d.Fetch, s.d.Vault, onboard.Options{
		ID:             records.NewID(),
		DisplayName:    in.DisplayName,
		DiscoveryURL:   in.DiscoveryURL,
		ClientID:       in.ClientID,
		ClientSecret:   in.ClientSecret,
		Dynamic:        dynamic,
		RedirectURI:    s.d.Cfg.RedirectURI,
		RolesClaimPath: in.RolesClaimPath,
		Roles:          in.Roles,
		Enabled:        m.GetEnabled(),
		Profile:        in.Profile,
	})
	if err != nil {
		return oidcflow.Provider{}, err
	}
	return s.d.Providers.Put(res.Provider)
}

// GetAuthProvider implements AdminServiceHandler.
func (s *Service) GetAuthProvider(ctx context.Context, req *connect.Request[adminv1.GetAuthProviderRequest]) (*connect.Response[adminv1.GetAuthProviderResponse], error) {
	if _, err := s.guard(ctx, req.Header()); err != nil {
		return nil, err
	}
	p, err := s.d.Providers.Get(req.Msg.GetId())
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&adminv1.GetAuthProviderResponse{Provider: oidcflow.ToAdminProto(p)}), nil
}

// ListAuthProviders implements AdminServiceHandler.
func (s *Service) ListAuthProviders(ctx context.Context, req *connect.Request[adminv1.ListAuthProvidersRequest]) (*connect.Response[adminv1.ListAuthProvidersResponse], error) {
	if _, err := s.guard(ctx, req.Header()); err != nil {
		return nil, err
	}
	all := s.d.Providers.List()
	page, next := paginate(all, req.Msg.GetPage(), func(p oidcflow.Provider) string { return p.ID })
	res := &adminv1.ListAuthProvidersResponse{Page: &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(all))}}
	for _, p := range page {
		res.Providers = append(res.Providers, oidcflow.ToAdminProto(p))
	}
	return connect.NewResponse(res), nil
}

// UpdateAuthProvider implements AdminServiceHandler.
func (s *Service) UpdateAuthProvider(ctx context.Context, req *connect.Request[adminv1.UpdateAuthProviderRequest]) (*connect.Response[adminv1.UpdateAuthProviderResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	in := oidcflow.FromAdminProto(req.Msg.GetProvider())
	current, err := s.d.Providers.Get(in.ID)
	if err != nil {
		return nil, fail(s.write(ctx, id.Actor, "admin.UpdateAuthProvider", in.ID, err))
	}
	// The record keeps its secret reference when the caller sends none.
	if in.ClientSecret.IsZero() {
		in.ClientSecret = current.ClientSecret
	}
	if in.DiscoveryURL == "" {
		in.DiscoveryURL = current.DiscoveryURL
	}
	if in.ClientID == "" {
		in.ClientID = current.ClientID
	}
	in.Scopes = current.Scopes
	in.InternalAuthority = current.InternalAuthority
	stored, err := s.d.Providers.Put(in)
	if serr := s.write(ctx, id.Actor, "admin.UpdateAuthProvider", in.ID, err); serr != nil {
		return nil, fail(serr)
	}
	pushes := s.push(ctx, id, req.Header(), stored)
	return connect.NewResponse(&adminv1.UpdateAuthProviderResponse{Provider: oidcflow.ToAdminProto(stored), Pushes: pushes}), nil
}

// DeleteAuthProvider implements AdminServiceHandler.
func (s *Service) DeleteAuthProvider(ctx context.Context, req *connect.Request[adminv1.DeleteAuthProviderRequest]) (*connect.Response[adminv1.DeleteAuthProviderResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	err = s.d.Providers.Delete(req.Msg.GetId())
	if serr := s.write(ctx, id.Actor, "admin.DeleteAuthProvider", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.DeleteAuthProviderResponse{}), nil
}

// CreateApiKey implements AdminServiceHandler. The response shows the
// secret value once.
//
//nolint:staticcheck // ST1003: the generated Connect interface fixes this name
func (s *Service) CreateApiKey(ctx context.Context, req *connect.Request[adminv1.CreateApiKeyRequest]) (*connect.Response[adminv1.CreateApiKeyResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	spec := records.KeySpec{
		DisplayName: req.Msg.GetDisplayName(),
		TenantID:    req.Msg.GetTenantId(),
		Roles:       roleNames(req.Msg.GetRoles()),
	}
	if req.Msg.GetExpiresAt() != nil {
		spec.ExpiresAt = req.Msg.GetExpiresAt().AsTime()
	}
	key, secret, err := s.d.Records.CreateKey(ctx, spec)
	if serr := s.write(ctx, id.Actor, "admin.CreateApiKey", key.ID, err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.CreateApiKeyResponse{Key: keyProto(key), Secret: secret}), nil
}

// ListApiKeys implements AdminServiceHandler.
//
//nolint:staticcheck // ST1003: the generated Connect interface fixes this name
func (s *Service) ListApiKeys(ctx context.Context, req *connect.Request[adminv1.ListApiKeysRequest]) (*connect.Response[adminv1.ListApiKeysResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	all, err := s.d.Records.ListKeys(ctx, req.Msg.GetTenantId())
	if serr := s.write(ctx, id.Actor, "admin.ListApiKeys", req.Msg.GetTenantId(), err); serr != nil {
		return nil, fail(serr)
	}
	page, next := paginate(all, req.Msg.GetPage(), func(k records.APIKey) string { return k.ID })
	res := &adminv1.ListApiKeysResponse{Page: &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(all))}}
	for _, k := range page {
		res.Keys = append(res.Keys, keyProto(k))
	}
	return connect.NewResponse(res), nil
}

// RevokeApiKey implements AdminServiceHandler.
//
//nolint:staticcheck // ST1003: the generated Connect interface fixes this name
func (s *Service) RevokeApiKey(ctx context.Context, req *connect.Request[adminv1.RevokeApiKeyRequest]) (*connect.Response[adminv1.RevokeApiKeyResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	_, err = s.d.Records.RevokeKey(ctx, req.Msg.GetId())
	if serr := s.write(ctx, id.Actor, "admin.RevokeApiKey", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.RevokeApiKeyResponse{}), nil
}

// GetServiceHealth implements AdminServiceHandler. It probes the readyz
// endpoint of every configured service.
func (s *Service) GetServiceHealth(ctx context.Context, req *connect.Request[adminv1.GetServiceHealthRequest]) (*connect.Response[adminv1.GetServiceHealthResponse], error) {
	if _, err := s.guard(ctx, req.Header()); err != nil {
		return nil, err
	}
	targets := make([]health.Target, 0, len(s.d.Cfg.Targets()))
	for _, t := range s.d.Cfg.Targets() {
		targets = append(targets, health.Target{Name: t.Name, URL: t.ReadyzURL()})
	}
	res := &adminv1.GetServiceHealthResponse{}
	for _, r := range s.d.Health.CheckAll(ctx, targets) {
		res.Services = append(res.Services, &adminv1.GetServiceHealthResponse_ServiceHealth{
			Name: r.Name, Version: r.Version, Ready: r.Ready,
			CheckedAt: timestamppb.New(r.CheckedAt), Error: r.Error,
		})
	}
	return connect.NewResponse(res), nil
}

// QueryAuditLog implements AdminServiceHandler.
func (s *Service) QueryAuditLog(ctx context.Context, req *connect.Request[adminv1.QueryAuditLogRequest]) (*connect.Response[adminv1.QueryAuditLogResponse], error) {
	if _, err := s.guard(ctx, req.Header()); err != nil {
		return nil, err
	}
	f := auditlog.Filter{
		Actor:     req.Msg.GetActor(),
		Action:    req.Msg.GetAction(),
		PageSize:  pageSize(req.Msg.GetPage()),
		PageToken: req.Msg.GetPage().GetPageToken(),
	}
	if req.Msg.GetFrom() != nil {
		f.From = req.Msg.GetFrom().AsTime()
	}
	if req.Msg.GetTo() != nil {
		f.To = req.Msg.GetTo().AsTime()
	}
	page, err := s.d.Audit.Query(ctx, f)
	if err != nil {
		return nil, fail(err)
	}
	res := &adminv1.QueryAuditLogResponse{Page: &commonv1.PageResult{
		NextPageToken: page.NextPageToken, TotalSize: int64(page.TotalSize),
	}}
	for _, r := range page.Records {
		res.Records = append(res.Records, &adminv1.AuditRecord{
			Id: r.ID, At: timestamppb.New(r.At), Actor: r.Actor, Action: r.Action,
			RequestId: r.RequestID, Target: r.Target, Ok: r.OK,
		})
	}
	return connect.NewResponse(res), nil
}

// OnboardAdmin implements AdminServiceHandler. The caller sends the one
// time bootstrap token and an ID token from an OIDC login (ADR-010
// decision 4). The RPC needs no session, because no admin exists yet.
func (s *Service) OnboardAdmin(ctx context.Context, req *connect.Request[adminv1.OnboardAdminRequest]) (*connect.Response[adminv1.OnboardAdminResponse], error) {
	admin, err := s.d.Login.OnboardAdmin(ctx, req.Msg.GetProviderId(), req.Msg.GetIdToken(), req.Msg.GetBootstrapToken())
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&adminv1.OnboardAdminResponse{Issuer: admin.Issuer, Subject: admin.Subject}), nil
}

// ListCommands implements AdminServiceHandler. The list is the help
// source of the CLI, the man pages, and the portal help page.
func (s *Service) ListCommands(_ context.Context, _ *connect.Request[adminv1.ListCommandsRequest]) (*connect.Response[adminv1.ListCommandsResponse], error) {
	return connect.NewResponse(&adminv1.ListCommandsResponse{Commands: Commands()}), nil
}

// paginate returns one page of items and the token of the next page.
// The token is the id of the last item in the page.
func paginate[T any](all []T, page *commonv1.Pagination, idOf func(T) string) ([]T, string) {
	size := pageSize(page)
	start := 0
	if token := page.GetPageToken(); token != "" {
		start = len(all)
		for i, item := range all {
			if idOf(item) == token {
				start = i + 1
				break
			}
		}
	}
	if start >= len(all) {
		return nil, ""
	}
	end := start + size
	if end >= len(all) {
		return all[start:], ""
	}
	return all[start:end], idOf(all[end-1])
}

// pageSize returns the page size of a request inside the limits.
func pageSize(page *commonv1.Pagination) int {
	size := int(page.GetPageSize())
	if size <= 0 {
		return DefaultPageSize
	}
	if size > MaxPageSize {
		return MaxPageSize
	}
	return size
}

// keyProto converts an API key record into its message. The hash never
// leaves the service.
func keyProto(k records.APIKey) *adminv1.ApiKey {
	if k.ID == "" {
		return nil
	}
	m := &adminv1.ApiKey{
		Id: k.ID, DisplayName: k.DisplayName, TenantId: k.TenantID, Prefix: k.Prefix,
		Roles: roleValues(k.Roles), CreatedAt: timestamppb.New(k.CreatedAt),
	}
	if !k.ExpiresAt.IsZero() {
		m.ExpiresAt = timestamppb.New(k.ExpiresAt)
	}
	if !k.RevokedAt.IsZero() {
		m.RevokedAt = timestamppb.New(k.RevokedAt)
	}
	return m
}

// stateName returns the record state of a message state.
func stateName(s adminv1.Tenant_State) string {
	switch s {
	case adminv1.Tenant_STATE_ACTIVE:
		return records.StateActive
	case adminv1.Tenant_STATE_SUSPENDED:
		return records.StateSuspended
	}
	return ""
}

// stateValue returns the message state of a record state.
func stateValue(s string) adminv1.Tenant_State {
	switch s {
	case records.StateActive:
		return adminv1.Tenant_STATE_ACTIVE
	case records.StateSuspended:
		return adminv1.Tenant_STATE_SUSPENDED
	}
	return adminv1.Tenant_STATE_UNSPECIFIED
}

// roleNames returns the record names of message roles.
func roleNames(roles []commonv1.Role) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if name := RoleName(r); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// roleValues returns the message roles of record names.
func roleValues(names []string) []commonv1.Role {
	out := make([]commonv1.Role, 0, len(names))
	for _, n := range names {
		if v := RoleValue(n); v != commonv1.Role_ROLE_UNSPECIFIED {
			out = append(out, v)
		}
	}
	return out
}

// RoleName returns the name of a deployment role (ADR-007).
func RoleName(r commonv1.Role) string {
	switch r {
	case commonv1.Role_ROLE_ISSUER:
		return "issuer"
	case commonv1.Role_ROLE_HOLDER:
		return "holder"
	case commonv1.Role_ROLE_VERIFIER:
		return "verifier"
	case commonv1.Role_ROLE_ADMIN:
		return "admin"
	}
	return ""
}

// RoleValue returns the value of a role name.
func RoleValue(name string) commonv1.Role {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "issuer":
		return commonv1.Role_ROLE_ISSUER
	case "holder":
		return commonv1.Role_ROLE_HOLDER
	case "verifier":
		return commonv1.Role_ROLE_VERIFIER
	case "admin":
		return commonv1.Role_ROLE_ADMIN
	}
	return commonv1.Role_ROLE_UNSPECIFIED
}

// identifierText returns the reader facing identifier of a trust entry.
func identifierText(id *trustv1.TrustEntry_Identifier) string {
	if id.GetDid() != "" {
		return id.GetDid()
	}
	return id.GetX509Subject()
}
