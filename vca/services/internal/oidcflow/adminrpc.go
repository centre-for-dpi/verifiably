// SPDX-License-Identifier: Apache-2.0

package oidcflow

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
)

// Authorizer decides whether a request can change the registry.
// It receives the request headers. A nil error allows the call.
type Authorizer func(ctx context.Context, h http.Header) error

// BearerAuthorizer allows requests that carry "Authorization: Bearer
// <token>" with the given token. An empty token allows nothing.
func BearerAuthorizer(token string) Authorizer {
	return func(_ context.Context, h http.Header) error {
		got := strings.TrimSpace(strings.TrimPrefix(h.Get("Authorization"), "Bearer "))
		if token == "" || got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			return ErrUnauthorized
		}
		return nil
	}
}

// AnyAuthorizer allows a request that any of the given authorizers allows.
func AnyAuthorizer(list ...Authorizer) Authorizer {
	return func(ctx context.Context, h http.Header) error {
		last := ErrUnauthorized
		for _, a := range list {
			if err := a(ctx, h); err == nil {
				return nil
			} else {
				last = err
			}
		}
		return last
	}
}

// AdminProviders serves the provider RPCs of vca.admin.v1.AdminService
// on top of a Registry (ADR-012 decision 5). The other admin RPCs return
// CodeUnimplemented. A service mounts it with NewAdminHandler.
type AdminProviders struct {
	adminv1connect.UnimplementedAdminServiceHandler
	Registry  *Registry
	Authorize Authorizer
	// Roles, when set, replaces the roles of every provider it stores,
	// so an issuer deployment holds only issuer providers.
	Roles []string
	// InternalAuthority, when set, is applied to every provider it
	// stores, for split horizon deployments (ADR-012 decision 6).
	InternalAuthority string
}

func (a AdminProviders) apply(p Provider) Provider {
	if a.Roles != nil {
		p.Roles = a.Roles
	}
	if a.InternalAuthority != "" {
		p.InternalAuthority = a.InternalAuthority
	}
	return p
}

// NewAdminHandler returns the Connect path and handler.
func NewAdminHandler(svc adminv1connect.AdminServiceHandler) (string, http.Handler) {
	return adminv1connect.NewAdminServiceHandler(svc)
}

func (a AdminProviders) auth(ctx context.Context, h http.Header) error {
	if a.Authorize == nil {
		return connect.NewError(connect.CodeUnauthenticated, ErrUnauthorized)
	}
	if err := a.Authorize(ctx, h); err != nil {
		return ConnectError(err)
	}
	return nil
}

// CreateAuthProvider implements AdminServiceHandler.
func (a AdminProviders) CreateAuthProvider(ctx context.Context, req *connect.Request[adminv1.CreateAuthProviderRequest]) (*connect.Response[adminv1.CreateAuthProviderResponse], error) {
	if err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	if req.Msg.GetDynamicRegistration() {
		return nil, connect.NewError(connect.CodeUnimplemented, wrap(ErrInvalidProvider, "dynamic client registration is not supported here"))
	}
	p := a.apply(FromAdminProto(req.Msg.GetProvider()))
	p.ID = ""
	stored, err := a.Registry.Put(p)
	if err != nil {
		return nil, ConnectError(err)
	}
	return connect.NewResponse(&adminv1.CreateAuthProviderResponse{Provider: ToAdminProto(stored)}), nil
}

// GetAuthProvider implements AdminServiceHandler.
func (a AdminProviders) GetAuthProvider(ctx context.Context, req *connect.Request[adminv1.GetAuthProviderRequest]) (*connect.Response[adminv1.GetAuthProviderResponse], error) {
	if err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	p, err := a.Registry.Get(req.Msg.GetId())
	if err != nil {
		return nil, ConnectError(err)
	}
	return connect.NewResponse(&adminv1.GetAuthProviderResponse{Provider: ToAdminProto(p)}), nil
}

// ListAuthProviders implements AdminServiceHandler. It returns one page.
func (a AdminProviders) ListAuthProviders(ctx context.Context, req *connect.Request[adminv1.ListAuthProvidersRequest]) (*connect.Response[adminv1.ListAuthProvidersResponse], error) {
	if err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	list := a.Registry.List()
	res := &adminv1.ListAuthProvidersResponse{Page: &commonv1.PageResult{TotalSize: int64(len(list))}}
	for _, p := range list {
		res.Providers = append(res.Providers, ToAdminProto(p))
	}
	return connect.NewResponse(res), nil
}

// UpdateAuthProvider implements AdminServiceHandler.
func (a AdminProviders) UpdateAuthProvider(ctx context.Context, req *connect.Request[adminv1.UpdateAuthProviderRequest]) (*connect.Response[adminv1.UpdateAuthProviderResponse], error) {
	if err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	p := a.apply(FromAdminProto(req.Msg.GetProvider()))
	if _, err := a.Registry.Get(p.ID); err != nil {
		return nil, ConnectError(err)
	}
	stored, err := a.Registry.Put(p)
	if err != nil {
		return nil, ConnectError(err)
	}
	return connect.NewResponse(&adminv1.UpdateAuthProviderResponse{Provider: ToAdminProto(stored)}), nil
}

// DeleteAuthProvider implements AdminServiceHandler.
func (a AdminProviders) DeleteAuthProvider(ctx context.Context, req *connect.Request[adminv1.DeleteAuthProviderRequest]) (*connect.Response[adminv1.DeleteAuthProviderResponse], error) {
	if err := a.auth(ctx, req.Header()); err != nil {
		return nil, err
	}
	if err := a.Registry.Delete(req.Msg.GetId()); err != nil {
		return nil, ConnectError(err)
	}
	return connect.NewResponse(&adminv1.DeleteAuthProviderResponse{}), nil
}
