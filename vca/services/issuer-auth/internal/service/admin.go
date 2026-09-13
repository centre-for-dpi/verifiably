// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/roles"
)

// Admin serves the provider and API key RPCs of vca.admin.v1.AdminService
// for this deployment. An API key is a machine client for the client
// credentials grant (ADR-012 decision 4).
type Admin struct {
	oidcflow.AdminProviders
	svc *Service
}

// Admin returns the admin RPC handler of the service.
func (s *Service) Admin() Admin {
	return Admin{
		AdminProviders: oidcflow.AdminProviders{Registry: s.d.Providers, Authorize: s.AdminAuthorizer(), Roles: []string{"issuer"}, InternalAuthority: s.cfg.ProviderInternalAuthority},
		svc:            s,
	}
}

// MachineRoles maps the deployment roles of an API key to issuer roles:
// admin gives issuer-admin, issuer gives issuer-operator, and every
// other role gives issuer-viewer.
func MachineRoles(rs []commonv1.Role) []string {
	set := map[string]bool{}
	for _, r := range rs {
		switch r {
		case commonv1.Role_ROLE_ADMIN:
			set[roles.Admin] = true
		case commonv1.Role_ROLE_ISSUER:
			set[roles.Operator] = true
		default:
			set[roles.Viewer] = true
		}
	}
	var out []string
	for _, r := range []string{roles.Admin, roles.Operator, roles.Viewer} {
		if set[r] {
			out = append(out, r)
		}
	}
	return out
}

func machineRolesToProto(names []string) []commonv1.Role {
	var out []commonv1.Role
	for _, n := range names {
		switch n {
		case roles.Admin:
			out = append(out, commonv1.Role_ROLE_ADMIN)
		case roles.Operator:
			out = append(out, commonv1.Role_ROLE_ISSUER)
		default:
			out = append(out, commonv1.Role_ROLE_VERIFIER)
		}
	}
	return out
}

func clientToProto(c clients.Client) *adminv1.ApiKey {
	k := &adminv1.ApiKey{
		Id:          c.ID,
		DisplayName: c.DisplayName,
		TenantId:    c.TenantID,
		Roles:       machineRolesToProto(c.Roles),
		CreatedAt:   timestamppb.New(c.CreatedAt),
		Prefix:      c.Prefix,
	}
	if c.ExpiresAt != nil {
		k.ExpiresAt = timestamppb.New(*c.ExpiresAt)
	}
	if c.RevokedAt != nil {
		k.RevokedAt = timestamppb.New(*c.RevokedAt)
	}
	return k
}

// CreateApiKey implements AdminServiceHandler.
func (a Admin) CreateApiKey(ctx context.Context, req *connect.Request[adminv1.CreateApiKeyRequest]) (*connect.Response[adminv1.CreateApiKeyResponse], error) {
	if err := a.Authorize(ctx, req.Header()); err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	var exp *time.Time
	if req.Msg.GetExpiresAt() != nil {
		t := req.Msg.GetExpiresAt().AsTime()
		exp = &t
	}
	tenant := req.Msg.GetTenantId()
	if tenant == "" {
		tenant = a.svc.cfg.TenantID
	}
	c, secret, err := a.svc.d.Clients.Create(req.Msg.GetDisplayName(), tenant, MachineRoles(req.Msg.GetRoles()), exp)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	return connect.NewResponse(&adminv1.CreateApiKeyResponse{Key: clientToProto(c), Secret: secret}), nil
}

// ListApiKeys implements AdminServiceHandler.
func (a Admin) ListApiKeys(ctx context.Context, req *connect.Request[adminv1.ListApiKeysRequest]) (*connect.Response[adminv1.ListApiKeysResponse], error) {
	if err := a.Authorize(ctx, req.Header()); err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	list := a.svc.d.Clients.List(req.Msg.GetTenantId())
	res := &adminv1.ListApiKeysResponse{Page: &commonv1.PageResult{TotalSize: int64(len(list))}}
	for _, c := range list {
		res.Keys = append(res.Keys, clientToProto(c))
	}
	return connect.NewResponse(res), nil
}

// RevokeApiKey implements AdminServiceHandler.
func (a Admin) RevokeApiKey(ctx context.Context, req *connect.Request[adminv1.RevokeApiKeyRequest]) (*connect.Response[adminv1.RevokeApiKeyResponse], error) {
	if err := a.Authorize(ctx, req.Header()); err != nil {
		return nil, oidcflow.ConnectError(err)
	}
	if err := a.svc.d.Clients.Revoke(req.Msg.GetId()); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&adminv1.RevokeApiKeyResponse{}), nil
}
