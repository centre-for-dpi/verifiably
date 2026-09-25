// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
)

// clientCredentials is the feature a stack lists when its tenants hold
// client credentials.
const clientCredentials = backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS

// ListStackCredentials implements AdminServiceHandler. It reads the
// client credentials of every stack tenant on a stack that lists tenant
// client credentials (ADR-038 decision 2). A stack tenant that the
// adapter cannot read adds one line to errors.
func (s *Service) ListStackCredentials(ctx context.Context, req *connect.Request[adminv1.ListStackCredentialsRequest]) (*connect.Response[adminv1.ListStackCredentialsResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	res, err := s.listStackCredentials(ctx, req.Msg.GetTenantId())
	if serr := s.write(ctx, id.Actor, "admin.ListStackCredentials", req.Msg.GetTenantId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(res), nil
}

// listStackCredentials does the work of ListStackCredentials.
func (s *Service) listStackCredentials(ctx context.Context, tenantID string) (*adminv1.ListStackCredentialsResponse, error) {
	all, err := s.d.Records.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	offered := map[configv1.Dpg]stacks.Stack{}
	for _, st := range s.d.Stacks.List(ctx) {
		if st.Has(clientCredentials) {
			offered[st.Dpg] = st
		}
	}
	res := &adminv1.ListStackCredentialsResponse{}
	for _, t := range all {
		if tenantID != "" && t.ID != tenantID {
			continue
		}
		for _, b := range t.Bindings {
			st, ok := offered[dpgValue(b.Stack)]
			if !ok {
				continue
			}
			list, lerr := s.d.Stacks.Tenants(st).ListClientCredentials(ctx, connect.NewRequest(&backendv1.ListClientCredentialsRequest{TenantId: b.TenantID}))
			if lerr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s on %s: %v", t.DisplayName, st.Name, lerr))
				continue
			}
			for _, c := range list.Msg.GetCredentials() {
				res.Credentials = append(res.Credentials, &adminv1.StackCredential{
					TenantId: t.ID, Stack: st.Dpg, StackName: st.Name, Credential: c,
				})
			}
		}
	}
	return res, nil
}

// CreateStackCredential implements AdminServiceHandler. The secret goes
// to the caller once. The service keeps no copy and the audit record
// names the credential id only.
func (s *Service) CreateStackCredential(ctx context.Context, req *connect.Request[adminv1.CreateStackCredentialRequest]) (*connect.Response[adminv1.CreateStackCredentialResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	res, err := s.createStackCredential(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.CreateStackCredential", res.GetCredential().GetCredential().GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(res), nil
}

// createStackCredential does the work of CreateStackCredential.
func (s *Service) createStackCredential(ctx context.Context, m *adminv1.CreateStackCredentialRequest) (*adminv1.CreateStackCredentialResponse, error) {
	name := strings.TrimSpace(m.GetDisplayName())
	if name == "" || len(name) > records.MaxDisplayName {
		return nil, fmt.Errorf("%w: the credential needs a name of at most %d characters", records.ErrInvalid, records.MaxDisplayName)
	}
	st, b, err := s.credentialStack(ctx, m.GetTenantId(), m.GetStack())
	if err != nil {
		return nil, err
	}
	res, err := s.d.Stacks.Tenants(st).CreateClientCredential(ctx, connect.NewRequest(&backendv1.CreateClientCredentialRequest{TenantId: b.TenantID, Name: name}))
	if err != nil {
		return nil, stackError(st, "create the client credential", err)
	}
	return &adminv1.CreateStackCredentialResponse{
		Credential: &adminv1.StackCredential{
			TenantId: m.GetTenantId(), Stack: st.Dpg, StackName: st.Name, Credential: res.Msg.GetCredential(),
		},
		ClientSecret: res.Msg.GetClientSecret(),
	}, nil
}

// DeleteStackCredential implements AdminServiceHandler.
func (s *Service) DeleteStackCredential(ctx context.Context, req *connect.Request[adminv1.DeleteStackCredentialRequest]) (*connect.Response[adminv1.DeleteStackCredentialResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	err = s.deleteStackCredential(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.DeleteStackCredential", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.DeleteStackCredentialResponse{}), nil
}

// deleteStackCredential does the work of DeleteStackCredential.
func (s *Service) deleteStackCredential(ctx context.Context, m *adminv1.DeleteStackCredentialRequest) error {
	st, b, err := s.credentialStack(ctx, m.GetTenantId(), m.GetStack())
	if err != nil {
		return err
	}
	_, err = s.d.Stacks.Tenants(st).DeleteClientCredential(ctx, connect.NewRequest(&backendv1.DeleteClientCredentialRequest{TenantId: b.TenantID, Id: m.GetId()}))
	if err != nil {
		return stackError(st, "delete the client credential", err)
	}
	return nil
}

// credentialStack returns the stack and the binding of a tenant on a
// stack that lists tenant client credentials.
func (s *Service) credentialStack(ctx context.Context, tenantID string, d configv1.Dpg) (stacks.Stack, records.Binding, error) {
	tenant, err := s.d.Records.GetTenant(ctx, tenantID)
	if err != nil {
		return stacks.Stack{}, records.Binding{}, err
	}
	b, ok := tenant.Binding(d.String())
	if !ok {
		return stacks.Stack{}, records.Binding{}, fmt.Errorf("%w: the tenant has no binding on %s", records.ErrNotFound, d)
	}
	st, err := s.d.Stacks.Find(ctx, d, clientCredentials)
	if err != nil {
		return stacks.Stack{}, records.Binding{}, err
	}
	return st, b, nil
}
