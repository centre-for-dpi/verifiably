// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
)

// Agent type names of a binding record.
const (
	agentShared    = "shared"
	agentDedicated = "dedicated"
)

// tenancy is the feature a stack lists when it separates tenants.
const tenancy = backendv1.Feature_FEATURE_MULTI_TENANCY

// CreateTenant implements AdminServiceHandler. It creates the tenant on
// every stack the request names too, and records one binding per stack
// (ADR-037 decision 1). It checks every stack first. When a stack fails,
// the service removes what it made, so no half made tenant stays.
func (s *Service) CreateTenant(ctx context.Context, req *connect.Request[adminv1.CreateTenantRequest]) (*connect.Response[adminv1.CreateTenantResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	tenant, err := s.createTenant(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.CreateTenant", tenant.ID, err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.CreateTenantResponse{Tenant: tenantProto(tenant)}), nil
}

// createTenant does the work of CreateTenant.
func (s *Service) createTenant(ctx context.Context, m *adminv1.CreateTenantRequest) (records.Tenant, error) {
	var targets []stacks.Stack
	seen := map[configv1.Dpg]bool{}
	for _, d := range m.GetStacks() {
		if seen[d] {
			continue
		}
		seen[d] = true
		st, err := s.d.Stacks.Find(ctx, d, tenancy)
		if err != nil {
			return records.Tenant{}, err
		}
		targets = append(targets, st)
	}
	tenant, err := s.d.Records.CreateTenant(ctx, m.GetDisplayName())
	if err != nil {
		return records.Tenant{}, err
	}
	for _, st := range targets {
		b, berr := s.bindStack(ctx, st, tenant.DisplayName, m.GetAgentType())
		if berr != nil {
			s.rollback(ctx, tenant)
			return records.Tenant{}, berr
		}
		bound, berr := s.d.Records.AddBinding(ctx, tenant.ID, b)
		if berr != nil {
			tenant.Bindings = append(tenant.Bindings, b)
			s.rollback(ctx, tenant)
			return records.Tenant{}, berr
		}
		tenant = bound
	}
	return tenant, nil
}

// rollback removes the stack tenants and the record of a tenant whose
// creation failed. It runs as far as it can: the create error is what
// the caller sees.
func (s *Service) rollback(ctx context.Context, tenant records.Tenant) {
	for _, b := range tenant.Bindings {
		anyval.Discard(s.unbindStack(ctx, b))
	}
	anyval.Discard(s.d.Records.DeleteTenant(ctx, tenant.ID))
}

// GetTenant implements AdminServiceHandler. It reads each stack tenant
// again, so the page shows the DIDs the stack holds now. A stack that
// does not answer leaves the stored values and a reason.
func (s *Service) GetTenant(ctx context.Context, req *connect.Request[adminv1.GetTenantRequest]) (*connect.Response[adminv1.GetTenantResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	tenant, err := s.d.Records.GetTenant(ctx, req.Msg.GetId())
	if serr := s.write(ctx, id.Actor, "admin.GetTenant", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	m := tenantProto(tenant)
	for _, b := range m.GetBindings() {
		s.refresh(ctx, b)
	}
	return connect.NewResponse(&adminv1.GetTenantResponse{Tenant: m}), nil
}

// refresh reads the stack tenant of one binding into the message.
func (s *Service) refresh(ctx context.Context, b *adminv1.TenantBinding) {
	st, err := s.d.Stacks.Find(ctx, b.GetStack(), tenancy)
	if err != nil {
		b.Error = err.Error()
		return
	}
	res, err := s.d.Stacks.Tenants(st).GetTenant(ctx, connect.NewRequest(&backendv1.GetTenantRequest{Id: b.GetTenant().GetId()}))
	if err != nil {
		b.Error = err.Error()
		return
	}
	if t := res.Msg.GetTenant(); t.GetId() != "" {
		b.Tenant = t
	}
}

// ListTenants implements AdminServiceHandler. The list carries the
// stored bindings and calls no stack.
func (s *Service) ListTenants(ctx context.Context, req *connect.Request[adminv1.ListTenantsRequest]) (*connect.Response[adminv1.ListTenantsResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	all, err := s.d.Records.ListTenants(ctx)
	if serr := s.write(ctx, id.Actor, "admin.ListTenants", "", err); serr != nil {
		return nil, fail(serr)
	}
	page, next := paginate(all, req.Msg.GetPage(), func(t records.Tenant) string { return t.ID })
	res := &adminv1.ListTenantsResponse{Page: &commonv1.PageResult{NextPageToken: next, TotalSize: int64(len(all))}}
	for _, t := range page {
		res.Tenants = append(res.Tenants, tenantProto(t))
	}
	return connect.NewResponse(res), nil
}

// UpdateTenant implements AdminServiceHandler.
func (s *Service) UpdateTenant(ctx context.Context, req *connect.Request[adminv1.UpdateTenantRequest]) (*connect.Response[adminv1.UpdateTenantResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	tenant, err := s.d.Records.UpdateTenant(ctx, req.Msg.GetId(), req.Msg.GetDisplayName(), stateName(req.Msg.GetState()))
	if serr := s.write(ctx, id.Actor, "admin.UpdateTenant", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.UpdateTenantResponse{Tenant: tenantProto(tenant)}), nil
}

// DeleteTenant implements AdminServiceHandler. It deletes the tenant of
// every bound stack first. A stack that does not run keeps the tenant
// and its binding, so the admin starts the stack and deletes again.
func (s *Service) DeleteTenant(ctx context.Context, req *connect.Request[adminv1.DeleteTenantRequest]) (*connect.Response[adminv1.DeleteTenantResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	err = s.deleteTenant(ctx, req.Msg.GetId())
	if serr := s.write(ctx, id.Actor, "admin.DeleteTenant", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.DeleteTenantResponse{}), nil
}

// deleteTenant does the work of DeleteTenant.
func (s *Service) deleteTenant(ctx context.Context, id string) error {
	tenant, err := s.d.Records.GetTenant(ctx, id)
	if err != nil {
		return err
	}
	for _, b := range tenant.Bindings {
		if err := s.unbindStack(ctx, b); err != nil {
			return err
		}
		if _, err := s.d.Records.RemoveBinding(ctx, id, b.Stack); err != nil {
			return err
		}
	}
	return s.d.Records.DeleteTenant(ctx, id)
}

// BindTenant implements AdminServiceHandler.
func (s *Service) BindTenant(ctx context.Context, req *connect.Request[adminv1.BindTenantRequest]) (*connect.Response[adminv1.BindTenantResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	tenant, err := s.bindTenant(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.BindTenant", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.BindTenantResponse{Tenant: tenantProto(tenant)}), nil
}

// bindTenant does the work of BindTenant.
func (s *Service) bindTenant(ctx context.Context, m *adminv1.BindTenantRequest) (records.Tenant, error) {
	tenant, err := s.d.Records.GetTenant(ctx, m.GetId())
	if err != nil {
		return records.Tenant{}, err
	}
	if _, ok := tenant.Binding(m.GetStack().String()); ok {
		return records.Tenant{}, fmt.Errorf("%w: the tenant is bound on %s", records.ErrExists, m.GetStack())
	}
	st, err := s.d.Stacks.Find(ctx, m.GetStack(), tenancy)
	if err != nil {
		return records.Tenant{}, err
	}
	b, err := s.bindStack(ctx, st, tenant.DisplayName, m.GetAgentType())
	if err != nil {
		return records.Tenant{}, err
	}
	bound, err := s.d.Records.AddBinding(ctx, tenant.ID, b)
	if err != nil {
		anyval.Discard(s.unbindStack(ctx, b))
		return records.Tenant{}, err
	}
	return bound, nil
}

// UnbindTenant implements AdminServiceHandler.
func (s *Service) UnbindTenant(ctx context.Context, req *connect.Request[adminv1.UnbindTenantRequest]) (*connect.Response[adminv1.UnbindTenantResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	tenant, err := s.unbindTenant(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.UnbindTenant", req.Msg.GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.UnbindTenantResponse{Tenant: tenantProto(tenant)}), nil
}

// unbindTenant does the work of UnbindTenant.
func (s *Service) unbindTenant(ctx context.Context, m *adminv1.UnbindTenantRequest) (records.Tenant, error) {
	tenant, err := s.d.Records.GetTenant(ctx, m.GetId())
	if err != nil {
		return records.Tenant{}, err
	}
	b, ok := tenant.Binding(m.GetStack().String())
	if !ok {
		return records.Tenant{}, fmt.Errorf("%w: the tenant has no binding on %s", records.ErrNotFound, m.GetStack())
	}
	if err := s.unbindStack(ctx, b); err != nil {
		return records.Tenant{}, err
	}
	return s.d.Records.RemoveBinding(ctx, tenant.ID, b.Stack)
}

// bindStack creates the tenant on one stack and returns the binding.
func (s *Service) bindStack(ctx context.Context, st stacks.Stack, name string, agent backendv1.DpgTenant_AgentType) (records.Binding, error) {
	res, err := s.d.Stacks.Tenants(st).CreateTenant(ctx, connect.NewRequest(&backendv1.CreateTenantRequest{Name: name, AgentType: agent}))
	if err != nil {
		return records.Binding{}, stackError(st, "create the tenant", err)
	}
	t := res.Msg.GetTenant()
	if t.GetId() == "" {
		return records.Binding{}, stackError(st, "create the tenant", errors.New("the answer names no tenant id"))
	}
	if t.GetAgentType() != backendv1.DpgTenant_AGENT_TYPE_UNSPECIFIED {
		agent = t.GetAgentType()
	}
	return records.Binding{
		Stack: st.Dpg.String(), StackName: st.Name, TenantID: t.GetId(), Name: t.GetName(),
		AgentType: agentName(agent), DIDs: t.GetDids(),
	}, nil
}

// unbindStack deletes the tenant of one binding on its stack. A stack
// that no longer knows the tenant counts as done.
func (s *Service) unbindStack(ctx context.Context, b records.Binding) error {
	st, err := s.d.Stacks.Find(ctx, dpgValue(b.Stack), tenancy)
	if err != nil {
		return err
	}
	_, err = s.d.Stacks.Tenants(st).DeleteTenant(ctx, connect.NewRequest(&backendv1.DeleteTenantRequest{Id: b.TenantID}))
	if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		return stackError(st, "delete the tenant", err)
	}
	return nil
}

// stackError names the stack in an adapter error and keeps its code.
func stackError(st stacks.Stack, action string, err error) error {
	return connect.NewError(connect.CodeOf(err), fmt.Errorf("service: %s on the stack %s: %w", action, st.Name, err))
}

// tenantProto converts a tenant record into its message.
func tenantProto(t records.Tenant) *adminv1.Tenant {
	if t.ID == "" {
		return nil
	}
	m := &adminv1.Tenant{
		Id: t.ID, DisplayName: t.DisplayName, State: stateValue(t.State),
		CreatedAt: timestamppb.New(t.CreatedAt), UpdatedAt: timestamppb.New(t.UpdatedAt),
	}
	for _, b := range t.Bindings {
		m.Bindings = append(m.Bindings, &adminv1.TenantBinding{
			Stack: dpgValue(b.Stack), StackName: b.StackName, BoundAt: timestamppb.New(b.BoundAt),
			Tenant: &backendv1.DpgTenant{Id: b.TenantID, Name: b.Name, AgentType: agentValue(b.AgentType), Dids: b.DIDs},
		})
	}
	return m
}

// dpgValue returns the enum value of a stored stack name.
func dpgValue(name string) configv1.Dpg { return configv1.Dpg(configv1.Dpg_value[name]) }

// agentName returns the record name of an agent type.
func agentName(a backendv1.DpgTenant_AgentType) string {
	switch a {
	case backendv1.DpgTenant_AGENT_TYPE_SHARED:
		return agentShared
	case backendv1.DpgTenant_AGENT_TYPE_DEDICATED:
		return agentDedicated
	}
	return ""
}

// agentValue returns the message value of a record agent type.
func agentValue(name string) backendv1.DpgTenant_AgentType {
	switch name {
	case agentShared:
		return backendv1.DpgTenant_AGENT_TYPE_SHARED
	case agentDedicated:
		return backendv1.DpgTenant_AGENT_TYPE_DEDICATED
	}
	return backendv1.DpgTenant_AGENT_TYPE_UNSPECIFIED
}
