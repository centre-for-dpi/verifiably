// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
)

// ecosystemsFeature is the feature a stack lists when it groups its
// tenants into ecosystems (ADR-068).
const ecosystemsFeature = backendv1.Feature_FEATURE_ECOSYSTEMS

// ListStackEcosystems implements AdminServiceHandler. It reads the
// switch of every stack that lists ecosystems and, where the switch is
// on, the ecosystems of each bound tenant, each ecosystem once with its
// members. A call that fails adds one line to the answer.
func (s *Service) ListStackEcosystems(ctx context.Context, req *connect.Request[adminv1.ListStackEcosystemsRequest]) (*connect.Response[adminv1.ListStackEcosystemsResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	res, err := s.listStackEcosystems(ctx)
	if serr := s.write(ctx, id.Actor, "admin.ListStackEcosystems", "", err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(res), nil
}

// tenantIndex maps the stack tenant ids of one stack onto VCA tenants.
type tenantIndex map[string]records.Tenant

// bound returns the VCA tenants bound on one stack by their stack tenant
// id.
func bound(all []records.Tenant, d configv1.Dpg) tenantIndex {
	out := tenantIndex{}
	for _, t := range all {
		if b, ok := t.Binding(d.String()); ok {
			out[b.TenantID] = t
		}
	}
	return out
}

// listStackEcosystems does the work of ListStackEcosystems.
func (s *Service) listStackEcosystems(ctx context.Context) (*adminv1.ListStackEcosystemsResponse, error) {
	all, err := s.d.Records.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	res := &adminv1.ListStackEcosystemsResponse{}
	for _, st := range s.d.Stacks.List(ctx) {
		if !st.Has(ecosystemsFeature) {
			continue
		}
		entry := &adminv1.EcosystemStack{Stack: st.Dpg, StackName: st.Name}
		res.Stacks = append(res.Stacks, entry)
		got, gerr := s.d.Stacks.Tenants(st).GetEcosystemSettings(ctx, connect.NewRequest(&backendv1.GetEcosystemSettingsRequest{}))
		if gerr != nil {
			entry.Error = gerr.Error()
			continue
		}
		entry.Enabled = got.Msg.GetEnabled()
		if entry.Enabled {
			s.addEcosystems(ctx, st, bound(all, st.Dpg), res)
		}
	}
	return res, nil
}

// addEcosystems adds the ecosystems of the bound tenants of one stack,
// each once, with their members.
func (s *Service) addEcosystems(ctx context.Context, st stacks.Stack, index tenantIndex, res *adminv1.ListStackEcosystemsResponse) {
	client := s.d.Stacks.Tenants(st)
	seen := map[string]bool{}
	for _, stackTenant := range slices.Sorted(maps.Keys(index)) {
		t := index[stackTenant]
		list, err := client.ListEcosystems(ctx, connect.NewRequest(&backendv1.ListEcosystemsRequest{TenantId: stackTenant}))
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s on %s: %v", t.DisplayName, st.Name, err))
			continue
		}
		for _, e := range list.Msg.GetEcosystems() {
			if seen[e.GetId()] {
				continue
			}
			seen[e.GetId()] = true
			entry := &adminv1.StackEcosystem{Stack: st.Dpg, StackName: st.Name, Ecosystem: e, LeadTenantId: index[e.GetLeadTenantId()].ID}
			members, merr := client.ListEcosystemMembers(ctx, connect.NewRequest(&backendv1.ListEcosystemMembersRequest{EcosystemId: e.GetId()}))
			if merr != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("%s on %s: %v", e.GetName(), st.Name, merr))
			}
			for _, m := range members.Msg.GetMembers() {
				entry.Members = append(entry.Members, &adminv1.StackEcosystemMember{TenantId: index[m.GetTenantId()].ID, Member: m})
			}
			res.Ecosystems = append(res.Ecosystems, entry)
		}
	}
}

// SetStackEcosystems implements AdminServiceHandler.
func (s *Service) SetStackEcosystems(ctx context.Context, req *connect.Request[adminv1.SetStackEcosystemsRequest]) (*connect.Response[adminv1.SetStackEcosystemsResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	res, err := s.setStackEcosystems(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.SetStackEcosystems", req.Msg.GetStack().String(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.SetStackEcosystemsResponse{Stack: res}), nil
}

// setStackEcosystems does the work of SetStackEcosystems.
func (s *Service) setStackEcosystems(ctx context.Context, m *adminv1.SetStackEcosystemsRequest) (*adminv1.EcosystemStack, error) {
	st, err := s.d.Stacks.Find(ctx, m.GetStack(), ecosystemsFeature)
	if err != nil {
		return nil, err
	}
	res, err := s.d.Stacks.Tenants(st).SetEcosystemSettings(ctx, connect.NewRequest(&backendv1.SetEcosystemSettingsRequest{Enabled: m.GetEnabled()}))
	if err != nil {
		return nil, stackError(st, "set the ecosystem switch", err)
	}
	return &adminv1.EcosystemStack{Stack: st.Dpg, StackName: st.Name, Enabled: res.Msg.GetEnabled()}, nil
}

// ecosystemStack returns the stack and the binding of a tenant on a
// stack that lists ecosystems.
func (s *Service) ecosystemStack(ctx context.Context, tenantID string, d configv1.Dpg) (stacks.Stack, records.Binding, error) {
	tenant, err := s.d.Records.GetTenant(ctx, tenantID)
	if err != nil {
		return stacks.Stack{}, records.Binding{}, err
	}
	b, ok := tenant.Binding(d.String())
	if !ok {
		return stacks.Stack{}, records.Binding{}, fmt.Errorf("%w: the tenant has no binding on %s", records.ErrNotFound, d)
	}
	st, err := s.d.Stacks.Find(ctx, d, ecosystemsFeature)
	if err != nil {
		return stacks.Stack{}, records.Binding{}, err
	}
	return st, b, nil
}

// CreateStackEcosystem implements AdminServiceHandler.
func (s *Service) CreateStackEcosystem(ctx context.Context, req *connect.Request[adminv1.CreateStackEcosystemRequest]) (*connect.Response[adminv1.CreateStackEcosystemResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	res, err := s.createStackEcosystem(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.CreateStackEcosystem", res.GetEcosystem().GetId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.CreateStackEcosystemResponse{Ecosystem: res}), nil
}

// createStackEcosystem does the work of CreateStackEcosystem.
func (s *Service) createStackEcosystem(ctx context.Context, m *adminv1.CreateStackEcosystemRequest) (*adminv1.StackEcosystem, error) {
	name := strings.TrimSpace(m.GetName())
	if name == "" || len(name) > records.MaxDisplayName {
		return nil, fmt.Errorf("%w: the ecosystem needs a name of at most %d characters", records.ErrInvalid, records.MaxDisplayName)
	}
	st, b, err := s.ecosystemStack(ctx, m.GetLeadTenantId(), m.GetStack())
	if err != nil {
		return nil, err
	}
	res, err := s.d.Stacks.Tenants(st).CreateEcosystem(ctx, connect.NewRequest(&backendv1.CreateEcosystemRequest{
		LeadTenantId: b.TenantID, Name: name, Description: strings.TrimSpace(m.GetDescription()),
	}))
	if err != nil {
		return nil, stackError(st, "create the ecosystem", err)
	}
	return &adminv1.StackEcosystem{Stack: st.Dpg, StackName: st.Name, Ecosystem: res.Msg.GetEcosystem(), LeadTenantId: m.GetLeadTenantId()}, nil
}

// memberCall checks the fields of a member change and returns the stack
// and the binding of the tenant.
func (s *Service) memberCall(ctx context.Context, d configv1.Dpg, ecosystemID, tenantID string) (stacks.Stack, records.Binding, error) {
	if strings.TrimSpace(ecosystemID) == "" {
		return stacks.Stack{}, records.Binding{}, fmt.Errorf("%w: the call names no ecosystem", records.ErrInvalid)
	}
	return s.ecosystemStack(ctx, tenantID, d)
}

// AddStackEcosystemMember implements AdminServiceHandler.
func (s *Service) AddStackEcosystemMember(ctx context.Context, req *connect.Request[adminv1.AddStackEcosystemMemberRequest]) (*connect.Response[adminv1.AddStackEcosystemMemberResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	invited, err := s.addStackEcosystemMember(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.AddStackEcosystemMember", req.Msg.GetTenantId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.AddStackEcosystemMemberResponse{Invited: invited}), nil
}

// addStackEcosystemMember does the work of AddStackEcosystemMember.
func (s *Service) addStackEcosystemMember(ctx context.Context, m *adminv1.AddStackEcosystemMemberRequest) (bool, error) {
	st, b, err := s.memberCall(ctx, m.GetStack(), m.GetEcosystemId(), m.GetTenantId())
	if err != nil {
		return false, err
	}
	res, err := s.d.Stacks.Tenants(st).AddEcosystemMember(ctx, connect.NewRequest(&backendv1.AddEcosystemMemberRequest{
		EcosystemId: strings.TrimSpace(m.GetEcosystemId()), TenantId: b.TenantID,
	}))
	if err != nil {
		return false, stackError(st, "add the tenant to the ecosystem", err)
	}
	return res.Msg.GetInvited(), nil
}

// RemoveStackEcosystemMember implements AdminServiceHandler.
func (s *Service) RemoveStackEcosystemMember(ctx context.Context, req *connect.Request[adminv1.RemoveStackEcosystemMemberRequest]) (*connect.Response[adminv1.RemoveStackEcosystemMemberResponse], error) {
	id, err := s.guard(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	err = s.removeStackEcosystemMember(ctx, req.Msg)
	if serr := s.write(ctx, id.Actor, "admin.RemoveStackEcosystemMember", req.Msg.GetTenantId(), err); serr != nil {
		return nil, fail(serr)
	}
	return connect.NewResponse(&adminv1.RemoveStackEcosystemMemberResponse{}), nil
}

// removeStackEcosystemMember does the work of RemoveStackEcosystemMember.
func (s *Service) removeStackEcosystemMember(ctx context.Context, m *adminv1.RemoveStackEcosystemMemberRequest) error {
	st, b, err := s.memberCall(ctx, m.GetStack(), m.GetEcosystemId(), m.GetTenantId())
	if err != nil {
		return err
	}
	if _, err := s.d.Stacks.Tenants(st).RemoveEcosystemMember(ctx, connect.NewRequest(&backendv1.RemoveEcosystemMemberRequest{
		EcosystemId: strings.TrimSpace(m.GetEcosystemId()), TenantId: b.TenantID,
	})); err != nil {
		return stackError(st, "remove the tenant from the ecosystem", err)
	}
	return nil
}
