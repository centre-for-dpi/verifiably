// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
)

// fakeEcosystems is what the fake adapter keeps of the ecosystems of
// its stack: the switch, each ecosystem with its lead, and the stack
// tenant ids of the members of each.
type fakeEcosystems struct {
	on      bool
	list    []*backendv1.Ecosystem
	members map[string][]string
	// err, when set, fails every ecosystem call.
	err error
	// listErr, when set, fails every list of the ecosystems of a tenant.
	listErr error
}

func (f *fakeAdapter) GetEcosystemSettings(context.Context, *connect.Request[backendv1.GetEcosystemSettingsRequest]) (*connect.Response[backendv1.GetEcosystemSettingsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eco.err != nil {
		return nil, f.eco.err
	}
	return connect.NewResponse(&backendv1.GetEcosystemSettingsResponse{Enabled: f.eco.on}), nil
}

func (f *fakeAdapter) SetEcosystemSettings(_ context.Context, req *connect.Request[backendv1.SetEcosystemSettingsRequest]) (*connect.Response[backendv1.SetEcosystemSettingsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eco.err != nil {
		return nil, f.eco.err
	}
	f.eco.on = req.Msg.GetEnabled()
	return connect.NewResponse(&backendv1.SetEcosystemSettingsResponse{Enabled: f.eco.on}), nil
}

func (f *fakeAdapter) ListEcosystems(_ context.Context, req *connect.Request[backendv1.ListEcosystemsRequest]) (*connect.Response[backendv1.ListEcosystemsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eco.listErr != nil {
		return nil, f.eco.listErr
	}
	out := &backendv1.ListEcosystemsResponse{}
	for _, e := range f.eco.list {
		if e.GetLeadTenantId() == req.Msg.GetTenantId() || slices.Contains(f.eco.members[e.GetId()], req.Msg.GetTenantId()) {
			e.MemberCount = int32(len(f.eco.members[e.GetId()])) // #nosec G115 -- a test holds few members
			out.Ecosystems = append(out.Ecosystems, e)
		}
	}
	return connect.NewResponse(out), nil
}

func (f *fakeAdapter) CreateEcosystem(_ context.Context, req *connect.Request[backendv1.CreateEcosystemRequest]) (*connect.Response[backendv1.CreateEcosystemResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eco.err != nil {
		return nil, f.eco.err
	}
	e := &backendv1.Ecosystem{
		Id: fmt.Sprintf("eco-%d", len(f.eco.list)+1), Name: req.Msg.GetName(), Description: req.Msg.GetDescription(),
		LeadTenantId: req.Msg.GetLeadTenantId(), LeadTenantName: f.tenants[req.Msg.GetLeadTenantId()].GetName(),
	}
	f.eco.list = append(f.eco.list, e)
	return connect.NewResponse(&backendv1.CreateEcosystemResponse{Ecosystem: e}), nil
}

func (f *fakeAdapter) ListEcosystemMembers(_ context.Context, req *connect.Request[backendv1.ListEcosystemMembersRequest]) (*connect.Response[backendv1.ListEcosystemMembersResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eco.err != nil {
		return nil, f.eco.err
	}
	out := &backendv1.ListEcosystemMembersResponse{}
	for _, m := range f.eco.members[req.Msg.GetEcosystemId()] {
		out.Members = append(out.Members, &backendv1.EcosystemMember{TenantId: m, TenantName: f.tenants[m].GetName(), Status: "ACTIVE"})
	}
	return connect.NewResponse(out), nil
}

func (f *fakeAdapter) AddEcosystemMember(_ context.Context, req *connect.Request[backendv1.AddEcosystemMemberRequest]) (*connect.Response[backendv1.AddEcosystemMemberResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.eco.err != nil {
		return nil, f.eco.err
	}
	if f.eco.members == nil {
		f.eco.members = map[string][]string{}
	}
	f.eco.members[req.Msg.GetEcosystemId()] = append(f.eco.members[req.Msg.GetEcosystemId()], req.Msg.GetTenantId())
	return connect.NewResponse(&backendv1.AddEcosystemMemberResponse{}), nil
}

func (f *fakeAdapter) RemoveEcosystemMember(_ context.Context, req *connect.Request[backendv1.RemoveEcosystemMemberRequest]) (*connect.Response[backendv1.RemoveEcosystemMemberResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.eco.members[req.Msg.GetEcosystemId()]
	if !slices.Contains(list, req.Msg.GetTenantId()) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("the tenant is no member of the ecosystem"))
	}
	f.eco.members[req.Msg.GetEcosystemId()] = slices.DeleteFunc(list, func(m string) bool { return m == req.Msg.GetTenantId() })
	return connect.NewResponse(&backendv1.RemoveEcosystemMemberResponse{}), nil
}

// TestStackEcosystemRPCs is P6-C9 (ADR-068): the admin reads the
// ecosystem switch of a stack that lists ecosystems and turns it on,
// creates an ecosystem that a bound tenant leads, adds a second bound
// tenant, lists each ecosystem once with its members named by their VCA
// tenants, and removes the member. Each change writes one audit record.
func TestStackEcosystemRPCs(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h, backendv1.Feature_FEATURE_ECOSYSTEMS)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	second, err := h.svc.CreateTenant(ctx, request(h, &adminv1.CreateTenantRequest{DisplayName: "County Farm Board", Stacks: []configv1.Dpg{configv1.Dpg_DPG_CREDEBL}}))
	if err != nil {
		t.Fatal(err)
	}
	member := second.Msg.GetTenant().GetId()
	list, err := h.svc.ListStackEcosystems(ctx, request(h, &adminv1.ListStackEcosystemsRequest{}))
	if err != nil || len(list.Msg.GetStacks()) != 1 || list.Msg.GetStacks()[0].GetEnabled() || list.Msg.GetStacks()[0].GetStack() != configv1.Dpg_DPG_CREDEBL ||
		len(list.Msg.GetEcosystems()) != 0 {
		t.Fatalf("ListStackEcosystems = %+v, %v", list, err)
	}
	on, err := h.svc.SetStackEcosystems(ctx, request(h, &adminv1.SetStackEcosystemsRequest{Stack: configv1.Dpg_DPG_CREDEBL, Enabled: true}))
	if err != nil || !on.Msg.GetStack().GetEnabled() || !fake.eco.on {
		t.Fatalf("SetStackEcosystems = %+v, %v", on, err)
	}
	created, err := h.svc.CreateStackEcosystem(ctx, request(h, &adminv1.CreateStackEcosystemRequest{
		Stack: configv1.Dpg_DPG_CREDEBL, LeadTenantId: h.tenantID, Name: " Health agencies ", Description: "The agencies that issue health records.",
	}))
	if err != nil {
		t.Fatalf("CreateStackEcosystem: %v", err)
	}
	e := created.Msg.GetEcosystem()
	if e.GetLeadTenantId() != h.tenantID || e.GetEcosystem().GetLeadTenantId() != "org-1" || e.GetEcosystem().GetName() != "Health agencies" {
		t.Fatalf("created = %+v", e)
	}
	added, err := h.svc.AddStackEcosystemMember(ctx, request(h, &adminv1.AddStackEcosystemMemberRequest{
		Stack: configv1.Dpg_DPG_CREDEBL, EcosystemId: e.GetEcosystem().GetId(), TenantId: member,
	}))
	if err != nil || added.Msg.GetInvited() {
		t.Fatalf("AddStackEcosystemMember = %+v, %v", added, err)
	}
	list, err = h.svc.ListStackEcosystems(ctx, request(h, &adminv1.ListStackEcosystemsRequest{}))
	if err != nil || len(list.Msg.GetEcosystems()) != 1 || !list.Msg.GetStacks()[0].GetEnabled() {
		t.Fatalf("ListStackEcosystems = %+v, %v", list, err)
	}
	got := list.Msg.GetEcosystems()[0]
	if got.GetLeadTenantId() != h.tenantID || len(got.GetMembers()) != 1 || got.GetMembers()[0].GetTenantId() != member ||
		got.GetMembers()[0].GetMember().GetTenantId() != "org-2" || got.GetStackName() != "Tenancy stack" {
		t.Errorf("listed = %+v", got)
	}
	if _, err = h.svc.RemoveStackEcosystemMember(ctx, request(h, &adminv1.RemoveStackEcosystemMemberRequest{
		Stack: configv1.Dpg_DPG_CREDEBL, EcosystemId: e.GetEcosystem().GetId(), TenantId: member,
	})); err != nil || len(fake.eco.members[e.GetEcosystem().GetId()]) != 0 {
		t.Fatalf("RemoveStackEcosystemMember = %v, %v", err, fake.eco.members)
	}
	for action, target := range map[string]string{
		"admin.SetStackEcosystems": "DPG_CREDEBL", "admin.CreateStackEcosystem": e.GetEcosystem().GetId(),
		"admin.AddStackEcosystemMember": member, "admin.RemoveStackEcosystemMember": member,
	} {
		if recs := auditActions(t, h, action); len(recs) != 1 || !recs[0].OK || recs[0].Target != target {
			t.Errorf("%s audit = %+v", action, recs)
		}
	}
}

// TestStackEcosystemRefusals is P6-C9: each call names a bound tenant
// on a stack that lists ecosystems, a name, and a caller. A stack that
// fails leaves a line in the errors of the list.
func TestStackEcosystemRefusals(t *testing.T) {
	h := newHarness(t)
	fake, _ := withStacks(t, h, backendv1.Feature_FEATURE_ECOSYSTEMS)
	ctx := context.Background()
	if _, err := h.svc.BindTenant(ctx, request(h, &adminv1.BindTenantRequest{Id: h.tenantID, Stack: configv1.Dpg_DPG_CREDEBL})); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		call func() error
		want connect.Code
	}{
		"no name": {func() error {
			_, err := h.svc.CreateStackEcosystem(ctx, request(h, &adminv1.CreateStackEcosystemRequest{Stack: configv1.Dpg_DPG_CREDEBL, LeadTenantId: h.tenantID}))
			return err
		}, connect.CodeInvalidArgument},
		"no ecosystem": {func() error {
			_, err := h.svc.AddStackEcosystemMember(ctx, request(h, &adminv1.AddStackEcosystemMemberRequest{Stack: configv1.Dpg_DPG_CREDEBL, TenantId: h.tenantID}))
			return err
		}, connect.CodeInvalidArgument},
		"no binding": {func() error {
			_, err := h.svc.CreateStackEcosystem(ctx, request(h, &adminv1.CreateStackEcosystemRequest{Stack: configv1.Dpg_DPG_WALTID, LeadTenantId: h.tenantID, Name: "Health", Description: "Health agencies"}))
			return err
		}, connect.CodeNotFound},
		"no tenant": {func() error {
			_, err := h.svc.RemoveStackEcosystemMember(ctx, request(h, &adminv1.RemoveStackEcosystemMemberRequest{Stack: configv1.Dpg_DPG_CREDEBL, EcosystemId: "eco-1", TenantId: "missing"}))
			return err
		}, connect.CodeNotFound},
		"no stack": {func() error {
			_, err := h.svc.SetStackEcosystems(ctx, request(h, &adminv1.SetStackEcosystemsRequest{Stack: configv1.Dpg_DPG_WALTID, Enabled: true}))
			return err
		}, connect.CodeFailedPrecondition},
		"not a member": {func() error {
			_, err := h.svc.RemoveStackEcosystemMember(ctx, request(h, &adminv1.RemoveStackEcosystemMemberRequest{Stack: configv1.Dpg_DPG_CREDEBL, EcosystemId: "eco-1", TenantId: h.tenantID}))
			return err
		}, connect.CodeNotFound},
		"anonymous": {func() error {
			_, err := h.svc.ListStackEcosystems(ctx, connect.NewRequest(&adminv1.ListStackEcosystemsRequest{}))
			return err
		}, connect.CodeUnauthenticated},
	}
	for name, c := range cases {
		if err := c.call(); connect.CodeOf(err) != c.want {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	fake.eco.err = connect.NewError(connect.CodeUnavailable, errors.New("the ecosystem service is down"))
	list, err := h.svc.ListStackEcosystems(ctx, request(h, &adminv1.ListStackEcosystemsRequest{}))
	if err != nil || !strings.Contains(list.Msg.GetStacks()[0].GetError(), "down") {
		t.Errorf("a failed switch gave %+v, %v", list, err)
	}
	if _, err = h.svc.SetStackEcosystems(ctx, request(h, &adminv1.SetStackEcosystemsRequest{Stack: configv1.Dpg_DPG_CREDEBL, Enabled: true})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Errorf("a failed set gave %v", err)
	}
	fake.eco = fakeEcosystems{on: true, list: []*backendv1.Ecosystem{{Id: "eco-9", Name: "Farms", LeadTenantId: "org-1"}},
		listErr: connect.NewError(connect.CodeUnavailable, errors.New("the list is down"))}
	if list, err = h.svc.ListStackEcosystems(ctx, request(h, &adminv1.ListStackEcosystemsRequest{})); err != nil || len(list.Msg.GetErrors()) != 1 {
		t.Errorf("a failed list gave %+v, %v", list, err)
	}
}
