// SPDX-License-Identifier: Apache-2.0

package service_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
)

// P6-C9: the ecosystems of the platform (ADR-068).

// memberOrg is a second organisation of the recorded answers.
const memberOrg = "org-3"

// TestListEcosystems is P6-C9: the switch of the platform reads off and
// turns on. A create sends the lead in the query after the invitation
// of the platform admin, and signs in again so the next call carries the
// lead role. The list of the lead names the ecosystem with its lead and
// the member count. A member joins at once, shows in the members and in
// its own list, and leaves.
func TestListEcosystems(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	got, err := svc.GetEcosystemSettings(ctx, connect.NewRequest(&backendv1.GetEcosystemSettingsRequest{}))
	if err != nil || got.Msg.GetEnabled() {
		t.Fatalf("settings = %v, %v", got, err)
	}
	set, err := svc.SetEcosystemSettings(ctx, connect.NewRequest(&backendv1.SetEcosystemSettingsRequest{Enabled: true}))
	if err != nil || !set.Msg.GetEnabled() {
		t.Fatalf("set = %v, %v", set, err)
	}
	list, err := svc.ListEcosystems(ctx, connect.NewRequest(&backendv1.ListEcosystemsRequest{TenantId: tenantOrg}))
	if err != nil || len(list.Msg.GetEcosystems()) != 0 {
		t.Fatalf("no ecosystem = %v, %v", list, err)
	}
	before := f.Signins()
	created, err := svc.CreateEcosystem(ctx, connect.NewRequest(&backendv1.CreateEcosystemRequest{
		LeadTenantId: tenantOrg, Name: " Health agencies ", Description: "The agencies that issue health records.",
	}))
	if err != nil {
		t.Fatalf("CreateEcosystem: %v", err)
	}
	e := created.Msg.GetEcosystem()
	if e.GetId() != fake.EcosystemID || e.GetName() != "Health agencies" || e.GetLeadTenantId() != tenantOrg || e.GetLeadTenantName() == "" {
		t.Fatalf("created = %+v", e)
	}
	calls := f.Calls()
	if i, j := slices.Index(calls, "POST /v1/invitations"), slices.Index(calls, "POST /v1/ecosystem"); i < 0 || j < i {
		t.Errorf("calls = %v, want the invitation before the create", calls)
	}
	if q := f.Query("/v1/ecosystem"); !strings.Contains(q, "orgId="+tenantOrg) {
		t.Errorf("query = %q", q)
	}
	if f.Signins() == before {
		t.Error("the adapter kept the token that has no lead role")
	}
	added, err := svc.AddEcosystemMember(ctx, connect.NewRequest(&backendv1.AddEcosystemMemberRequest{EcosystemId: e.GetId(), TenantId: memberOrg}))
	if err != nil || added.Msg.GetInvited() {
		t.Fatalf("add = %v, %v", added, err)
	}
	members, err := svc.ListEcosystemMembers(ctx, connect.NewRequest(&backendv1.ListEcosystemMembersRequest{EcosystemId: e.GetId()}))
	if err != nil || len(members.Msg.GetMembers()) != 1 {
		t.Fatalf("members = %v, %v", members, err)
	}
	if m := members.Msg.GetMembers()[0]; m.GetTenantId() != memberOrg || m.GetStatus() != "ACTIVE" || m.GetJoinedAt() == nil || m.GetTenantName() == "" {
		t.Errorf("member = %+v", m)
	}
	for org, count := range map[string]int32{tenantOrg: 1, memberOrg: 1} {
		l, lerr := svc.ListEcosystems(ctx, connect.NewRequest(&backendv1.ListEcosystemsRequest{TenantId: org}))
		if lerr != nil || len(l.Msg.GetEcosystems()) != 1 {
			t.Fatalf("%s lists %v, %v", org, l, lerr)
		}
		if got := l.Msg.GetEcosystems()[0]; got.GetMemberCount() != count || got.GetLeadTenantId() != tenantOrg || got.GetDescription() == "" {
			t.Errorf("%s lists %+v", org, got)
		}
	}
	if _, err = svc.RemoveEcosystemMember(ctx, connect.NewRequest(&backendv1.RemoveEcosystemMemberRequest{EcosystemId: e.GetId(), TenantId: memberOrg})); err != nil {
		t.Fatal(err)
	}
	members, err = svc.ListEcosystemMembers(ctx, connect.NewRequest(&backendv1.ListEcosystemMembersRequest{EcosystemId: e.GetId()}))
	if err != nil || len(members.Msg.GetMembers()) != 0 {
		t.Errorf("after the removal = %v, %v", members, err)
	}
}

// TestEcosystemRefusals is P6-C9: the adapter checks each field before
// the platform, refuses a member twice, and names the reason of each
// refusal of the platform.
func TestEcosystemRefusals(t *testing.T) {
	svc, f := newService(t, nil)
	ctx := context.Background()
	if _, err := svc.SetEcosystemSettings(ctx, connect.NewRequest(&backendv1.SetEcosystemSettingsRequest{Enabled: true})); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("n", 51)
	for name, req := range map[string]*backendv1.CreateEcosystemRequest{
		"no lead":        {Name: "Health", Description: "Health agencies"},
		"short name":     {LeadTenantId: tenantOrg, Name: "H", Description: "Health agencies"},
		"long name":      {LeadTenantId: tenantOrg, Name: long, Description: "Health agencies"},
		"no description": {LeadTenantId: tenantOrg, Name: "Health"},
	} {
		if _, err := svc.CreateEcosystem(ctx, connect.NewRequest(req)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for name, err := range map[string]error{
		"list":    second(svc.ListEcosystems(ctx, connect.NewRequest(&backendv1.ListEcosystemsRequest{}))),
		"members": second(svc.ListEcosystemMembers(ctx, connect.NewRequest(&backendv1.ListEcosystemMembersRequest{}))),
		"add":     second(svc.AddEcosystemMember(ctx, connect.NewRequest(&backendv1.AddEcosystemMemberRequest{EcosystemId: fake.EcosystemID}))),
		"remove":  second(svc.RemoveEcosystemMember(ctx, connect.NewRequest(&backendv1.RemoveEcosystemMemberRequest{TenantId: memberOrg}))),
	} {
		if connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	create := &backendv1.CreateEcosystemRequest{LeadTenantId: tenantOrg, Name: "Health", Description: "Health agencies"}
	if _, err := svc.CreateEcosystem(ctx, connect.NewRequest(create)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateEcosystem(ctx, connect.NewRequest(create)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Errorf("a second name = %v", err)
	}
	add := &backendv1.AddEcosystemMemberRequest{EcosystemId: fake.EcosystemID, TenantId: memberOrg}
	if _, err := svc.AddEcosystemMember(ctx, connect.NewRequest(add)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddEcosystemMember(ctx, connect.NewRequest(add)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Errorf("a member twice = %v", err)
	}
	lead := &backendv1.AddEcosystemMemberRequest{EcosystemId: fake.EcosystemID, TenantId: tenantOrg}
	if _, err := svc.AddEcosystemMember(ctx, connect.NewRequest(lead)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("the lead as a member = %v", err)
	}
	remove := &backendv1.RemoveEcosystemMemberRequest{EcosystemId: fake.EcosystemID, TenantId: "org-4"}
	if _, err := svc.RemoveEcosystemMember(ctx, connect.NewRequest(remove)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("no member = %v", err)
	}
	f.SetStatus("/v1/config/ecosystem", http.StatusBadRequest)
	_, err := svc.SetEcosystemSettings(ctx, connect.NewRequest(&backendv1.SetEcosystemSettingsRequest{Enabled: true}))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "bootstrap") {
		t.Errorf("a realm without the ecosystem roles = %v", err)
	}
	for _, path := range []string{"/v1/ecosystem/status", "/v1/ecosystem", "/v1/ecosystem/members", "/v1/ecosystem/invitation", "/v1/invitations"} {
		f.SetStatus(path, http.StatusBadGateway)
	}
	errs := []error{
		second(svc.GetEcosystemSettings(ctx, connect.NewRequest(&backendv1.GetEcosystemSettingsRequest{}))),
		second(svc.ListEcosystems(ctx, connect.NewRequest(&backendv1.ListEcosystemsRequest{TenantId: tenantOrg}))),
		second(svc.ListEcosystemMembers(ctx, connect.NewRequest(&backendv1.ListEcosystemMembersRequest{EcosystemId: fake.EcosystemID}))),
		second(svc.AddEcosystemMember(ctx, connect.NewRequest(&backendv1.AddEcosystemMemberRequest{EcosystemId: fake.EcosystemID, TenantId: "org-4"}))),
		second(svc.CreateEcosystem(ctx, connect.NewRequest(&backendv1.CreateEcosystemRequest{LeadTenantId: tenantOrg, Name: "Farms", Description: "Farm boards"}))),
	}
	for i, err := range errs {
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Errorf("call %d: err = %v", i+1, err)
		}
	}
}

// second returns the error of a call.
func second[T any](_ T, err error) error { return err }
