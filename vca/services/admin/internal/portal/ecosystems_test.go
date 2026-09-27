// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
)

func (f *fakeStack) GetEcosystemSettings(context.Context, *connect.Request[backendv1.GetEcosystemSettingsRequest]) (*connect.Response[backendv1.GetEcosystemSettingsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return connect.NewResponse(&backendv1.GetEcosystemSettingsResponse{Enabled: f.ecoOn}), nil
}

func (f *fakeStack) SetEcosystemSettings(_ context.Context, req *connect.Request[backendv1.SetEcosystemSettingsRequest]) (*connect.Response[backendv1.SetEcosystemSettingsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ecoOn = req.Msg.GetEnabled()
	return connect.NewResponse(&backendv1.SetEcosystemSettingsResponse{Enabled: f.ecoOn}), nil
}

func (f *fakeStack) ListEcosystems(_ context.Context, req *connect.Request[backendv1.ListEcosystemsRequest]) (*connect.Response[backendv1.ListEcosystemsResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &backendv1.ListEcosystemsResponse{}
	for _, e := range f.ecosystems {
		if e.GetLeadTenantId() == req.Msg.GetTenantId() || slices.Contains(f.ecoMembers[e.GetId()], req.Msg.GetTenantId()) {
			e.MemberCount = int32(len(f.ecoMembers[e.GetId()])) // #nosec G115 -- a test holds few members
			out.Ecosystems = append(out.Ecosystems, e)
		}
	}
	return connect.NewResponse(out), nil
}

func (f *fakeStack) CreateEcosystem(_ context.Context, req *connect.Request[backendv1.CreateEcosystemRequest]) (*connect.Response[backendv1.CreateEcosystemResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.ecosystems {
		if e.GetName() == req.Msg.GetName() {
			return nil, connect.NewError(connect.CodeAlreadyExists, errors.New("the ecosystem name exists"))
		}
	}
	e := &backendv1.Ecosystem{
		Id: fmt.Sprintf("eco-%d", len(f.ecosystems)+1), Name: req.Msg.GetName(), Description: req.Msg.GetDescription(),
		LeadTenantId: req.Msg.GetLeadTenantId(), LeadTenantName: f.tenants[req.Msg.GetLeadTenantId()].GetName(),
	}
	f.ecosystems = append(f.ecosystems, e)
	return connect.NewResponse(&backendv1.CreateEcosystemResponse{Ecosystem: e}), nil
}

func (f *fakeStack) ListEcosystemMembers(_ context.Context, req *connect.Request[backendv1.ListEcosystemMembersRequest]) (*connect.Response[backendv1.ListEcosystemMembersResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &backendv1.ListEcosystemMembersResponse{}
	for _, m := range f.ecoMembers[req.Msg.GetEcosystemId()] {
		out.Members = append(out.Members, &backendv1.EcosystemMember{
			TenantId: m, TenantName: f.tenants[m].GetName(), Status: "ACTIVE", JoinedAt: timestamppb.New(fixedJoin),
		})
	}
	return connect.NewResponse(out), nil
}

func (f *fakeStack) AddEcosystemMember(_ context.Context, req *connect.Request[backendv1.AddEcosystemMemberRequest]) (*connect.Response[backendv1.AddEcosystemMemberResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ecoMembers[req.Msg.GetEcosystemId()] = append(f.ecoMembers[req.Msg.GetEcosystemId()], req.Msg.GetTenantId())
	return connect.NewResponse(&backendv1.AddEcosystemMemberResponse{}), nil
}

func (f *fakeStack) RemoveEcosystemMember(_ context.Context, req *connect.Request[backendv1.RemoveEcosystemMemberRequest]) (*connect.Response[backendv1.RemoveEcosystemMemberResponse], error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := req.Msg.GetEcosystemId()
	f.ecoMembers[id] = slices.DeleteFunc(f.ecoMembers[id], func(m string) bool { return m == req.Msg.GetTenantId() })
	return connect.NewResponse(&backendv1.RemoveEcosystemMemberResponse{}), nil
}

// ecosystemHarness is a signed in harness whose tenancy stack lists
// ecosystems, with two tenants bound on it. It returns the stack and
// the ids of the two tenants.
func ecosystemHarness(t *testing.T) (*harness, *fakeStack, string, string) {
	t.Helper()
	h, tenancy, lead := credentialHarness(t, backendv1.Feature_FEATURE_ECOSYSTEMS)
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"County Farm Board"}, "stacks": {"DPG_CREDEBL"}}); status != http.StatusSeeOther {
		t.Fatal("the second tenant could not be created")
	}
	for _, id := range h.tenantIDs(t) {
		if id != lead {
			return h, tenancy, lead, id
		}
	}
	t.Fatal("no second tenant")
	return nil, nil, "", ""
}

// TestEcosystemsTabOnlyWithFeature is P6-C9 (ADR-068): the tenant pages
// show an Ecosystems tab only where a live adapter lists ecosystems. The
// tab shows the switch of each such stack, off at first, with an empty
// state that says what to do. Without the feature the page does not
// exist.
func TestEcosystemsTabOnlyWithFeature(t *testing.T) {
	h, _, _, _ := ecosystemHarness(t)
	list := h.page(t, "/admin/tenants")
	tab := `href="/admin/tenants/ecosystems"`
	if !strings.Contains(list, tab) || !strings.Contains(list, msg.T("admin.tenants.tab.ecosystems.label")) {
		t.Error("the tenant list has no Ecosystems tab")
	}
	page := h.page(t, "/admin/tenants/ecosystems")
	for _, want := range []string{
		msg.T("admin.ecosystems.switch.label"), "Tenancy stack", msg.T("admin.ecosystems.off.label"),
		msg.T("admin.ecosystems.turn_on.label"), msg.T("admin.ecosystems.off.title.label"),
		`<a href="/admin/tenants/ecosystems" aria-current="page"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page misses %q", want)
		}
	}
	if strings.Contains(page, `id="ecosystem_name"`) {
		t.Error("the page offers a create form while the switch is off")
	}
	without, _, _ := credentialHarness(t)
	if strings.Contains(without.page(t, "/admin/tenants"), tab) {
		t.Error("a deployment without ecosystems shows the tab")
	}
	if status, _ := without.get(t, "/admin/tenants/ecosystems"); status != http.StatusNotFound {
		t.Errorf("the page without the feature = %d", status)
	}
}

// TestEcosystemsPageRunsEachStep is P6-C9: the admin turns the switch
// on, creates an ecosystem that one tenant leads, adds the second tenant
// as a member, and removes it. Each step redirects with a notice, and
// the tables show the ecosystem with its lead and its member.
func TestEcosystemsPageRunsEachStep(t *testing.T) {
	h, tenancy, lead, member := ecosystemHarness(t)
	if status, _ := h.post(t, "/admin/tenants/ecosystems/switch", url.Values{"stack": {"DPG_CREDEBL"}, "enabled": {"true"}}); status != http.StatusSeeOther || !tenancy.ecoOn {
		t.Fatalf("switch = %d, on %v", status, tenancy.ecoOn)
	}
	on := h.page(t, "/admin/tenants/ecosystems?notice=ecosystems-on")
	for _, want := range []string{msg.T("admin.ecosystems.on.label"), msg.T("admin.ecosystems.turn_off.label"), msg.T("admin.ecosystems.empty"),
		`value="` + lead + `|DPG_CREDEBL"`, `id="ecosystem_name"`, msg.T("admin.ecosystems.turned_on")} {
		if !strings.Contains(on, want) {
			t.Errorf("the page after the switch misses %q", want)
		}
	}
	status, _ := h.post(t, "/admin/tenants/ecosystems", url.Values{
		"target": {lead + "|DPG_CREDEBL"}, "name": {"Health agencies"}, "description": {"The agencies that issue health records."},
	})
	if status != http.StatusSeeOther || len(tenancy.ecosystems) != 1 {
		t.Fatalf("create = %d, %d ecosystems", status, len(tenancy.ecosystems))
	}
	created := h.page(t, "/admin/tenants/ecosystems?notice=ecosystem-created")
	for _, want := range []string{"Health agencies", "The agencies that issue health records.", "Ministry of Health", `value="eco-1|DPG_CREDEBL"`,
		msg.T("admin.ecosystems.members.empty")} {
		if !strings.Contains(created, want) {
			t.Errorf("the page after the create misses %q", want)
		}
	}
	if status, _ = h.post(t, "/admin/tenants/ecosystems/members", url.Values{"ecosystem": {"eco-1|DPG_CREDEBL"}, "tenant": {member}}); status != http.StatusSeeOther {
		t.Fatalf("add = %d", status)
	}
	added := h.page(t, "/admin/tenants/ecosystems?notice=ecosystem-member-added")
	for _, want := range []string{"County Farm Board", msg.T("admin.ecosystems.remove.label"), msg.T("admin.ecosystems.member_added")} {
		if !strings.Contains(added, want) {
			t.Errorf("the page after the add misses %q", want)
		}
	}
	if status, _ = h.post(t, "/admin/tenants/ecosystems/members/remove", url.Values{"ecosystem": {"eco-1|DPG_CREDEBL"}, "tenant": {member}}); status != http.StatusSeeOther {
		t.Fatalf("remove = %d", status)
	}
	if len(tenancy.ecoMembers["eco-1"]) != 0 {
		t.Errorf("members = %v", tenancy.ecoMembers)
	}
	for path, form := range map[string]url.Values{
		"/admin/tenants/ecosystems/switch":         {"stack": {"NOPE"}, "enabled": {"true"}},
		"/admin/tenants/ecosystems":                {"target": {"no-separator"}, "name": {"x"}},
		"/admin/tenants/ecosystems/members":        {"ecosystem": {"eco-1"}, "tenant": {member}},
		"/admin/tenants/ecosystems/members/remove": {"ecosystem": {"eco-1|NOPE"}, "tenant": {member}},
	} {
		if status, _ := h.post(t, path, form); status != http.StatusBadRequest {
			t.Errorf("%s %v = %d", path, form, status)
		}
	}
}

// fixedJoin is when each member of the fake stack joined.
var fixedJoin = time.Date(2026, 9, 27, 9, 5, 0, 0, time.UTC)

// tenantIDs lists the ids of every tenant.
func (h *harness) tenantIDs(t *testing.T) []string {
	t.Helper()
	res, err := h.app.Service.ListTenants(context.Background(), authed(t, h, &adminv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	var out []string
	for _, tn := range res.Msg.GetTenants() {
		out = append(out, tn.GetId())
	}
	return out
}
