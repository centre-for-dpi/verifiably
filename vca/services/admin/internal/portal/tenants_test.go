// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/portal"
)

// tenancyHarness is a signed in harness over a tenancy stack and a plain
// stack.
func tenancyHarness(t *testing.T) (*harness, *fakeStack) {
	t.Helper()
	tenancy := newFakeStack("Tenancy stack", backendv1.Feature_FEATURE_MULTI_TENANCY)
	plain := newFakeStack("Plain stack")
	h := newHarnessWith(t, true, stackPeers(tenancy, plain))
	h.signIn(t)
	return h, tenancy
}

// TestTenantFormOffersOnlyTenancyStacks is ADR-037 decision 3: the form
// offers a stack only when its live adapter lists multi tenancy, and a
// deployment without such a stack shows no tenancy control at all.
func TestTenantFormOffersOnlyTenancyStacks(t *testing.T) {
	h, _ := tenancyHarness(t)
	page := h.page(t, "/admin/tenants")
	for _, want := range []string{
		`name="stacks" value="DPG_CREDEBL"`, "Tenancy stack",
		`name="agent_type" value="shared"`, `name="agent_type" value="dedicated"`,
		msg.T("admin.tenants.stacks.label"),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the form misses %q", want)
		}
	}
	if strings.Contains(page, `value="DPG_WALTID"`) || strings.Contains(page, "Plain stack") {
		t.Error("the form offers a stack without multi tenancy")
	}
	bare := newHarness(t, true)
	bare.signIn(t)
	plain := bare.page(t, "/admin/tenants")
	for _, gone := range []string{`name="stacks"`, `name="agent_type"`, msg.T("admin.tenants.stacks.label"), msg.T("admin.tenants.column.stacks.label")} {
		if strings.Contains(plain, gone) {
			t.Errorf("a deployment without tenancy shows %q", gone)
		}
	}
	only := newHarnessWith(t, true, stackPeers(nil, newFakeStack("Plain stack")))
	only.signIn(t)
	if page := only.page(t, "/admin/tenants"); strings.Contains(page, `name="stacks"`) {
		t.Error("a deployment with a plain stack only shows the stack choice")
	}
}

// TestCreateTenantBindsToStacksFromThePage creates a tenant on the
// tenancy stack through the form.
func TestCreateTenantBindsToStacksFromThePage(t *testing.T) {
	h, tenancy := tenancyHarness(t)
	status, body := h.post(t, "/admin/tenants", url.Values{
		"display_name": {"Ministry of Health"}, "stacks": {"DPG_CREDEBL"}, "agent_type": {"dedicated"},
	})
	if status != http.StatusSeeOther {
		t.Fatalf("create = %d %s", status, body)
	}
	if tenancy.count() != 1 {
		t.Fatalf("the stack holds %d tenants", tenancy.count())
	}
	page := h.page(t, "/admin/tenants?notice=tenant-created")
	for _, want := range []string{"Ministry of Health", msg.T("admin.tenants.column.stacks.label"), "Tenancy stack"} {
		if !strings.Contains(page, want) {
			t.Errorf("the list misses %q", want)
		}
	}
	res, err := h.app.Service.ListTenants(context.Background(), authed(t, h, &adminv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var got *adminv1.Tenant
	for _, tn := range res.Msg.GetTenants() {
		if tn.GetDisplayName() == "Ministry of Health" {
			got = tn
		}
	}
	if got == nil || len(got.GetBindings()) != 1 || got.GetBindings()[0].GetTenant().GetAgentType() != backendv1.DpgTenant_AGENT_TYPE_DEDICATED {
		t.Fatalf("tenant = %+v", got)
	}
	// A stack value the form never offers fails.
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"X"}, "stacks": {"DPG_WALTID"}}); status != http.StatusBadRequest {
		t.Errorf("a plain stack gave %d", status)
	}
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"X"}, "stacks": {"NOT_A_STACK"}}); status != http.StatusBadRequest {
		t.Errorf("an unknown stack gave %d", status)
	}
}

// TestTenantDetailShowsBindings shows the stack tenant with its id, its
// agent and its DIDs, and binds and unbinds from the page.
func TestTenantDetailShowsBindings(t *testing.T) {
	h, tenancy := tenancyHarness(t)
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"Civil Registry"}}); status != http.StatusSeeOther {
		t.Fatal("the create failed")
	}
	id := ""
	res, err := h.app.Service.ListTenants(context.Background(), authed(t, h, &adminv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tn := range res.Msg.GetTenants() {
		if tn.GetDisplayName() == "Civil Registry" {
			id = tn.GetId()
		}
	}
	list := h.page(t, "/admin/tenants")
	if !strings.Contains(list, `href="/admin/tenants/`+id+`"`) {
		t.Error("the list does not link the detail page")
	}
	detail := h.page(t, "/admin/tenants/"+id)
	for _, want := range []string{"<h1>Civil Registry</h1>", id, msg.T("admin.tenants.bind.label"), `name="stack" value="DPG_CREDEBL"`} {
		if !strings.Contains(detail, want) {
			t.Errorf("the detail page misses %q", want)
		}
	}
	if status, _ := h.post(t, "/admin/tenants/"+id+"/bind", url.Values{"stack": {"DPG_CREDEBL"}, "agent_type": {"shared"}}); status != http.StatusSeeOther {
		t.Fatalf("bind = %d", status)
	}
	bound := h.page(t, "/admin/tenants/"+id+"?notice=tenant-bound")
	for _, want := range []string{
		"Tenancy stack", "org-1", "did:key:z6Mkorg-1", msg.T("admin.tenants.agent.shared.label"),
		msg.T("admin.tenants.unbind.label"), portal.Notices["tenant-bound"].Text,
	} {
		if !strings.Contains(bound, want) {
			t.Errorf("the bound detail misses %q", want)
		}
	}
	// Every tenancy stack is bound, so the page offers no bind form.
	if strings.Contains(bound, `name="stack" value="DPG_CREDEBL"`+` checked`) || strings.Contains(bound, `id="bind-stack"`) {
		t.Error("the page offers a stack the tenant is bound on")
	}
	if status, _ := h.post(t, "/admin/tenants/"+id+"/unbind", url.Values{"stack": {"DPG_CREDEBL"}}); status != http.StatusSeeOther {
		t.Fatalf("unbind = %d", status)
	}
	if tenancy.count() != 0 {
		t.Fatal("the stack kept its tenant")
	}
	if page := h.page(t, "/admin/tenants/"+id+"?notice=tenant-unbound"); strings.Contains(page, "org-1") {
		t.Error("the detail still shows the stack tenant")
	}
	if status, _ := h.get(t, "/admin/tenants/missing"); status != http.StatusNotFound {
		t.Errorf("an unknown tenant gave %d", status)
	}
	if status, _ := h.post(t, "/admin/tenants/"+id+"/bind", url.Values{"stack": {"DPG_WALTID"}}); status != http.StatusBadRequest {
		t.Errorf("a bind on a plain stack gave %d", status)
	}
}

// TestTenantDetailWithoutTenancyHidesStacks shows a tenant of a
// deployment without tenancy: no stack section, no bind form.
func TestTenantDetailWithoutTenancyHidesStacks(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	id := h.tenantIDOrCreate(t)
	page := h.page(t, "/admin/tenants/"+id)
	for _, gone := range []string{msg.T("admin.tenants.on_stacks.label"), `id="bind-stack"`} {
		if strings.Contains(page, gone) {
			t.Errorf("the detail shows %q", gone)
		}
	}
}

// tenantIDOrCreate returns the id of a tenant, and makes one when none
// exists.
func (h *harness) tenantIDOrCreate(t *testing.T) string {
	t.Helper()
	res, err := h.app.Service.ListTenants(context.Background(), authed(t, h, &adminv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Msg.GetTenants()) == 0 {
		if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"Ministry"}}); status != http.StatusSeeOther {
			t.Fatal("the create failed")
		}
	}
	return h.tenantID(t)
}
