// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// TestKeyFormHasTenantAndExpiry is ADR-038 decision 1: the key form
// takes the tenant by name and an expiry, and the list shows both.
func TestKeyFormHasTenantAndExpiry(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"Ministry of Health"}}); status != http.StatusSeeOther {
		t.Fatal("the tenant could not be created")
	}
	tenant := h.tenantID(t)
	page := h.page(t, "/admin/keys")
	for _, want := range []string{
		`<select id="tenant_id" name="tenant_id"`, `<option value="` + tenant + `"`, ">Ministry of Health</option>",
		`<select id="expires_days" name="expires_days"`, `<option value="90" selected>`, `<option value="">` + msg.T("admin.keys.expiry.none.label"),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the form misses %q", want)
		}
	}
	status, body := h.post(t, "/admin/keys", url.Values{
		"display_name": {"Payroll export"}, "tenant_id": {tenant}, "role": {"issuer"}, "expires_days": {"30"},
	})
	if status != http.StatusOK {
		t.Fatalf("create = %d %s", status, body)
	}
	list := h.page(t, "/admin/keys")
	for _, want := range []string{
		"Payroll export", msg.T("admin.keys.column.tenant.label"), msg.T("admin.keys.column.expires.label"),
	} {
		if !strings.Contains(list, want) {
			t.Errorf("the list misses %q", want)
		}
	}
	// The tenant column names the tenant, not only its id.
	row := list[strings.Index(list, "Payroll export"):]
	row = row[:strings.Index(row, "</tr>")]
	if !strings.Contains(row, "Ministry of Health") {
		t.Errorf("the row does not name the tenant: %s", row)
	}
	if strings.Contains(row, msg.T("admin.keys.expiry.never.label")) {
		t.Error("a key with an expiry shows no end")
	}
	// A deployment without a tenant asks for one first.
	bare := newHarness(t, true)
	bare.signIn(t)
	if empty := bare.page(t, "/admin/keys"); !strings.Contains(empty, msg.T("admin.keys.no_tenant.title")) || strings.Contains(empty, `name="tenant_id"`) {
		t.Error("the page offers a key form without a tenant")
	}
}

// credentialHarness is a signed in harness whose tenancy stack lists
// tenant client credentials, with one tenant bound on it.
func credentialHarness(t *testing.T, features ...backendv1.Feature) (*harness, *fakeStack, string) {
	t.Helper()
	tenancy := newFakeStack("Tenancy stack", append([]backendv1.Feature{backendv1.Feature_FEATURE_MULTI_TENANCY}, features...)...)
	h := newHarnessWith(t, true, stackPeers(tenancy, newFakeStack("Plain stack")))
	h.signIn(t)
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"Ministry of Health"}, "stacks": {"DPG_CREDEBL"}}); status != http.StatusSeeOther {
		t.Fatal("the tenant could not be created")
	}
	return h, tenancy, h.tenantID(t)
}

// TestStackCredentialShownOnce is ADR-038 decision 2: a stack client
// secret shows once, on the answer to the create form, and never again.
func TestStackCredentialShownOnce(t *testing.T) {
	h, tenancy, tenant := credentialHarness(t, backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS)
	page := h.page(t, "/admin/keys")
	for _, want := range []string{
		msg.T("admin.keys.stack.label"), `<select id="target" name="target"`, `value="` + tenant + `|DPG_CREDEBL"`,
		"Ministry of Health on Tenancy stack",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page misses %q", want)
		}
	}
	status, body := h.post(t, "/admin/keys/stack", url.Values{"target": {tenant + "|DPG_CREDEBL"}, "display_name": {"Records sync"}})
	if status != http.StatusOK {
		t.Fatalf("create = %d %s", status, body)
	}
	a11ytest.AssertPage(t, body)
	for _, want := range []string{"stack-secret-2", "client-2", msg.T("admin.keys.stack.secret.label")} {
		if !strings.Contains(body, want) {
			t.Errorf("the answer misses %q", want)
		}
	}
	again := h.page(t, "/admin/keys")
	if strings.Contains(again, "stack-secret-2") {
		t.Fatal("the page shows the stack secret again")
	}
	for _, want := range []string{"Records sync", "client-2", "Tenancy stack"} {
		if !strings.Contains(again, want) {
			t.Errorf("the list misses %q", want)
		}
	}
	if status, _ := h.post(t, "/admin/keys/stack/delete", url.Values{"tenant_id": {tenant}, "stack": {"DPG_CREDEBL"}, "id": {"cred-2"}}); status != http.StatusSeeOther {
		t.Fatalf("delete = %d", status)
	}
	if len(tenancy.creds["org-1"]) != 0 {
		t.Fatal("the stack kept the credential")
	}
	if page := h.page(t, "/admin/keys?notice=stack-credential-deleted"); strings.Contains(page, "Records sync") {
		t.Error("the list still shows the credential")
	}
	for _, bad := range []url.Values{
		{"target": {"no-separator"}, "display_name": {"x"}},
		{"target": {tenant + "|NOT_A_STACK"}, "display_name": {"x"}},
	} {
		if status, _ := h.post(t, "/admin/keys/stack", bad); status != http.StatusBadRequest {
			t.Errorf("%v gave %d", bad, status)
		}
	}
}

// TestStackCredentialsHiddenWithoutFeature keeps the stack credential
// section off a deployment whose live adapters do not list the feature.
func TestStackCredentialsHiddenWithoutFeature(t *testing.T) {
	h, _, _ := credentialHarness(t)
	bare := newHarness(t, true)
	bare.signIn(t)
	for name, page := range map[string]string{
		"tenancy only": h.page(t, "/admin/keys"), "no stack": bare.page(t, "/admin/keys"),
	} {
		for _, gone := range []string{msg.T("admin.keys.stack.label"), `name="target"`, `id="stack-credentials"`} {
			if strings.Contains(page, gone) {
				t.Errorf("%s: the page shows %q", name, gone)
			}
		}
	}
}

// TestStackCredentialsWithoutABindingPointAtTenants shows the empty
// state when no tenant sits on a stack with client credentials.
func TestStackCredentialsWithoutABindingPointAtTenants(t *testing.T) {
	tenancy := newFakeStack("Tenancy stack", backendv1.Feature_FEATURE_MULTI_TENANCY, backendv1.Feature_FEATURE_TENANT_CLIENT_CREDENTIALS)
	h := newHarnessWith(t, true, stackPeers(tenancy, nil))
	h.signIn(t)
	page := h.page(t, "/admin/keys")
	if !strings.Contains(page, msg.T("admin.keys.stack.empty.title")) || strings.Contains(page, `name="target"`) {
		t.Error("the page offers a stack credential without a bound tenant")
	}
}
