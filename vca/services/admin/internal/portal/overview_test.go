// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/msg"
	"github.com/centre-for-dpi/vc-adapters/internal/rolenav"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// stackStub answers GetCapabilities with a display name, so the shell
// can name the stack of a pair (ADR-034 decision 4).
type stackStub struct {
	backendv1connect.UnimplementedCapabilityServiceHandler
	name string
}

func (s *stackStub) GetCapabilities(context.Context, *connect.Request[backendv1.GetCapabilitiesRequest]) (*connect.Response[backendv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&backendv1.GetCapabilitiesResponse{
		DpgInfo: &backendv1.DpgInfo{DisplayName: s.name},
	}), nil
}

// peers is a fake deployment: this admin pair live on stack one, a
// second admin pair starting on stack two, an absent admin pair on stack
// three, and one live issuer pair on stack one whose adapter names the
// stack.
func peers(t *testing.T, h *harness) func(*config.Config, *app.Deps) {
	t.Helper()
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("ready"))
	}))
	t.Cleanup(ready.Close)
	starting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(starting.Close)
	adapterMux := http.NewServeMux()
	adapterMux.Handle(backendv1connect.NewCapabilityServiceHandler(&stackStub{name: "Stack One"}))
	adapter := httptest.NewServer(adapterMux)
	t.Cleanup(adapter.Close)
	return func(cfg *config.Config, deps *app.Deps) {
		cfg.Peers = []topology.Peer{
			{Pair: "admin-waltid", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: h.server.URL,
				Services: map[string]string{"admin": ready.URL}},
			{Pair: "admin-inji", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_INJI, PublicURL: "https://admin-inji.example",
				Services: map[string]string{"admin": starting.URL}},
			{Pair: "admin-credebl", Role: commonv1.Role_ROLE_ADMIN, Dpg: configv1.Dpg_DPG_CREDEBL, PublicURL: "https://admin-credebl.example",
				Services: map[string]string{"admin": "http://absent.invalid:1"}},
			{Pair: "issuer-waltid", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: "https://issuer-waltid.example",
				Services: map[string]string{"issuance": ready.URL, "dpg-adapter-waltid": adapter.URL}},
		}
		deps.Prober = &topology.Prober{Peers: cfg.Peers, Lookup: func(_ context.Context, host string) ([]string, error) {
			if strings.HasSuffix(host, ".invalid") {
				return nil, errors.New("no such host")
			}
			return []string{"127.0.0.1"}, nil
		}}
	}
}

// keycloakProvider is a provider record of kind keycloak for the admin
// role, as the setup CLI seeds it (ADR-035 decision 2).
func keycloakProvider(h *harness, id, realm string, roles ...string) oidcflow.Provider {
	return oidcflow.Provider{
		ID: id, DisplayName: "Keycloak", DiscoveryURL: h.idp.DiscoveryURL(), ClientID: h.idp.ClientID,
		Enabled: true, Roles: roles,
		Profile: oidcflow.Profile{
			Kind: oidcflow.KindKeycloak, Realm: realm,
			ConsoleURL: "https://kc.example/admin/" + realm + "/console/", IsDefault: true,
		},
	}
}

func TestAdminPagesUseShell(t *testing.T) {
	h := newHarness(t, true)
	h.idp.Claims["name"] = "Amina Ali"
	h.signIn(t)
	for _, path := range rolenav.Paths(commonv1.Role_ROLE_ADMIN) {
		body := h.page(t, path)
		for _, want := range []string{
			`<body data-role="admin" class="has-shell">`, `<span class="role-chip">Admin</span>`,
			`<nav aria-label="Portal">`, `<details class="user-menu">`, `<summary>Amina Ali</summary>`,
			`<form method="post" action="/auth/logout">`, `name="csrf_token" value="`, `>Sign out</button>`,
			`<a href="` + path + `" aria-current="page"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s misses %q", path, want)
			}
		}
		// The old top navigation is gone: the shell holds the pages.
		if strings.Contains(body, `aria-label="Super admin"`) {
			t.Errorf("%s still draws the old top navigation", path)
		}
	}
	// A page below a section page marks that page current.
	wizard := h.page(t, "/admin/providers/new")
	if !strings.Contains(wizard, `<a href="/admin/providers" aria-current="page"`) {
		t.Error("the provider form does not mark the providers page current")
	}
	// The sign out form works: the session ends.
	res, err := h.client.PostForm(h.server.URL+"/auth/logout", url.Values{oidcflow.CSRFField: {h.csrf}})
	if err != nil {
		t.Fatal(err)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Error(cerr)
	}
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status = %d", res.StatusCode)
	}
	if status, _ := h.get(t, "/admin/"); status != http.StatusSeeOther {
		t.Fatalf("after logout the overview answers %d, want a redirect to the login", status)
	}
}

func TestOverviewCardsShowCounts(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	empty := h.page(t, "/admin/")
	for _, want := range []string{
		`<h1>Overview</h1>`, msg.T("admin.overview.lead"),
		`<span class="stat-value">0 trusted issuers</span>`, `<span class="stat-value">Local registry</span>`,
		`<span class="stat-value">1 provider</span>`, `<span class="stat-value">0 tenants</span>`,
		`<span class="stat-value">No keys yet</span>`, `events today</span>`,
		`<a class="stat-link" href="/admin/trust">`, `<a class="stat-link" href="/admin/providers">`,
		`<a class="stat-link" href="/admin/tenants">`, `<a class="stat-link" href="/admin/keys">`,
		`<a class="stat-link" href="/admin/audit">`,
	} {
		if !strings.Contains(empty, want) {
			t.Errorf("empty overview misses %q\n%s", want, empty)
		}
	}
	// The health table of the old dashboard stays, below the cards.
	if !strings.Contains(empty, "trust-registry") || !strings.Contains(empty, "Ready") {
		t.Error("the overview lost the service health")
	}
	if status, _ := h.post(t, "/admin/trust", url.Values{
		"identifier": {"did:web:one.example"}, "display_name": {"One"}, "role": {"issuer"}, "status": {"active"},
	}); status != http.StatusSeeOther {
		t.Fatal("the trust entry failed")
	}
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"Ministry"}}); status != http.StatusSeeOther {
		t.Fatal("the tenant failed")
	}
	if status, _ := h.post(t, "/admin/keys", url.Values{"display_name": {"CI"}, "tenant_id": {h.tenantID(t)}, "role": {"issuer"}}); status != http.StatusOK {
		t.Fatal("the key failed")
	}
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-issuer", "vca-issuer-realm", "issuer")); err != nil {
		t.Fatal(err)
	}
	filled := h.page(t, "/admin/")
	for _, want := range []string{
		`<span class="stat-value">1 trusted issuer</span>`, `<span class="stat-value">2 providers</span>`,
		`1 realm.`, `<span class="stat-value">1 tenant</span>`, `<span class="stat-value">1 key</span>`,
	} {
		if !strings.Contains(filled, want) {
			t.Errorf("filled overview misses %q\n%s", want, filled)
		}
	}
	// Every action of this test wrote an audit record today.
	if strings.Contains(filled, `<span class="stat-value">0 events today</span>`) {
		t.Error("the audit card counts no event")
	}
	// Without a trust registry the card says so instead of a count.
	none := newHarness(t, false)
	none.signIn(t)
	if page := none.page(t, "/admin/"); !strings.Contains(page, `<span class="stat-value">No trust registry</span>`) {
		t.Error("the trust card does not name the missing registry")
	}
}

func TestChecklistMarksDoneItems(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	// The seeded admin provider is a Keycloak realm that still registers
	// users, the trust list is empty, and no other role has a provider.
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-admin", "vca-admin-realm", "admin")); err != nil {
		t.Fatal(err)
	}
	if err := h.app.Login.Providers().Delete("idp"); err != nil {
		t.Fatal(err)
	}
	page := h.page(t, "/admin/")
	items := checklistItems(page)
	want := map[string]string{
		msg.T("admin.checklist.register.text"):  "Done",
		msg.T("admin.checklist.self_reg.text"):  "To do",
		msg.T("admin.checklist.trust.text"):     "To do",
		msg.T("admin.checklist.providers.text"): "To do",
	}
	for text, state := range want {
		if got := items[text]; got != state {
			t.Errorf("%q = %q, want %q\n%s", text, got, state, page)
		}
	}
	if !strings.Contains(page, `vca-admin-realm`) {
		t.Error("the register item does not name the realm")
	}
	// The operator turns registration off at the realm and sets the
	// record to none; adds one trust entry; adds a provider for the
	// other three roles.
	kc := keycloakProvider(h, "kc-admin", "vca-admin-realm", "admin")
	kc.Registration = oidcflow.RegistrationNone
	if _, err := h.app.Login.Providers().Put(kc); err != nil {
		t.Fatal(err)
	}
	if status, _ := h.post(t, "/admin/trust", url.Values{
		"identifier": {"did:web:one.example"}, "display_name": {"One"}, "role": {"issuer"}, "status": {"active"},
	}); status != http.StatusSeeOther {
		t.Fatal("the trust entry failed")
	}
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-roles", "vca-issuer-realm", "issuer", "holder", "verifier")); err != nil {
		t.Fatal(err)
	}
	done := checklistItems(h.page(t, "/admin/"))
	for text := range want {
		if done[text] != "Done" {
			t.Errorf("%q = %q after the steps, want Done", text, done[text])
		}
	}
	// A provider role gap keeps the item open: a disabled provider does
	// not count.
	roles := keycloakProvider(h, "kc-roles", "vca-issuer-realm", "issuer", "holder", "verifier")
	roles.Enabled = false
	if _, err := h.app.Login.Providers().Put(roles); err != nil {
		t.Fatal(err)
	}
	if again := checklistItems(h.page(t, "/admin/")); again[msg.T("admin.checklist.providers.text")] != "To do" {
		t.Error("a disabled provider counts for its roles")
	}
}

// checklistItems maps the text of every checklist item to its state word.
func checklistItems(page string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(page, `<li class="check`)[1:] {
		state := between(part, `<span class="check-state">`, `</span>`)
		text := between(part, `<span class="check-text">`, `</span>`)
		out[text] = state
	}
	return out
}

// between returns the text between the first open and the next close.
func between(s, open, closing string) string {
	_, after, ok := strings.Cut(s, open)
	if !ok {
		return ""
	}
	before, _, _ := strings.Cut(after, closing)
	return before
}

func TestKeycloakConsoleLinksComeFromProviders(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	// The harness provider is generic: no console link anywhere.
	page := h.page(t, "/admin/")
	if strings.Contains(page, "console") || strings.Contains(page, msg.T("admin.nav.console.label")) {
		t.Fatalf("a generic provider gives a console link:\n%s", page)
	}
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-admin", "vca-admin-realm", "admin")); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-issuer", "vca-issuer-realm", "issuer")); err != nil {
		t.Fatal(err)
	}
	// A second record of the same realm gives one link, not two.
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-issuer-2", "vca-issuer-realm", "issuer")); err != nil {
		t.Fatal(err)
	}
	page = h.page(t, "/admin/")
	for _, want := range []string{
		`<p class="side-label" id="side-` /* the console section has a heading */, msg.T("admin.nav.console.label"),
		`<a href="https://kc.example/admin/vca-admin-realm/console/" rel="noopener">vca-admin-realm</a>`,
		`<a href="https://kc.example/admin/vca-issuer-realm/console/" rel="noopener">vca-issuer-realm</a>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("overview misses %q\n%s", want, page)
		}
	}
	// The admin realm appears twice: one link in the side navigation and
	// one button in the header. The issuer realm appears once.
	if n := strings.Count(page, `/admin/vca-admin-realm/console/`); n != 2 {
		t.Errorf("the admin realm console appears %d times, want 2", n)
	}
	if n := strings.Count(page, `/admin/vca-issuer-realm/console/`); n != 1 {
		t.Errorf("the issuer realm console appears %d times, want 1", n)
	}
	// The header of the overview carries the console button of the admin realm.
	if !strings.Contains(page, `<a class="btn btn-secondary" href="https://kc.example/admin/vca-admin-realm/console/"`) {
		t.Error("the overview header has no console button")
	}
}

func TestStackSwitcherListsAdminPairs(t *testing.T) {
	h := newHarnessWith(t, true, peers)
	h.signIn(t)
	page := h.page(t, "/admin/")
	for _, want := range []string{
		`<nav class="stack-nav" aria-label="Stack">`,
		`<a href="` + h.server.URL + `/admin/" aria-current="true">Stack One</a>`,
		`<span class="stack-starting">inji <span class="badge badge-warn">Starting</span></span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("overview misses %q\n%s", want, page)
		}
	}
	if strings.Contains(page, "credebl") {
		t.Error("an absent pair shows in the switcher")
	}
	// Without peers the switcher is absent and the page still renders.
	alone := newHarness(t, true)
	alone.signIn(t)
	if page := alone.page(t, "/admin/"); strings.Contains(page, `class="stack-nav"`) {
		t.Error("a deployment without peers draws a stack switcher")
	}
}

// TestOverviewCountsOnlyTrustedIssuers keeps a pending issuer and a
// verifier out of the trusted issuer count.
func TestOverviewCountsOnlyTrustedIssuers(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	h.seedTrust(didOf("did:web:active.example"), "Active issuer", trustv1.Status_STATUS_ACTIVE)
	h.seedTrust(didOf("did:web:pending.example"), "Pending issuer", trustv1.Status_STATUS_PENDING)
	h.trust.entries["did:web:verifier.example"] = &trustv1.TrustEntry{
		Identifier: didOf("did:web:verifier.example"), Role: commonv1.Role_ROLE_VERIFIER, Status: trustv1.Status_STATUS_ACTIVE,
	}
	if page := h.page(t, "/admin/"); !strings.Contains(page, `<span class="stat-value">1 trusted issuer</span>`) {
		t.Error("the trust card counts more than the active issuers")
	}
	// The registries card counts the external registries and opens the
	// registries tab.
	h.seedRegistries()
	page := h.page(t, "/admin/")
	for _, want := range []string{`<span class="stat-value">Local and 2 external</span>`, `<a class="stat-link" href="/admin/trust/registries">`} {
		if !strings.Contains(page, want) {
			t.Errorf("the overview misses %q", want)
		}
	}
}
