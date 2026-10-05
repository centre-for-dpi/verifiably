// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// realmProvider is the provider that setup writes into the auth service
// of a role pair: the Keycloak realm of that role.
func realmProvider(h *harness, id, realm, role string) oidcflow.Provider {
	return oidcflow.Provider{
		ID: id, DisplayName: "Keycloak", DiscoveryURL: "https://kc.example/realms/" + realm + "/.well-known/openid-configuration",
		ClientID: "vca-" + role, Enabled: true, Roles: []string{role},
		Profile: oidcflow.Profile{
			Kind: oidcflow.KindKeycloak, Realm: realm, IsDefault: true,
			ConsoleURL: "https://kc.example/admin/" + realm + "/console/",
		},
	}
}

// pairRealms is livePairs with the realm provider that setup made in the
// auth service of the issuer pair and of the holder pair.
func pairRealms(t *testing.T, h *harness) func(*config.Config, *app.Deps) {
	t.Helper()
	more := livePairs(t, h)
	for pair, realm := range map[string]string{"issuer-waltid": "vca-issuer-realm", "holder-waltid": "vca-holder-realm"} {
		role := strings.SplitN(pair, "-", 2)[0]
		if _, err := h.auth[pair].registry.Put(realmProvider(h, oidcflow.SeedID, realm, role)); err != nil {
			t.Fatal(err)
		}
	}
	return more
}

// TestOverviewListsEveryLoginProviderInUse is review finding 8: the
// overview counts the providers and the realms of the auth services of
// the live pairs too, so a holder realm that setup made is not missing.
func TestOverviewListsEveryLoginProviderInUse(t *testing.T) {
	h := newHarnessWith(t, true, pairRealms)
	h.signIn(t)
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-admin", "vca-admin-realm", "admin")); err != nil {
		t.Fatal(err)
	}
	if err := h.app.Login.Providers().Delete("idp"); err != nil {
		t.Fatal(err)
	}
	page := h.page(t, "/admin/")
	for _, want := range []string{"3 providers", "3 realms"} {
		if !strings.Contains(page, want) {
			t.Errorf("the overview lacks %q", want)
		}
	}
	// The admin realm, the issuer pair and the holder pair have a
	// provider. Only the verifier pair, which is not live, has none.
	if !strings.Contains(page, "No provider yet for verifiers.") {
		t.Errorf("the checklist does not name the one role without a provider\n%s", page)
	}
	providers := h.page(t, "/admin/providers")
	for _, want := range []string{
		`id="pair-providers"`, "Providers of each pair", "holder-waltid", "issuer-waltid",
		"vca-holder-realm", "vca-issuer-realm",
	} {
		if !strings.Contains(providers, want) {
			t.Errorf("the providers page lacks %q", want)
		}
	}
}

// TestManagementConsoleCard is the console redirect of the admin (spec
// admin, review finding 5): each provider record that names a console
// gets a link, and the link sends the browser to that console.
func TestManagementConsoleCard(t *testing.T) {
	h := newHarnessWith(t, true, pairRealms)
	h.signIn(t)
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-admin", "vca-admin-realm", "admin")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/admin/", "/admin/providers"} {
		page := h.page(t, path)
		for _, want := range []string{
			`id="consoles"`, "Management consoles",
			`href="/admin/providers/kc-admin/console"`,
			`href="/admin/providers/pairs/holder-waltid/default/console"`,
		} {
			if !strings.Contains(page, want) {
				t.Errorf("%s lacks %q", path, want)
			}
		}
		if strings.Contains(page, `href="/admin/providers/idp/console"`) {
			t.Errorf("%s links a console for a provider that names none", path)
		}
	}
	for path, want := range map[string]string{
		"/admin/providers/kc-admin/console":                    "https://kc.example/admin/vca-admin-realm/console/",
		"/admin/providers/pairs/holder-waltid/default/console": "https://kc.example/admin/vca-holder-realm/console/",
		"/admin/providers/pairs/issuer-waltid/default/console": "https://kc.example/admin/vca-issuer-realm/console/",
	} {
		res, err := h.client.Get(h.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if cerr := res.Body.Close(); cerr != nil {
			t.Fatal(cerr)
		}
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("%s: %d to %q, want %q", path, res.StatusCode, res.Header.Get("Location"), want)
		}
	}
	for _, path := range []string{"/admin/providers/idp/console", "/admin/providers/pairs/holder-waltid/none/console", "/admin/providers/pairs/nowhere/default/console"} {
		if status, _ := h.get(t, path); status != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, status)
		}
	}
}

// TestProviderSetDefault is review finding 22: the admin makes another
// provider the default, and the old default gives the flag up.
func TestProviderSetDefault(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-admin", "vca-admin-realm", "admin")); err != nil {
		t.Fatal(err)
	}
	page := h.page(t, "/admin/providers")
	if !strings.Contains(page, `action="/admin/providers/idp/default"`) || strings.Contains(page, `action="/admin/providers/kc-admin/default"`) {
		t.Fatalf("the make default action is not on the right rows\n%s", page)
	}
	if status, _ := h.post(t, "/admin/providers/idp/default", nil); status != http.StatusSeeOther {
		t.Fatalf("make default: %d", status)
	}
	idp, ierr := h.app.Login.Providers().Get("idp")
	kc, kerr := h.app.Login.Providers().Get("kc-admin")
	if ierr != nil || kerr != nil || !idp.IsDefault || kc.IsDefault {
		t.Fatalf("after make default: idp %v, kc-admin %v", idp.IsDefault, kc.IsDefault)
	}
	if after := h.page(t, "/admin/providers?notice=provider-default"); !strings.Contains(after, "The provider is the default now.") {
		t.Errorf("no notice after make default\n%s", after)
	}
	if status, _ := h.post(t, "/admin/providers/missing/default", nil); status != http.StatusNotFound {
		t.Errorf("an unknown provider became the default: %d", status)
	}
}

// TestProviderFormSetsTheConsole lets the admin name the management
// console of a provider of any kind.
func TestProviderFormSetsTheConsole(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if form := h.page(t, "/admin/providers/new"); !strings.Contains(form, `name="console_url"`) {
		t.Fatal("the form has no console field")
	}
	if status, body := h.post(t, "/admin/providers", providerForm(h, url.Values{"console_url": {"https://idp.example/console"}})); status != http.StatusOK {
		t.Fatalf("save: %d\n%s", status, body)
	}
	if got := providerByName(t, h, "National IdP").ConsoleURL; got != "https://idp.example/console" {
		t.Fatalf("console = %q", got)
	}
	if status, _ := h.post(t, "/admin/providers", providerForm(h, url.Values{"display_name": {"Bad"}, "console_url": {"javascript:alert(1)"}})); status == http.StatusOK {
		if p := providerByNameOrZero(h, "Bad"); p.ConsoleURL != "" {
			t.Fatalf("a script URL became a console: %q", p.ConsoleURL)
		}
	}
}

// providerByNameOrZero returns the record with a display name, or the
// zero record.
func providerByNameOrZero(h *harness, name string) oidcflow.Provider {
	for _, p := range h.app.Login.Providers().List() {
		if p.DisplayName == name {
			return p
		}
	}
	return oidcflow.Provider{}
}
