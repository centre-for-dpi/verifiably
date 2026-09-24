// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	configv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/config/v1"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// pairAuth is the fake auth service of one live pair: the provider RPCs
// over a registry that accepts what the admin key set signed.
type pairAuth struct {
	registry *oidcflow.Registry
	server   *httptest.Server
}

// livePairs is a fake deployment with a live issuer pair and a live
// holder pair on one stack, each with an auth service, and a starting
// verifier pair. The registries land on the harness under auth.
func livePairs(t *testing.T, h *harness) func(*config.Config, *app.Deps) {
	t.Helper()
	ready := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("ready"))
	}))
	t.Cleanup(ready.Close)
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	h.auth = map[string]*pairAuth{}
	for _, role := range []string{"issuer", "holder"} {
		registry, err := oidcflow.NewRegistry(oidcflow.NewMemoryPersister(), nil)
		if err != nil {
			t.Fatal(err)
		}
		accept := func(_ context.Context, hdr http.Header) error {
			_, verr := h.app.Login.Signer().Verify(oidcflow.TokenFromRequest(&http.Request{Header: hdr}, ""))
			return verr
		}
		mux := http.NewServeMux()
		mux.Handle(oidcflow.NewAdminHandler(oidcflow.AdminProviders{Registry: registry, Authorize: accept, Roles: []string{role}}))
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		h.auth[role+"-waltid"] = &pairAuth{registry: registry, server: srv}
	}
	return func(cfg *config.Config, deps *app.Deps) {
		cfg.Peers = []topology.Peer{
			{Pair: "issuer-waltid", Role: commonv1.Role_ROLE_ISSUER, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: "https://issuer-waltid.example",
				Services: map[string]string{"schema-registry": ready.URL, "issuer-auth": h.auth["issuer-waltid"].server.URL}},
			{Pair: "holder-waltid", Role: commonv1.Role_ROLE_HOLDER, Dpg: configv1.Dpg_DPG_WALTID, PublicURL: "https://holder-waltid.example",
				Services: map[string]string{"wallet-portal": ready.URL, "wallet-auth": h.auth["holder-waltid"].server.URL}},
			{Pair: "verifier-inji", Role: commonv1.Role_ROLE_VERIFIER, Dpg: configv1.Dpg_DPG_INJI, PublicURL: "https://verifier-inji.example",
				Services: map[string]string{"verifier-results": down.URL}},
		}
		deps.Prober = &topology.Prober{Peers: cfg.Peers, Lookup: func(context.Context, string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		}}
	}
}

// providerForm is a filled provider form with the given overrides.
func providerForm(h *harness, over url.Values) url.Values {
	form := url.Values{
		"kind": {"generic"}, "display_name": {"National IdP"}, "issuer": {h.idp.Issuer()},
		"client": {"given"}, "client_id": {h.idp.ClientID}, "roles": {"issuer", "holder"},
	}
	for k, v := range over {
		form[k] = v
	}
	return form
}

// providerByName returns the record with a display name.
func providerByName(t *testing.T, h *harness, name string) oidcflow.Provider {
	t.Helper()
	for _, p := range h.app.Login.Providers().List() {
		if p.DisplayName == name {
			return p
		}
	}
	t.Fatalf("no provider named %q", name)
	return oidcflow.Provider{}
}

func TestProvidersTableShowsRealmRoleStacks(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if err := h.app.Login.Providers().Delete("idp"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.Login.Providers().Put(keycloakProvider(h, "kc-admin", "vca-admin-realm", "admin")); err != nil {
		t.Fatal(err)
	}
	wso2 := oidcflow.Provider{
		ID: "wso2", DisplayName: "National IdP", DiscoveryURL: "https://is.example/oauth2/token/.well-known/openid-configuration",
		ClientID: "vca", Enabled: false, Roles: []string{"issuer", "holder"},
		Profile: oidcflow.Profile{Kind: oidcflow.KindWSO2, Stacks: []string{"waltid"}},
	}
	if _, err := h.app.Login.Providers().Put(wso2); err != nil {
		t.Fatal(err)
	}
	page := h.page(t, "/admin/providers")
	for _, want := range []string{
		`<h1>Login providers</h1>`, `<th scope="col">Provider</th>`, `<th scope="col">Realm or issuer</th>`,
		`<th scope="col">Roles</th>`, `<th scope="col">Stacks</th>`, `<th scope="col">State</th>`, `<th scope="col">Default</th>`,
		`<a class="btn btn-primary" href="/admin/providers/new"`, `Add provider</a>`,
		// The Keycloak row: realm, role, every stack, enabled, default.
		`<a href="/admin/providers/kc-admin">Keycloak</a>`, `<td>vca-admin-realm</td>`, `<td>Admin</td>`, `<td>All</td>`,
		`>Enabled</span>`, `>Default</span>`,
		// The WSO2 row: the issuer, two roles, one stack, disabled.
		`<a href="/admin/providers/wso2">National IdP</a>`, `<td>https://is.example/oauth2/token</td>`, `<td>Issuer, Holder</td>`, `<td>waltid</td>`,
		`>Disabled</span>`,
		// Row actions: turn on or off, remove.
		`action="/admin/providers/kc-admin/enable"`,
		`<input type="hidden" name="enabled" value="false">`, `>Turn off</button>`,
		`action="/admin/providers/wso2/enable"`, `<input type="hidden" name="enabled" value="true">`, `>Turn on</button>`,
		`action="/admin/providers/wso2/delete"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("providers page misses %q\n%s", want, page)
		}
	}
	if strings.Contains(page, h.idp.ClientID) {
		t.Error("the table shows a client id")
	}
	// An empty registry shows the empty state with the one action.
	for _, p := range h.app.Login.Providers().List() {
		if err := h.app.Login.Providers().Delete(p.ID); err != nil {
			t.Fatal(err)
		}
	}
	if empty := h.page(t, "/admin/providers"); !strings.Contains(empty, `class="empty"`) || !strings.Contains(empty, `href="/admin/providers/new"`) {
		t.Errorf("empty page:\n%s", empty)
	}
}

func TestProviderFormOffersPresetsRolesAndStacks(t *testing.T) {
	h := newHarnessWith(t, true, livePairs)
	h.signIn(t)
	form := h.page(t, "/admin/providers/new")
	for _, want := range []string{
		`<h1>New provider</h1>`, `<select id="kind" name="kind"`,
		`<option value="keycloak" selected>Keycloak</option>`, `<option value="wso2">WSO2 Identity Server</option>`,
		`<option value="esignet">eSignet</option>`, `<option value="generic"`,
		`id="display_name"`, `id="issuer"`, `id="client_id"`, `id="client_secret_env"`, `id="private_key_env"`,
		`<select id="token_auth"`, `<option value="private_key_jwt">`, `<select id="register"`,
		`<fieldset class="choice" id="roles">`, `name="roles" value="issuer"`, `name="roles" value="admin"`,
		`<fieldset class="choice" id="stacks">`, `name="stacks" value="waltid"`, `name="stacks" value="inji"`,
		`hx-post="/admin/providers/test"`, `hx-target="#discovery"`, `formaction="/admin/providers/test"`,
		`>Test discovery</button>`, `>Save provider</button>`, `<div id="discovery">`,
	} {
		if !strings.Contains(form, want) {
			t.Errorf("form misses %q\n%s", want, form)
		}
	}
	// A stack with no present pair is not on offer.
	if strings.Contains(form, `name="stacks" value="credebl"`) {
		t.Error("the form offers a stack that does not run")
	}
	// Without peers the form names no stack and says every stack applies.
	alone := newHarness(t, true)
	alone.signIn(t)
	if page := alone.page(t, "/admin/providers/new"); strings.Contains(page, `id="stacks"`) {
		t.Error("a deployment without peers offers a stack choice")
	}
}

func TestTestDiscoveryReportsEndpoints(t *testing.T) {
	h := newHarness(t, true)
	h.idp.PromptValuesSupported = []string{"login", "create"}
	h.signIn(t)
	form := providerForm(h, url.Values{"kind": {"keycloak"}})
	form.Set(oidcflow.CSRFField, h.csrf)
	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/admin/providers/test", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(res.Body)
	if cerr := res.Body.Close(); cerr != nil {
		t.Error(cerr)
	}
	if err != nil {
		t.Fatal(err)
	}
	fragment := string(raw)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d\n%s", res.StatusCode, fragment)
	}
	a11ytest.AssertFragment(t, fragment)
	for _, want := range []string{
		`<section class="card" id="discovery-result"`, h.idp.Issuer() + `/.well-known/openid-configuration`,
		h.idp.Issuer() + `/authorize`, h.idp.Issuer() + `/token`, `prompt=create`, `client_secret_basic`,
	} {
		if !strings.Contains(fragment, want) {
			t.Errorf("fragment misses %q\n%s", want, fragment)
		}
	}
	if strings.Contains(fragment, "<html") {
		t.Error("an htmx request got the whole page")
	}
	// Without htmx the same action renders the form page with the result.
	status, page := h.post(t, "/admin/providers/test", providerForm(h, nil))
	if status != http.StatusOK {
		t.Fatalf("plain status = %d", status)
	}
	a11ytest.AssertPage(t, page)
	if !strings.Contains(page, `id="discovery-result"`) || !strings.Contains(page, `value="National IdP"`) {
		t.Errorf("the plain answer lost the result or the typed values:\n%s", page)
	}
}

func TestTestDiscoveryRejectsPrivateAddress(t *testing.T) {
	h := newHarnessWith(t, true, func(*testing.T, *harness) func(*config.Config, *app.Deps) {
		return func(cfg *config.Config, _ *app.Deps) { cfg.AllowPrivateNetwork = false }
	})
	h.signIn(t)
	status, page := h.post(t, "/admin/providers/test", providerForm(h, nil))
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if !strings.Contains(page, "is not a public address") {
		t.Errorf("the page does not name the refusal:\n%s", page)
	}
	if strings.Contains(page, h.idp.Issuer()+`/authorize`) {
		t.Error("the guard let the fetch through")
	}
}

func TestSaveFansOutAndReportsTargets(t *testing.T) {
	h := newHarnessWith(t, true, livePairs)
	h.signIn(t)
	status, page := h.post(t, "/admin/providers", providerForm(h, url.Values{"stacks": {"waltid"}, "client_secret_env": {"VCA_TEST_SECRET"}}))
	if status != http.StatusOK {
		t.Fatalf("save = %d\n%s", status, page)
	}
	a11ytest.AssertPage(t, page)
	for _, want := range []string{
		`class="toast toast-ok"`, `The login provider is ready.`,
		`issuer-waltid: the auth service took the provider.`, `holder-waltid: the auth service took the provider.`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("save page misses %q\n%s", want, page)
		}
	}
	for pair, auth := range h.auth {
		list := auth.registry.List()
		if len(list) != 1 || list[0].DisplayName != "National IdP" || list[0].ClientSecret.Name != "VCA_TEST_SECRET" {
			t.Errorf("%s holds %+v", pair, list)
		}
	}
	// A target that stops answering shows as a failure, in a warn toast.
	h.auth["holder-waltid"].server.Close()
	stored := providerByName(t, h, "National IdP")
	status, page = h.post(t, "/admin/providers/"+stored.ID, providerForm(h, url.Values{"display_name": {"Renamed"}, "stacks": {"waltid"}}))
	if status != http.StatusOK {
		t.Fatalf("edit = %d\n%s", status, page)
	}
	if !strings.Contains(page, `issuer-waltid: the auth service took the provider.`) || !strings.Contains(page, `holder-waltid: `) || !strings.Contains(page, `class="toast toast-warn"`) {
		t.Errorf("edit page misses the report:\n%s", page)
	}
	if list := h.auth["issuer-waltid"].registry.List(); len(list) != 1 || list[0].DisplayName != "Renamed" {
		t.Errorf("issuer-waltid after the edit holds %+v", list)
	}
}

func TestEditKeepsSecretRef(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, page := h.post(t, "/admin/providers", providerForm(h, url.Values{
		"kind": {"wso2"}, "client_secret_env": {"VCA_TEST_SECRET"},
	})); status != http.StatusOK {
		t.Fatalf("save = %d\n%s", status, page)
	}
	stored := providerByName(t, h, "National IdP")
	// The preset filled the kind and the claim path.
	if stored.Kind != oidcflow.KindWSO2 || stored.RolesClaimPath != "groups" || stored.ClientSecret.Name != "VCA_TEST_SECRET" {
		t.Fatalf("stored = %+v", stored)
	}
	form := h.page(t, "/admin/providers/"+stored.ID)
	for _, want := range []string{
		`<h1>Edit provider</h1>`, `value="National IdP"`, `<option value="wso2" selected>`, `value="groups"`,
		`name="roles" value="issuer"`, `checked`, `The record holds a reference.`,
	} {
		if !strings.Contains(form, want) {
			t.Errorf("edit form misses %q\n%s", want, form)
		}
	}
	// The secret field is empty: the form never echoes a reference value.
	if strings.Contains(form, `value="VCA_TEST_SECRET"`) {
		t.Error("the edit form echoes the secret reference")
	}
	// Saving with an empty secret field keeps the reference.
	if status, page := h.post(t, "/admin/providers/"+stored.ID, providerForm(h, url.Values{
		"kind": {"wso2"}, "display_name": {"Renamed"}, "roles": {"verifier"},
	})); status != http.StatusOK {
		t.Fatalf("edit = %d\n%s", status, page)
	}
	after := providerByName(t, h, "Renamed")
	if after.ID != stored.ID || after.ClientSecret.Name != "VCA_TEST_SECRET" || strings.Join(after.Roles, ",") != "verifier" {
		t.Fatalf("after the edit: %+v", after)
	}
	// An unknown id is not found; a bad issuer is a bad request.
	if status, _ := h.get(t, "/admin/providers/missing"); status != http.StatusNotFound {
		t.Errorf("unknown provider = %d", status)
	}
	if status, _ := h.post(t, "/admin/providers", providerForm(h, url.Values{"issuer": {"nowhere"}})); status != http.StatusBadRequest {
		t.Errorf("a bad issuer = %d", status)
	}
}

func TestEnableToggle(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, _ := h.post(t, "/admin/providers/idp/enable", url.Values{"enabled": {"false"}}); status != http.StatusSeeOther {
		t.Fatal("disable failed")
	}
	if p, err := h.app.Login.Providers().Get("idp"); err != nil || p.Enabled {
		t.Fatalf("after disable: %+v %v", p, err)
	}
	page := h.page(t, "/admin/providers?notice=provider-disabled")
	if !strings.Contains(page, `>Disabled</span>`) || !strings.Contains(page, "The login provider is off.") {
		t.Errorf("page after disable:\n%s", page)
	}
	if status, _ := h.post(t, "/admin/providers/idp/enable", url.Values{"enabled": {"true"}}); status != http.StatusSeeOther {
		t.Fatal("enable failed")
	}
	if p, err := h.app.Login.Providers().Get("idp"); err != nil || !p.Enabled {
		t.Fatalf("after enable: %+v %v", p, err)
	}
	if status, _ := h.post(t, "/admin/providers/missing/enable", url.Values{"enabled": {"true"}}); status != http.StatusNotFound {
		t.Error("an unknown provider toggled")
	}
}

func TestProviderWithDynamicRegistration(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	status, page := h.post(t, "/admin/providers", providerForm(h, url.Values{
		"issuer": {h.regIDP.URL}, "display_name": {"Registered"}, "client": {"dynamic"}, "client_id": {""},
	}))
	if status != http.StatusOK {
		t.Fatalf("save = %d\n%s", status, page)
	}
	if p := providerByName(t, h, "Registered"); p.ClientID != "registered" {
		t.Fatalf("registered client = %+v", p)
	}
	if list := h.page(t, "/admin/providers"); !strings.Contains(list, "Registered") {
		t.Fatal("the provider is not on the page")
	}
	// Remove works from the table.
	p := providerByName(t, h, "Registered")
	if status, _ := h.post(t, "/admin/providers/"+p.ID+"/delete", nil); status != http.StatusSeeOther {
		t.Fatal("the remove action failed")
	}
	if list := h.page(t, "/admin/providers"); strings.Contains(list, "Registered") {
		t.Fatal("the provider is still on the page")
	}
}
