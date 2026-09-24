// SPDX-License-Identifier: Apache-2.0

package signin_test

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/signin"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
	"github.com/centre-for-dpi/vc-adapters/ui/components"
)

// registry returns a provider registry with the given records.
func registry(t *testing.T, providers ...oidcflow.Provider) *oidcflow.Registry {
	t.Helper()
	reg, err := oidcflow.NewRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range providers {
		if _, err := reg.Put(p); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

// keycloak is a seeded provider of kind keycloak, so the register action
// falls back to the registration endpoint of the realm.
func keycloak(idp *oidctest.Provider) oidcflow.Provider {
	return oidcflow.Provider{
		ID: "default", DisplayName: "Keycloak", DiscoveryURL: idp.DiscoveryURL(), ClientID: idp.ClientID, Enabled: true,
		Roles:        []string{"issuer"},
		Profile:      oidcflow.Profile{Kind: oidcflow.KindKeycloak, Realm: "vca-issuer-realm", IsDefault: true},
		ClientSecret: oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "X"},
	}
}

// plain is a generic provider whose metadata offers no registration.
func plain(idp *oidctest.Provider, id string, enabled bool) oidcflow.Provider {
	return oidcflow.Provider{
		ID: id, DisplayName: "Plain " + id, DiscoveryURL: idp.DiscoveryURL(), ClientID: idp.ClientID, Enabled: enabled,
		Roles: []string{"issuer"}, Profile: oidcflow.Profile{Kind: oidcflow.KindGeneric},
	}
}

// registrar records the register calls and answers with a fixed URL or
// error.
type registrar struct {
	url  string
	err  error
	last []string
}

func (r *registrar) Register(_ context.Context, providerID, returnTo string) (string, error) {
	r.last = []string{providerID, returnTo}
	return r.url, r.err
}

func kit(t *testing.T) *components.Kit {
	t.Helper()
	k, err := components.New()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func chooser(t *testing.T, opts signin.Options) *signin.Chooser {
	t.Helper()
	if opts.Kit == nil {
		opts.Kit = kit(t)
	}
	c, err := signin.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func mount(c *signin.Chooser, prefix string) http.Handler {
	mux := http.NewServeMux()
	c.Mount(mux, prefix)
	return mux
}

// TestChooserListsEnabledProvidersOfTheRole is board Signin: the page
// names the role, lists one button per enabled provider with its realm
// in the monospace stack, the default provider first, and leaves a
// disabled provider out. Every login link keeps return_to.
func TestChooserListsEnabledProvidersOfTheRole(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	reg := registry(t, plain(idp, "a-first", true), keycloak(idp), plain(idp, "off", false))
	flow := &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}
	c := chooser(t, signin.Options{Role: commonv1.Role_ROLE_ISSUER, Providers: reg, Registrar: &registrar{}, Metadata: flow, LandingURL: "https://vca.example"})
	rec := get(t, mount(c, "/auth"), "/auth/?return_to=/portal/schemas")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<title>Sign in</title>`, `<span class="role">Issuer</span>`, `<h1>Sign in as an issuer.</h1>`,
		`You return to the issuer portal after sign in.`, `<p class="signin-label">Continue with</p>`,
		`<a class="btn btn-primary signin-provider" href="/auth/login?provider=default&amp;return_to=%2Fportal%2Fschemas"><span>Keycloak</span><span class="signin-meta">vca-issuer-realm</span></a>`,
		`<a class="btn btn-secondary signin-provider" href="/auth/login?provider=a-first&amp;return_to=%2Fportal%2Fschemas"><span>Plain a-first</span></a>`,
		`<p class="signin-note">VCA is not tied to Keycloak. Any OIDC provider the admin adds appears here.</p>`,
		`<a class="wordmark" href="https://vca.example">`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("chooser missing %q\n%s", want, doc)
		}
	}
	if strings.Contains(doc, "Plain off") || strings.Contains(doc, "provider=off") {
		t.Error("a disabled provider is listed")
	}
	if strings.Contains(doc, "signin-callout") || strings.Contains(doc, "bootstrap") {
		t.Error("a role chooser has no admin callout and no bootstrap card")
	}
	// A bad return_to falls back to the home of the role.
	doc = get(t, mount(c, "/auth"), "/auth/?return_to=https://evil.example/").Body.String()
	if !strings.Contains(doc, `return_to=%2Fportal%2F"`) {
		t.Errorf("a bad return_to must fall back to /portal/:\n%s", doc)
	}
	// The same page serves at the root prefix.
	if rec := get(t, mount(c, ""), "/"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `href="/auth/login?provider=default`) {
		t.Errorf("root mount: %d", rec.Code)
	}
}

// TestChooserShowsRegisterOnlyWhenSupported is ADR-035 decision 3: the
// register action appears for a provider whose metadata lists
// prompt=create or whose kind is keycloak, and not for a generic
// provider without it.
func TestChooserShowsRegisterOnlyWhenSupported(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	flow := &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}
	// A generic provider without prompt=create: no register action, no rule.
	c := chooser(t, signin.Options{Role: commonv1.Role_ROLE_ISSUER, Providers: registry(t, plain(idp, "a", true)), Registrar: &registrar{}, Metadata: flow})
	doc := get(t, mount(c, "/auth"), "/auth/").Body.String()
	if strings.Contains(doc, "signin-register") || strings.Contains(doc, "signin-or") || strings.Contains(doc, "/auth/register") {
		t.Errorf("a provider without registration shows no register action:\n%s", doc)
	}
	// A keycloak record gets one.
	c = chooser(t, signin.Options{Role: commonv1.Role_ROLE_ISSUER, Providers: registry(t, keycloak(idp)), Registrar: &registrar{}, Metadata: flow})
	doc = get(t, mount(c, "/auth"), "/auth/").Body.String()
	if !strings.Contains(doc, `<span>or</span>`) || !strings.Contains(doc, `<a class="btn btn-ghost" href="/auth/register?provider=default&amp;return_to=%2Fportal%2F">Register a new account</a>`) {
		t.Errorf("a keycloak provider offers registration:\n%s", doc)
	}
	// Two providers with prompt=create get one button each, named.
	create := oidctest.New()
	create.PromptValuesSupported = []string{"login", "create"}
	defer create.Close()
	c = chooser(t, signin.Options{Role: commonv1.Role_ROLE_ISSUER, Providers: registry(t, plain(create, "a", true), plain(create, "b", true)), Registrar: &registrar{}, Metadata: flow})
	doc = get(t, mount(c, "/auth"), "/auth/").Body.String()
	for _, want := range []string{">Register with Plain a</a>", ">Register with Plain b</a>"} {
		if !strings.Contains(doc, want) {
			t.Errorf("chooser missing %q\n%s", want, doc)
		}
	}
	// Without a metadata reader the record alone decides.
	c = chooser(t, signin.Options{Role: commonv1.Role_ROLE_ISSUER, Providers: registry(t, plain(create, "a", true)), Registrar: &registrar{}})
	if doc := get(t, mount(c, "/auth"), "/auth/").Body.String(); strings.Contains(doc, "/auth/register") {
		t.Errorf("a generic record without metadata offers no registration:\n%s", doc)
	}
}

// TestChooserAdminShowsBootstrapField is board Signin-Admin: the admin
// page carries the first admin callout and the bootstrap card with the
// token field, which the extra block renders.
func TestChooserAdminShowsBootstrapField(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	k := kit(t)
	extra := func(returnTo string) (template.HTML, error) {
		field, err := k.HTML("field", components.Field{ID: "bootstrap_token", Label: "Bootstrap token", Type: "password"})
		if err != nil {
			return "", err
		}
		return k.HTML("card", components.Card{ID: "bootstrap", Title: "First super admin", Body: components.Join(field, template.HTML(`<input type="hidden" name="return_to" value="`+template.HTMLEscapeString(returnTo)+`">`))}) //nolint:gosec // escaped
	}
	c := chooser(t, signin.Options{
		Kit: k, Role: commonv1.Role_ROLE_ADMIN, Providers: registry(t, keycloak(idp)), Registrar: &registrar{},
		Callout: true, Extra: extra, LoginPath: "/auth/login", Home: "/admin/",
		Toasts: func(*http.Request) []components.Toast {
			return []components.Toast{{Level: "info", Text: "You are signed out."}}
		},
	})
	rec := get(t, mount(c, "/auth"), "/auth/")
	doc := rec.Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<h1>Sign in as an admin.</h1>`, `<span class="role">Admin</span>`,
		`<div class="signin-callout"><strong>First admin after deployment?</strong> Paste the bootstrap token, then register or sign in.`,
		`<section class="card" id="bootstrap"`, `<input type="password" id="bootstrap_token" name="bootstrap_token"`, `name="return_to" value="/admin/"`,
		`class="toast toast-info"`, `return_to=%2Fadmin%2F`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("admin chooser missing %q\n%s", want, doc)
		}
	}
	// An extra block that fails takes the page down.
	broken := chooser(t, signin.Options{Kit: k, Role: commonv1.Role_ROLE_ADMIN, Providers: registry(t), Extra: func(string) (template.HTML, error) { return "", errors.New("boom") }})
	if rec := get(t, mount(broken, "/auth"), "/auth/"); rec.Code != http.StatusInternalServerError {
		t.Errorf("broken extra: status %d", rec.Code)
	}
}

// TestProvidersJSONHasNoSecret is the listing the landing reads: id,
// display name, realm, and the register flag, and nothing else. A
// disabled provider is absent.
func TestProvidersJSONHasNoSecret(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	flow := &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)}
	c := chooser(t, signin.Options{Role: commonv1.Role_ROLE_ISSUER, Providers: registry(t, keycloak(idp), plain(idp, "b", true), plain(idp, "off", false)), Metadata: flow})
	rec := get(t, mount(c, "/auth"), "/auth/providers.json")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d, headers %v", rec.Code, rec.Header())
	}
	body := rec.Body.String()
	for _, secret := range []string{"client_secret", "discovery_url", "client_id", idp.ClientID, "VCA_OIDC", "X\""} {
		if strings.Contains(body, secret) {
			t.Errorf("providers.json leaks %q: %s", secret, body)
		}
	}
	var listing signin.Listing
	if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if listing.Role != "issuer" || len(listing.Providers) != 2 {
		t.Fatalf("listing = %+v", listing)
	}
	if first := listing.Providers[0]; first.ID != "default" || first.DisplayName != "Keycloak" || first.Realm != "vca-issuer-realm" || !first.Register {
		t.Errorf("first = %+v", first)
	}
	if second := listing.Providers[1]; second.ID != "b" || second.Realm != "" || second.Register {
		t.Errorf("second = %+v", second)
	}
	var raw []map[string]any
	if err := json.Unmarshal([]byte(gjson(body, "providers")), &raw); err != nil {
		t.Fatal(err)
	}
	for _, entry := range raw {
		if len(entry) != 4 {
			t.Errorf("entry has %d fields, want id, display_name, realm, register: %v", len(entry), entry)
		}
	}
	// Fetch reads the same listing from a running service.
	srv := httptest.NewServer(mount(c, "/auth"))
	defer srv.Close()
	got, err := signin.Fetch(context.Background(), srv.Client(), srv.URL)
	if err != nil || got.Role != "issuer" || len(got.Providers) != 2 || got.Providers[0].Realm != "vca-issuer-realm" {
		t.Errorf("Fetch = %+v, %v", got, err)
	}
	if _, err := signin.Fetch(context.Background(), srv.Client(), srv.URL+"/nowhere"); err == nil {
		t.Error("a 404 must fail")
	}
	if _, err := signin.Fetch(context.Background(), srv.Client(), "http://127.0.0.1:1"); err == nil {
		t.Error("a refused connection must fail")
	}
	if _, err := signin.Fetch(context.Background(), srv.Client(), "::bad"); err == nil {
		t.Error("a bad URL must fail")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { anyval.DiscardWrite(w.Write([]byte("{"))) }))
	defer bad.Close()
	if _, err := signin.Fetch(context.Background(), bad.Client(), bad.URL); err == nil {
		t.Error("a body that is not JSON must fail")
	}
}

// gjson returns the raw JSON of one top level key.
func gjson(body, key string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return ""
	}
	return string(m[key])
}

// TestChooserLinksBackToTheLanding keeps the way back: the back link and
// the header point at the landing when the service knows it, and the
// page has no back link without it.
func TestChooserLinksBackToTheLanding(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	with := chooser(t, signin.Options{Role: commonv1.Role_ROLE_HOLDER, Providers: registry(t, keycloak(idp)), LandingURL: "https://vca.example/"})
	doc := get(t, mount(with, "/auth"), "/auth/").Body.String()
	a11ytest.AssertPage(t, doc)
	for _, want := range []string{
		`<a class="signin-back" href="https://vca.example/roles/" rel="noopener">Choose another role</a>`,
		`<a href="https://vca.example/#how" rel="noopener">How it works</a>`, `<a href="https://vca.example/roles/" rel="noopener">Start</a>`,
		`return_to=%2Fwallet%2F`, `<h1>Sign in as a holder.</h1>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("chooser missing %q\n%s", want, doc)
		}
	}
	without := chooser(t, signin.Options{Role: commonv1.Role_ROLE_VERIFIER, Providers: registry(t)})
	doc = get(t, mount(without, "/auth"), "/auth/").Body.String()
	a11ytest.AssertPage(t, doc)
	if strings.Contains(doc, "signin-back") || strings.Contains(doc, "How it works") {
		t.Errorf("no landing, no way back:\n%s", doc)
	}
	if !strings.Contains(doc, `<p class="signin-empty">This deployment has no login provider yet. Ask the admin to add one.</p>`) {
		t.Errorf("an empty registry names the gap:\n%s", doc)
	}
}

// TestRegisterRedirectsOrGives404 sends the browser to the register URL
// of the provider, and answers 404 when the provider offers none.
func TestRegisterRedirectsOrGives404(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	reg := &registrar{url: "https://idp.example/registrations?x=1"}
	c := chooser(t, signin.Options{Role: commonv1.Role_ROLE_ISSUER, Providers: registry(t, keycloak(idp)), Registrar: reg})
	rec := get(t, mount(c, "/auth"), "/auth/register?provider=default&return_to=/portal/")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != reg.url || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("register: %d %v", rec.Code, rec.Header())
	}
	if reg.last[0] != "default" || reg.last[1] != "/portal/" {
		t.Errorf("registrar got %v", reg.last)
	}
	reg.err = oidcflow.ErrRegisterUnsupported
	if rec := get(t, mount(c, "/auth"), "/auth/register?provider=default"); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not_found") {
		t.Errorf("unsupported: %d %s", rec.Code, rec.Body.String())
	}
	reg.err = oidcflow.ErrProviderNotFound
	if rec := get(t, mount(c, "/auth"), "/auth/register?provider=nope"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown provider: %d", rec.Code)
	}
	// A token in the query is refused before anything else.
	if rec := get(t, mount(c, "/auth"), "/auth/register?provider=default&access_token=x"); rec.Code != http.StatusBadRequest {
		t.Errorf("query token: %d", rec.Code)
	}
	// Without a registrar the route is absent.
	none := chooser(t, signin.Options{Role: commonv1.Role_ROLE_ISSUER, Providers: registry(t, keycloak(idp))})
	if rec := get(t, mount(none, "/auth"), "/auth/register?provider=default"); rec.Code != http.StatusNotFound {
		t.Errorf("no registrar: %d", rec.Code)
	}
}

// TestNewRejectsMissingParts keeps the constructor honest.
func TestNewRejectsMissingParts(t *testing.T) {
	k := kit(t)
	reg := registry(t)
	for name, opts := range map[string]signin.Options{
		"no kit":       {Role: commonv1.Role_ROLE_ISSUER, Providers: reg},
		"no role":      {Kit: k, Providers: reg},
		"no providers": {Kit: k, Role: commonv1.Role_ROLE_ISSUER},
	} {
		if _, err := signin.New(opts); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// A kit without templates fails the page with 500.
	c, err := signin.New(signin.Options{Kit: &components.Kit{}, Role: commonv1.Role_ROLE_ISSUER, Providers: reg})
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(t, mount(c, "/auth"), "/auth/"); rec.Code != http.StatusInternalServerError {
		t.Errorf("empty kit: status %d", rec.Code)
	}
}
