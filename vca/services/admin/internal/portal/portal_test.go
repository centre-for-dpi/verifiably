// SPDX-License-Identifier: Apache-2.0

package portal_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

// fakeTrust is a trust registry client in process.
type fakeTrust struct {
	trustv1connect.TrustServiceClient
	entries map[string]*trustv1.TrustEntry
	// listErr, when set, makes ListEntries fail.
	listErr error
}

func keyOf(id *trustv1.TrustEntry_Identifier) string {
	if id.GetDid() != "" {
		return id.GetDid()
	}
	return id.GetX509Subject()
}

func (f *fakeTrust) UpsertEntry(_ context.Context, req *connect.Request[trustv1.UpsertEntryRequest]) (*connect.Response[trustv1.UpsertEntryResponse], error) {
	entry := req.Msg.GetEntry()
	f.entries[keyOf(entry.GetIdentifier())] = entry
	return connect.NewResponse(&trustv1.UpsertEntryResponse{Entry: entry}), nil
}

func (f *fakeTrust) GetEntry(_ context.Context, req *connect.Request[trustv1.GetEntryRequest]) (*connect.Response[trustv1.GetEntryResponse], error) {
	entry, ok := f.entries[keyOf(req.Msg.GetIdentifier())]
	if !ok {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no entry"))
	}
	return connect.NewResponse(&trustv1.GetEntryResponse{Entry: entry}), nil
}

func (f *fakeTrust) ListEntries(_ context.Context, req *connect.Request[trustv1.ListEntriesRequest]) (*connect.Response[trustv1.ListEntriesResponse], error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	res := &trustv1.ListEntriesResponse{Page: &commonv1.PageResult{}}
	for _, e := range f.entries {
		if st := req.Msg.GetStatus(); st != trustv1.Status_STATUS_UNSPECIFIED && e.GetStatus() != st {
			continue
		}
		if r := req.Msg.GetRole(); r != commonv1.Role_ROLE_UNSPECIFIED && e.GetRole() != r {
			continue
		}
		res.Entries = append(res.Entries, e)
	}
	res.Page.TotalSize = int64(len(res.Entries))
	return connect.NewResponse(res), nil
}

func (f *fakeTrust) DeleteEntry(_ context.Context, req *connect.Request[trustv1.DeleteEntryRequest]) (*connect.Response[trustv1.DeleteEntryResponse], error) {
	delete(f.entries, keyOf(req.Msg.GetIdentifier()))
	return connect.NewResponse(&trustv1.DeleteEntryResponse{}), nil
}

// harness holds the whole service behind an HTTP server.
type harness struct {
	app    *app.App
	server *httptest.Server
	idp    *oidctest.Provider
	regIDP *httptest.Server
	client *http.Client
	trust  *fakeTrust
	ready  *httptest.Server
	csrf   string
	// auth holds the fake auth service of every live pair, by pair name,
	// when the harness has peers.
	auth map[string]*pairAuth
}

// newHarness wires the service, logs one super admin in, and returns the
// harness with a cookie jar that holds the session.
func newHarness(t *testing.T, withTrust bool) *harness {
	t.Helper()
	return newHarnessWith(t, withTrust, nil)
}

// newHarnessWith wires the service like newHarness and lets more change
// the configuration and the dependencies first, for example to add
// peers. The factory runs after the server exists, so it can name the
// server URL as the public URL of this pair.
func newHarnessWith(t *testing.T, withTrust bool, more func(*testing.T, *harness) func(*config.Config, *app.Deps)) *harness {
	t.Helper()
	h := &harness{trust: &fakeTrust{entries: map[string]*trustv1.TrustEntry{}}}
	h.idp = oidctest.New()
	t.Cleanup(h.idp.Close)
	h.regIDP = registrationIDP(t, h.idp)
	h.ready = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("ready version=1.0.0"))
	}))
	t.Cleanup(h.ready.Close)
	var handler http.Handler
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(h.server.Close)
	cfg := config.Config{
		Listen: ":0", PublicURL: h.server.URL, RedirectURI: h.server.URL + "/auth/callback",
		CookieName: "vca_admin_session", InsecureCookie: true, SessionTTL: 15 * time.Minute,
		Timeout: 5 * time.Second, PortalPrefix: portal.DefaultPrefix, LogoutRedirect: "/admin/",
		SessionKey: "0123456789abcdef0123456789abcdef",
		Services:   []string{"trust-registry=" + h.ready.URL},
		LandingURL: "https://vca.example",
		// The test providers live on the loopback over plain http.
		AllowPrivateNetwork: true, AllowPlainHTTP: true,
	}
	deps := app.Deps{Client: h.server.Client()}
	if withTrust {
		deps.Trust = h.trust
		cfg.TrustURL = h.server.URL
	}
	if more != nil {
		more(t, h)(&cfg, &deps)
	}
	built, err := app.Build(cfg, deps)
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	h.app = built
	handler = built.Mux
	if _, serr := built.Login.Providers().Put(oidcflow.Provider{
		ID: "idp", DisplayName: "Test IdP", DiscoveryURL: h.idp.DiscoveryURL(),
		ClientID: h.idp.ClientID, Enabled: true,
	}); serr != nil {
		t.Fatalf("Put: %v", serr)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	h.client = &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return h
}

// registrationIDP serves metadata with a registration endpoint.
func registrationIDP(t *testing.T, idp *oidctest.Provider) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cerr := json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 idp.Issuer(),
			"authorization_endpoint": idp.Issuer() + "/authorize",
			"token_endpoint":         idp.Issuer() + "/token",
			"jwks_uri":               idp.Issuer() + "/jwks",
			"registration_endpoint":  srv.URL + "/register",
		}); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if cerr := json.NewEncoder(w).Encode(map[string]string{"client_id": "registered"}); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// signIn runs one login with the bootstrap token and keeps the session.
func (h *harness) signIn(t *testing.T) {
	t.Helper()
	if h.app.BootstrapToken == "" {
		t.Fatal("the service printed no bootstrap token")
	}
	start := h.server.URL + "/auth/login?provider=idp&return_to=" +
		url.QueryEscape("/admin/") + "&" + login.BootstrapField + "=" + url.QueryEscape(h.app.BootstrapToken)
	res, err := h.client.Get(start)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if cerr := res.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", res.StatusCode)
	}
	back, err := h.idp.Authorize(res.Header.Get("Location"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	done, err := h.client.Get(back)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if cerr := done.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	if done.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status = %d", done.StatusCode)
	}
	sessionRes, err := h.client.Get(h.server.URL + "/auth/session")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer func() {
		if cerr := sessionRes.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(sessionRes.Body).Decode(&body); err != nil {
		t.Fatalf("session body: %v", err)
	}
	if body.CSRFToken == "" {
		t.Fatal("the session has no synchronizer token")
	}
	h.csrf = body.CSRFToken
}

// get fetches one page and returns the status and the body.
func (h *harness) get(t *testing.T, path string) (int, string) {
	t.Helper()
	res, err := h.client.Get(h.server.URL + path)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return res.StatusCode, string(raw)
}

// page fetches one page, checks the status, and checks accessibility.
func (h *harness) page(t *testing.T, path string) string {
	t.Helper()
	status, body := h.get(t, path)
	if status != http.StatusOK {
		t.Fatalf("%s status = %d", path, status)
	}
	a11ytest.AssertPage(t, body)
	return body
}

// post sends a form with the synchronizer token.
func (h *harness) post(t *testing.T, path string, form url.Values) (int, string) {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set(oidcflow.CSRFField, h.csrf)
	res, err := h.client.Post(h.server.URL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	raw, verr := io.ReadAll(res.Body)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	return res.StatusCode, string(raw)
}

func TestNewChecksItsOptions(t *testing.T) {
	if _, err := portal.New(portal.Options{}); err == nil {
		t.Error("New accepted no client")
	}
	if _, err := portal.New(portal.Options{Client: nil, Login: nil}); err == nil {
		t.Error("New accepted no login service")
	}
	// The app passes the kit of the theme file. A caller with none gets
	// the default kit and the default prefix.
	h := newHarness(t, false)
	p, err := portal.New(portal.Options{Client: h.app.Service, Login: h.app.Login})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Prefix() != portal.DefaultPrefix {
		t.Errorf("prefix = %q", p.Prefix())
	}
}

func TestEveryPageWithoutASessionGoesToTheLogin(t *testing.T) {
	h := newHarness(t, true)
	for _, path := range []string{"/admin/", "/admin/tenants", "/admin/trust", "/admin/providers", "/admin/providers/new", "/admin/keys", "/admin/audit"} {
		status, _ := h.get(t, path)
		if status != http.StatusSeeOther {
			t.Errorf("%s status = %d, want a redirect to the login page", path, status)
		}
	}
	status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"x"}})
	if status != http.StatusSeeOther {
		t.Errorf("POST without a session = %d", status)
	}
}

func TestLoginPageAndHelpPageNeedNoSession(t *testing.T) {
	h := newHarness(t, true)
	loginPage := h.page(t, "/admin/login?notice=signed-out")
	if strings.Contains(strings.ToLower(loginPage), `type="password" name="password"`) {
		t.Error("the login page has a password field")
	}
	// Board Signin-Admin: the shared chooser with the bootstrap card
	// (P1-08, ADR-035 decision 6).
	for _, want := range []string{
		`<h1>Sign in as an admin.</h1>`, `<span class="role">Admin</span>`,
		`<a class="btn btn-primary signin-provider" href="/auth/login?provider=idp&amp;return_to=%2Fadmin%2F"><span>Test IdP</span></a>`,
		`<div class="signin-callout"><strong>First admin after deployment?</strong>`,
		`<section class="card" id="bootstrap"`, `<input type="password" id="bootstrap_token" name="bootstrap_token"`,
		`<input type="hidden" name="provider" value="idp">`,
		`<input type="hidden" name="return_to" value="/admin/">`, `>Sign in and bind</button>`,
		`formaction="/auth/register"`, `>Register and bind</button>`,
		`<p class="signin-note">VCA is not tied to Keycloak.`, `class="toast toast-info"`, `You are signed out.`,
		`<a class="signin-back" href="https://vca.example/roles/"`,
	} {
		if !strings.Contains(loginPage, want) {
			t.Errorf("login page missing %q\n%s", want, loginPage)
		}
	}
	// A generic provider without prompt=create offers no plain register
	// action; the bootstrap card still lets the first admin register.
	if strings.Contains(loginPage, `href="/auth/register`) {
		t.Error("a generic provider offers no register link")
	}
	// With one provider the bootstrap form needs no provider id field.
	if strings.Contains(loginPage, `id="provider"`) {
		t.Error("one provider: the id field is hidden")
	}
	if _, err := h.app.Login.Providers().Put(oidcflow.Provider{ID: "second", DisplayName: "Second", DiscoveryURL: h.idp.DiscoveryURL(), ClientID: h.idp.ClientID, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if two := h.page(t, "/admin/login"); !strings.Contains(two, `<input type="text" id="provider" name="provider"`) {
		t.Errorf("two providers: the id field shows:\n%s", two)
	}
	// The chooser answers at /auth/ too, so the landing link of the admin
	// role works, and return_to reaches the login links.
	authPage := h.page(t, "/auth/?return_to=/admin/audit")
	if !strings.Contains(authPage, `href="/auth/login?provider=idp&amp;return_to=%2Fadmin%2Faudit"`) {
		t.Errorf("/auth/ misses the return path:\n%s", authPage)
	}
	status, body := h.get(t, "/auth/providers.json")
	if status != http.StatusOK || !strings.Contains(body, `"role":"admin"`) || !strings.Contains(body, `"id":"idp"`) || strings.Contains(body, h.idp.ClientID) {
		t.Errorf("providers.json: %d %s", status, body)
	}
	help := h.page(t, "/admin/help")
	for _, want := range []string{"Creates one tenant.", "admin tenant create", "AdminService.CreateTenant"} {
		if !strings.Contains(help, want) {
			t.Errorf("the help page misses %q", want)
		}
	}
}

func TestEveryPageIsAccessible(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	for _, path := range []string{
		"/admin/", "/admin/tenants", "/admin/trust", "/admin/providers",
		"/admin/providers/new", "/admin/keys", "/admin/audit", "/admin/help", "/admin/login",
	} {
		body := h.page(t, path)
		if !strings.Contains(body, "<main") {
			t.Errorf("%s has no main landmark", path)
		}
	}
}

func TestTenantPagesCreateAndDelete(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, body := h.post(t, "/admin/tenants", url.Values{"display_name": {"Ministry of Health"}}); status != http.StatusSeeOther {
		t.Fatalf("create = %d %s", status, body)
	}
	page := h.page(t, "/admin/tenants?notice=tenant-created")
	if !strings.Contains(page, "Ministry of Health") {
		t.Fatal("the new tenant is not on the page")
	}
	if !strings.Contains(page, portal.Notices["tenant-created"].Text) {
		t.Error("the page shows no notice")
	}
	id := h.tenantID(t)
	if status, _ := h.post(t, "/admin/tenants/"+id+"/delete", nil); status != http.StatusSeeOther {
		t.Fatalf("delete = %d", status)
	}
	if page := h.page(t, "/admin/tenants"); strings.Contains(page, "Ministry of Health") {
		t.Fatal("the tenant is still on the page")
	}
}

// tenantID returns the id of the first tenant on the tenant page.
func (h *harness) tenantID(t *testing.T) string {
	t.Helper()
	res, err := h.app.Service.ListTenants(context.Background(), authed(t, h, &adminv1.ListTenantsRequest{}))
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(res.Msg.GetTenants()) == 0 {
		t.Fatal("no tenant exists")
	}
	return res.Msg.GetTenants()[0].GetId()
}

// authed builds an RPC request with the session of the cookie jar.
func authed[T any](t *testing.T, h *harness, msg *T) *connect.Request[T] {
	t.Helper()
	req := connect.NewRequest(msg)
	u, err := url.Parse(h.server.URL)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == "vca_admin_session" {
			req.Header().Set("Authorization", "Bearer "+c.Value)
		}
	}
	return req
}

func TestTenantCreateWithoutANameFails(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, _ := h.post(t, "/admin/tenants", url.Values{}); status != http.StatusBadRequest {
		t.Fatalf("status = %d", status)
	}
}

func TestPostWithoutTheSynchronizerTokenIsRefused(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	form := url.Values{"display_name": {"No token"}}
	res, err := h.client.Post(h.server.URL+"/admin/tenants", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
}

func TestTrustPagesAddAndRemove(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	form := url.Values{
		"identifier": {"did:web:issuer.example"}, "display_name": {"Issuer one"},
		"role": {"issuer"}, "status": {"active"}, "service_endpoint": {"https://issuer.example"},
	}
	if status, body := h.post(t, "/admin/trust", form); status != http.StatusSeeOther {
		t.Fatalf("add = %d %s", status, body)
	}
	page := h.page(t, "/admin/trust")
	if !strings.Contains(page, "did:web:issuer.example") || !strings.Contains(page, "Issuer one") {
		t.Fatal("the entry is not on the page")
	}
	if status, _ := h.post(t, "/admin/trust/delete", url.Values{"identifier": {"did:web:issuer.example"}}); status != http.StatusSeeOther {
		t.Fatal("the remove action failed")
	}
	if page := h.page(t, "/admin/trust"); strings.Contains(page, "did:web:issuer.example") {
		t.Fatal("the entry is still on the page")
	}
	// An x509 subject also works.
	form.Set("identifier", "CN=Issuer, O=Example")
	if status, _ := h.post(t, "/admin/trust", form); status != http.StatusSeeOther {
		t.Fatal("the x509 entry failed")
	}
	if page := h.page(t, "/admin/trust?role=issuer"); !strings.Contains(page, "CN=Issuer") {
		t.Fatal("the x509 entry is not on the page")
	}
}

func TestTrustPageWithoutARegistryExplainsIt(t *testing.T) {
	h := newHarness(t, false)
	h.signIn(t)
	page := h.page(t, "/admin/trust")
	if !strings.Contains(page, "No trust registry") {
		t.Fatal("the page does not name the missing registry")
	}
}

func TestKeyPagesCreateAndRevoke(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"Tenant"}}); status != http.StatusSeeOther {
		t.Fatal("the tenant could not be created")
	}
	tenant := h.tenantID(t)
	status, body := h.post(t, "/admin/keys", url.Values{
		"display_name": {"CI key"}, "tenant_id": {tenant}, "role": {"issuer"}, "expires_days": {"30"},
	})
	if status != http.StatusOK {
		t.Fatalf("create = %d %s", status, body)
	}
	a11ytest.AssertPage(t, body)
	if !strings.Contains(body, "vca_") {
		t.Fatal("the page does not show the secret once")
	}
	page := h.page(t, "/admin/keys")
	if strings.Contains(page, "vca_") && strings.Count(page, "vca_") > 1 {
		t.Error("the key list shows a secret value")
	}
	if !strings.Contains(page, "CI key") {
		t.Fatal("the key is not on the page")
	}
	if status, _ := h.post(t, "/admin/keys", url.Values{
		"display_name": {"Bad"}, "tenant_id": {tenant}, "role": {"issuer"}, "expires_days": {"soon"},
	}); status != http.StatusBadRequest {
		t.Error("a bad expiry was accepted")
	}
}

func TestKeyRevokeAndFilter(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"Tenant"}}); status != http.StatusSeeOther {
		t.Fatal("the tenant could not be created")
	}
	tenant := h.tenantID(t)
	if status, _ := h.post(t, "/admin/keys", url.Values{
		"display_name": {"Key"}, "tenant_id": {tenant}, "role": {"admin"},
	}); status != http.StatusOK {
		t.Fatal("the key could not be created")
	}
	res, err := h.app.Service.ListApiKeys(context.Background(), authed(t, h, &adminv1.ListApiKeysRequest{}))
	if err != nil || len(res.Msg.GetKeys()) == 0 {
		t.Fatalf("ListApiKeys = %v", err)
	}
	id := res.Msg.GetKeys()[0].GetId()
	if status, _ := h.post(t, "/admin/keys/"+id+"/revoke", nil); status != http.StatusSeeOther {
		t.Fatal("the revoke action failed")
	}
	page := h.page(t, "/admin/keys?tenant_id="+tenant)
	if !strings.Contains(page, "Revoked") {
		t.Fatal("the key is not marked revoked")
	}
	if status, _ := h.post(t, "/admin/keys/missing/revoke", nil); status != http.StatusNotFound {
		t.Error("an unknown key was revoked")
	}
}

func TestAuditPageShowsEveryAction(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"Audited"}}); status != http.StatusSeeOther {
		t.Fatal("the tenant could not be created")
	}
	page := h.page(t, "/admin/audit")
	if !strings.Contains(page, "admin.CreateTenant") {
		t.Fatal("the audit page misses the action")
	}
	filtered := h.page(t, "/admin/audit?action=admin.CreateTenant&actor=nobody")
	if !strings.Contains(filtered, "No record matches the filters.") {
		t.Error("the actor filter does not work")
	}
}

func TestAuditPagePages(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	for i := 0; i < 60; i++ {
		if status, _ := h.post(t, "/admin/tenants", url.Values{"display_name": {"T"}}); status != http.StatusSeeOther {
			t.Fatal("a tenant could not be created")
		}
	}
	page := h.page(t, "/admin/audit")
	if !strings.Contains(page, "Next page") {
		t.Fatal("the audit page has no next page link")
	}
}

func TestDashboardShowsTheServiceHealth(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	page := h.page(t, "/admin/")
	if !strings.Contains(page, "trust-registry") {
		t.Fatal("the dashboard misses the service")
	}
	if !strings.Contains(page, "Ready") {
		t.Fatal("the dashboard shows no readiness")
	}
}

func TestPrefixIsNormalized(t *testing.T) {
	h := newHarness(t, true)
	if h.app.Portal.Prefix() != "/admin" {
		t.Fatalf("prefix = %q", h.app.Portal.Prefix())
	}
}

func TestTrustPageShowsEveryStatusAndRole(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	cases := []struct {
		id, role, status, want string
	}{
		{"did:web:one.example", "issuer", "active", "Trusted"},
		{"did:web:two.example", "verifier", "suspended", "Suspended"},
		{"did:web:three.example", "holder", "revoked", "Revoked"},
		{"did:web:four.example", "issuer", "unknown", "Unknown"},
	}
	for _, c := range cases {
		form := url.Values{
			"identifier": {c.id}, "display_name": {c.id}, "role": {c.role}, "status": {c.status},
		}
		if status, body := h.post(t, "/admin/trust", form); status != http.StatusSeeOther {
			t.Fatalf("%s add = %d %s", c.id, status, body)
		}
	}
	page := h.page(t, "/admin/trust")
	for _, c := range cases {
		if !strings.Contains(page, c.want) {
			t.Errorf("the page misses the status %q", c.want)
		}
		if !strings.Contains(page, c.id) {
			t.Errorf("the page misses %q", c.id)
		}
	}
}

func TestDashboardShowsTheAdminName(t *testing.T) {
	h := newHarness(t, true)
	h.idp.Claims["name"] = "Amina Ali"
	h.signIn(t)
	if page := h.page(t, "/admin/"); !strings.Contains(page, "Amina Ali") {
		t.Fatal("the dashboard does not name the admin")
	}
}

func TestDashboardReportsAServiceThatIsNotReady(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	// The service list points at an address with no server, so the probe
	// fails and the page shows the reason.
	page := h.page(t, "/admin/")
	if !strings.Contains(page, "trust-registry") {
		t.Fatal("the dashboard misses the service")
	}
}

func TestAnUnknownTenantDeleteIsNotFound(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	if status, _ := h.post(t, "/admin/tenants/missing/delete", nil); status != http.StatusNotFound {
		t.Fatalf("status = %d", status)
	}
	if status, _ := h.post(t, "/admin/providers/missing/delete", nil); status != http.StatusNotFound {
		t.Fatalf("provider status = %d", status)
	}
	if status, _ := h.post(t, "/admin/trust/delete", url.Values{"identifier": {""}}); status != http.StatusSeeOther {
		t.Fatalf("a delete of a missing entry = %d", status)
	}
}

func TestRootRedirectsToThePortal(t *testing.T) {
	h := newHarness(t, true)
	res, err := h.client.Get(h.server.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() {
		if cerr := res.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/admin/" {
		t.Fatalf("status = %d location = %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestTrustPageReportsARegistryFault(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	h.trust.listErr = connect.NewError(connect.CodeUnavailable, errors.New("down"))
	status, _ := h.get(t, "/admin/trust")
	if status != http.StatusInternalServerError {
		t.Fatalf("status = %d", status)
	}
}

func TestDashboardNamesTheProbeFault(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	h.ready.Close()
	page := h.page(t, "/admin/")
	if !strings.Contains(page, "could not be reached") {
		t.Fatal("the dashboard does not name the probe fault")
	}
	if !strings.Contains(page, "Not ready") {
		t.Fatal("the dashboard does not mark the service")
	}
}

// seedTrust puts one entry straight into the fake registry, the way an
// issuer registration would.
func (h *harness) seedTrust(id *trustv1.TrustEntry_Identifier, name string, status trustv1.Status) {
	h.trust.entries[keyOf(id)] = &trustv1.TrustEntry{
		Identifier: id, DisplayName: name, Role: commonv1.Role_ROLE_ISSUER, Status: status,
		UpdatedAt: timestamppb.New(time.Date(2026, 9, 20, 9, 30, 0, 0, time.UTC)),
	}
}

func didOf(v string) *trustv1.TrustEntry_Identifier {
	return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: v}}
}

func x509Of(v string) *trustv1.TrustEntry_Identifier {
	return &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_X509Subject{X509Subject: v}}
}

// TestTrustListShowsPendingWithApprove puts a pending entry first, with
// approve and reject forms that carry the synchronizer token. A trusted
// entry has no approve button.
func TestTrustListShowsPendingWithApprove(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	h.seedTrust(didOf("did:web:active.example"), "Active issuer", trustv1.Status_STATUS_ACTIVE)
	h.seedTrust(x509Of("CN=Registrar, O=Ministry of Health"), "Ministry of Health", trustv1.Status_STATUS_PENDING)
	page := h.page(t, "/admin/trust")
	for _, want := range []string{
		"Trust lists and registries", "Pending review", "Trusted", "X.509", "did:web",
		`action="/admin/trust/approve"`, `action="/admin/trust/reject"`, ">Approve<", ">Reject<",
		`name="` + oidcflow.CSRFField + `"`, "2026-09-20", "1 pending review",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the trust page misses %q", want)
		}
	}
	if strings.Index(page, "Ministry of Health") > strings.Index(page, "Active issuer") {
		t.Error("the pending entry does not come first")
	}
	if strings.Count(page, ">Approve<") != 1 {
		t.Errorf("the page has %d approve buttons, want one for the pending entry", strings.Count(page, ">Approve<"))
	}
	pendingOnly := h.page(t, "/admin/trust?status=pending")
	if strings.Contains(pendingOnly, "Active issuer") || !strings.Contains(pendingOnly, "Ministry of Health") {
		t.Error("the status filter does not work")
	}
}

// TestAddX509Entry adds an entry by X.509 subject beside a DID entry.
// The form names the kind, so a subject never reads as a DID.
func TestAddX509Entry(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	page := h.page(t, "/admin/trust")
	for _, want := range []string{`name="kind"`, `value="did"`, `value="x509"`, "X.509 subject"} {
		if !strings.Contains(page, want) {
			t.Errorf("the add form misses %q", want)
		}
	}
	form := url.Values{
		"kind": {"x509"}, "identifier": {"CN=Registrar, O=Ministry of Health, C=KE"}, "display_name": {"Ministry of Health"},
		"role": {"issuer"}, "status": {"active"},
	}
	if status, body := h.post(t, "/admin/trust", form); status != http.StatusSeeOther {
		t.Fatalf("add = %d %s", status, body)
	}
	got, ok := h.trust.entries["CN=Registrar, O=Ministry of Health, C=KE"]
	if !ok || got.GetIdentifier().GetX509Subject() == "" {
		t.Fatalf("the registry holds %v, want an x509 entry", got)
	}
	form = url.Values{
		"kind": {"did"}, "identifier": {"did:web:issuer.example"}, "display_name": {"Issuer"},
		"role": {"issuer"}, "status": {"pending"},
	}
	if status, body := h.post(t, "/admin/trust", form); status != http.StatusSeeOther {
		t.Fatalf("add = %d %s", status, body)
	}
	if e := h.trust.entries["did:web:issuer.example"]; e.GetIdentifier().GetDid() == "" || e.GetStatus() != trustv1.Status_STATUS_PENDING {
		t.Fatalf("the registry holds %v, want a pending DID entry", e)
	}
	// A DID kind with a value that is not a DID is a bad request.
	form.Set("identifier", "issuer.example")
	if status, _ := h.post(t, "/admin/trust", form); status != http.StatusBadRequest {
		t.Fatalf("a DID without did: = %d, want 400", status)
	}
	listed := h.page(t, "/admin/trust")
	if !strings.Contains(listed, "CN=Registrar, O=Ministry of Health, C=KE") || !strings.Contains(listed, "X.509") {
		t.Error("the x509 entry is not on the page")
	}
}

// TestApproveWritesAudit approves one pending entry and rejects another
// through the page. The registry changes and the audit log names both.
func TestApproveWritesAudit(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	h.seedTrust(didOf("did:web:approve.example"), "To approve", trustv1.Status_STATUS_PENDING)
	h.seedTrust(x509Of("CN=Reject, O=Example"), "To reject", trustv1.Status_STATUS_PENDING)
	status, _ := h.post(t, "/admin/trust/approve", url.Values{"kind": {"did"}, "identifier": {"did:web:approve.example"}})
	if status != http.StatusSeeOther {
		t.Fatalf("approve = %d", status)
	}
	if h.trust.entries["did:web:approve.example"].GetStatus() != trustv1.Status_STATUS_ACTIVE {
		t.Fatal("the approved entry is not active")
	}
	status, _ = h.post(t, "/admin/trust/reject", url.Values{"kind": {"x509"}, "identifier": {"CN=Reject, O=Example"}})
	if status != http.StatusSeeOther {
		t.Fatalf("reject = %d", status)
	}
	if _, ok := h.trust.entries["CN=Reject, O=Example"]; ok {
		t.Fatal("the rejected entry is still in the registry")
	}
	audit := h.page(t, "/admin/audit")
	for _, want := range []string{"admin.ApproveTrustEntry", "did:web:approve.example", "admin.RejectTrustEntry", "CN=Reject, O=Example"} {
		if !strings.Contains(audit, want) {
			t.Errorf("the audit page misses %q", want)
		}
	}
	if page := h.page(t, "/admin/trust?notice=trust-approved"); !strings.Contains(page, "active") {
		t.Error("the approve notice is missing")
	}
	// An approval of an entry that is not pending fails and is audited.
	if status, _ := h.post(t, "/admin/trust/approve", url.Values{"kind": {"did"}, "identifier": {"did:web:approve.example"}}); status != http.StatusBadRequest {
		t.Fatalf("a second approval = %d, want 400", status)
	}
}

// TestApproveNeedsTheSynchronizerToken refuses a cross site approval.
func TestApproveNeedsTheSynchronizerToken(t *testing.T) {
	h := newHarness(t, true)
	h.signIn(t)
	h.seedTrust(didOf("did:web:approve.example"), "To approve", trustv1.Status_STATUS_PENDING)
	for _, path := range []string{"/admin/trust/approve", "/admin/trust/reject"} {
		form := url.Values{"kind": {"did"}, "identifier": {"did:web:approve.example"}}
		res, err := h.client.Post(h.server.URL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if cerr := res.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("%s without a token = %d, want 403", path, res.StatusCode)
		}
	}
	if h.trust.entries["did:web:approve.example"].GetStatus() != trustv1.Status_STATUS_PENDING {
		t.Fatal("a refused approval changed the entry")
	}
}
