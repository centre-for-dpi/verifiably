// SPDX-License-Identifier: Apache-2.0

package login_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/audit"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// harness holds a fake IdP, the login service, and its HTTP server.
type harness struct {
	idp     *oidctest.Provider
	device  *deviceIDP
	svc     *login.Service
	server  *httptest.Server
	rec     *records.Store
	audit   *audit.Log
	cfg     config.Config
	client  *http.Client
	handler *http.ServeMux
}

// deviceIDP wraps the fake provider with a device authorization
// endpoint, because the shared fake has none.
type deviceIDP struct {
	server *httptest.Server
	idp    *oidctest.Provider
	// pending is the device code the token endpoint accepts.
	pending string
	// body replaces the token endpoint answer when it is set.
	body string
	// status is the status of the token endpoint answer.
	status int
	// noDevice removes the device endpoint from the metadata.
	noDevice bool
}

func newDeviceIDP(t *testing.T, idp *oidctest.Provider) *deviceIDP {
	t.Helper()
	d := &deviceIDP{idp: idp, pending: "device-code-1", status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]any{
			"issuer":                 idp.Issuer(),
			"authorization_endpoint": idp.Issuer() + "/authorize",
			"token_endpoint":         d.server.URL + "/token",
			"jwks_uri":               idp.Issuer() + "/jwks",
		}
		if !d.noDevice {
			doc["device_authorization_endpoint"] = d.server.URL + "/device"
		}
		writeJSON(w, http.StatusOK, doc)
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"device_code": d.pending, "user_code": "ABCD-EFGH",
			"verification_uri": idp.Issuer() + "/device", "interval": 5, "expires_in": 600,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if d.body != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(d.status)
			_, _ = w.Write([]byte(d.body))
			return
		}
		_ = r.ParseForm()
		if r.PostFormValue("device_code") != d.pending {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authorization_pending"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 300,
			"id_token": idp.IDToken(idp.ClientID, ""),
		})
	})
	d.server = httptest.NewServer(mux)
	t.Cleanup(d.server.Close)
	return d
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// newHarness builds the whole login service over the fake provider.
func newHarness(t *testing.T) *harness {
	t.Helper()
	idp := oidctest.New()
	t.Cleanup(idp.Close)
	h := &harness{idp: idp, handler: http.NewServeMux()}
	h.device = newDeviceIDP(t, idp)
	h.server = httptest.NewServer(h.handler)
	t.Cleanup(h.server.Close)
	kv := store.Memory()
	rec, err := records.New(kv, nil)
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	log, err := audit.New(kv, nil)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	h.rec, h.audit = rec, log
	registry, err := oidcflow.NewRegistry(nil, nil)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	if _, err := registry.Put(oidcflow.Provider{
		ID: "idp", DisplayName: "Test IdP", DiscoveryURL: idp.DiscoveryURL(),
		ClientID: idp.ClientID, Enabled: true, Roles: []string{"admin"},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	key, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	h.cfg = config.Config{
		PublicURL: h.server.URL, RedirectURI: h.server.URL + "/auth/callback",
		CookieName: "vca_admin_session", InsecureCookie: true, SessionTTL: 15 * time.Minute,
		Timeout: 5 * time.Second, LogoutRedirect: "/admin/",
	}
	signer, err := oidcflow.NewSigner(key, h.cfg.PublicURL, login.Audience, h.cfg.SessionTTL, nil)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	csrf, err := oidcflow.NewCSRF([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCSRF: %v", err)
	}
	cache := oidcflow.NewCache(nil, 0)
	svc, err := login.New(login.Deps{
		Cfg: h.cfg, Flow: &oidcflow.Flow{Cache: cache}, Cache: cache, Providers: registry,
		Signer: signer, CSRF: csrf, Records: rec, Audit: log,
	})
	if err != nil {
		t.Fatalf("login.New: %v", err)
	}
	h.svc = svc
	h.handler.HandleFunc("GET /auth/login", svc.Login)
	h.handler.HandleFunc("GET /auth/callback", svc.Callback)
	handlers := svc.Handlers()
	h.handler.HandleFunc("POST /auth/logout", handlers.Logout)
	h.handler.HandleFunc("GET /auth/session", handlers.Session)
	svc.MountCLI(h.handler)
	h.client = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return h
}

// deviceProvider registers the wrapper provider and returns its id.
func (h *harness) deviceProvider(t *testing.T) string {
	t.Helper()
	p, err := h.svc.Providers().Put(oidcflow.Provider{
		ID: "device", DisplayName: "Device IdP", DiscoveryURL: h.device.server.URL + "/.well-known/openid-configuration",
		ClientID: h.idp.ClientID, Enabled: true,
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return p.ID
}

// login runs one browser login and returns the session token.
func (h *harness) login(t *testing.T, query string) (string, *http.Response) {
	t.Helper()
	res, err := h.client.Get(h.server.URL + "/auth/login?provider=idp" + query)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer res.Body.Close()
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
	t.Cleanup(func() { done.Body.Close() })
	for _, c := range done.Cookies() {
		if c.Name == h.cfg.CookieName {
			return c.Value, done
		}
	}
	return "", done
}

func TestNewChecksTheDependencies(t *testing.T) {
	if _, err := login.New(login.Deps{}); err == nil {
		t.Fatal("New accepted empty dependencies")
	}
}

func TestLoginWithoutABindingIsRefused(t *testing.T) {
	h := newHarness(t)
	token, res := h.login(t, "")
	if token != "" {
		t.Fatalf("a subject with no binding got a session")
	}
	if res.StatusCode == http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	page, err := h.audit.Query(context.Background(), audit.Filter{Action: "admin.Login"})
	if err != nil || len(page.Records) != 1 || page.Records[0].OK {
		t.Fatalf("audit = %+v, %v", page.Records, err)
	}
}

func TestBootstrapTokenBindsTheFirstSuperAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := records.NewBootstrapToken()
	if err := h.rec.SetBootstrap(ctx, token); err != nil {
		t.Fatalf("SetBootstrap: %v", err)
	}
	session, _ := h.login(t, "&"+login.BootstrapField+"="+token)
	if session == "" {
		t.Fatal("the bootstrap login gave no session")
	}
	claims, err := h.svc.Session(ctx, session)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if !claims.HasRole(login.RoleSuperAdmin) || !claims.HasRole(login.RoleAdmin) {
		t.Fatalf("roles = %v", claims.Roles)
	}
	if h.rec.BootstrapPending(ctx) {
		t.Error("the bootstrap token is still pending")
	}
	// The same subject logs in again without a token.
	again, _ := h.login(t, "")
	if again == "" {
		t.Fatal("the bound admin could not log in again")
	}
	// A second bootstrap login fails, because the token is spent.
	spent, _ := h.login(t, "&"+login.BootstrapField+"="+token)
	if spent == "" {
		t.Log("the bound admin keeps the role")
	}
}

func TestAWrongBootstrapTokenIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.rec.SetBootstrap(ctx, records.NewBootstrapToken()); err != nil {
		t.Fatalf("SetBootstrap: %v", err)
	}
	if session, _ := h.login(t, "&"+login.BootstrapField+"=wrong-token-value"); session != "" {
		t.Fatal("a wrong bootstrap token gave a session")
	}
	if !h.rec.BootstrapPending(ctx) {
		t.Error("a wrong token consumed the bootstrap")
	}
}

func TestLoginRejectsAnUnknownProvider(t *testing.T) {
	h := newHarness(t)
	res, err := h.client.Get(h.server.URL + "/auth/login?provider=nope")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

func TestStartPicksTheOnlyEnabledProvider(t *testing.T) {
	h := newHarness(t)
	u, err := h.svc.Start(context.Background(), "", "")
	if err != nil || !strings.Contains(u, "code_challenge_method=S256") {
		t.Fatalf("Start = %q, %v", u, err)
	}
	if _, err := h.svc.Providers().Put(oidcflow.Provider{
		ID: "second", DiscoveryURL: h.idp.DiscoveryURL(), ClientID: "x", Enabled: true,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := h.svc.Start(context.Background(), "", ""); !errors.Is(err, oidcflow.ErrProviderNotFound) {
		t.Fatalf("Start with two providers: %v", err)
	}
}

func TestCompleteReportsAnUnknownStateAndAProviderError(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, _, _, err := h.svc.Complete(ctx, "nothing", "code", ""); !errors.Is(err, oidcflow.ErrStateUnknown) {
		t.Errorf("unknown state: %v", err)
	}
	if _, err := h.svc.Start(ctx, "idp", ""); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func TestSessionAuthenticationAndCSRF(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.rec.BindAdmin(ctx, h.idp.Issuer(), h.idp.Subject); err != nil {
		t.Fatalf("BindAdmin: %v", err)
	}
	session, _ := h.login(t, "")
	if session == "" {
		t.Fatal("no session")
	}
	header := http.Header{"Authorization": {"Bearer " + session}}
	id, err := h.svc.Authenticate(ctx, header)
	if err != nil || !id.IsSuperAdmin() {
		t.Fatalf("Authenticate = %+v, %v", id, err)
	}
	if id.Actor == "" {
		t.Error("the identity has no actor")
	}
	// A POST without a synchronizer token fails (ADR-010 decision 7).
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants", nil)
	req.Header = header
	if _, err := h.svc.CheckCSRF(ctx, req); !errors.Is(err, oidcflow.ErrCSRF) {
		t.Fatalf("CheckCSRF without a token: %v", err)
	}
	claims, err := h.svc.Session(ctx, session)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	req.Header.Set(oidcflow.CSRFHeader, h.svc.CSRFToken(claims.SID))
	if _, err := h.svc.CheckCSRF(ctx, req); err != nil {
		t.Fatalf("CheckCSRF with a token: %v", err)
	}
	// A token of another session does not work.
	req.Header.Set(oidcflow.CSRFHeader, h.svc.CSRFToken("other"))
	if _, err := h.svc.CheckCSRF(ctx, req); !errors.Is(err, oidcflow.ErrCSRF) {
		t.Fatalf("CheckCSRF with a foreign token: %v", err)
	}
}

func TestAuthenticateRejectsBadCredentials(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.Authenticate(ctx, http.Header{}); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Errorf("no credential: %v", err)
	}
	if _, err := h.svc.Authenticate(ctx, http.Header{"Authorization": {"Bearer broken"}}); err == nil {
		t.Error("a broken token was accepted")
	}
	if _, err := h.svc.Authenticate(ctx, http.Header{"Authorization": {"Bearer " + records.SecretPrefix + "unknown"}}); !errors.Is(err, oidcflow.ErrUnauthorized) {
		t.Error("an unknown API key was accepted")
	}
	if err := h.svc.Authorizer()(ctx, http.Header{}); err == nil {
		t.Error("the authorizer accepted an empty header")
	}
}

func TestAuthenticateAcceptsAnAdminAPIKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenant, err := h.rec.CreateTenant(ctx, "Tenant")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	_, secret, err := h.rec.CreateKey(ctx, records.KeySpec{DisplayName: "cli", TenantID: tenant.ID, Roles: []string{login.RoleAdmin}})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	id, err := h.svc.Authenticate(ctx, http.Header{"Authorization": {"Bearer " + secret}})
	if err != nil || !id.IsSuperAdmin() || id.KeyID == "" {
		t.Fatalf("Authenticate = %+v, %v", id, err)
	}
	_, weak, err := h.rec.CreateKey(ctx, records.KeySpec{DisplayName: "ci", TenantID: tenant.ID, Roles: []string{"issuer"}})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if _, err := h.svc.Authenticate(ctx, http.Header{"Authorization": {"Bearer " + weak}}); !errors.Is(err, oidcflow.ErrForbidden) {
		t.Fatalf("an issuer key reached the admin service: %v", err)
	}
}

func TestOnboardAdminBindsFromAnIDToken(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := records.NewBootstrapToken()
	if err := h.rec.SetBootstrap(ctx, token); err != nil {
		t.Fatalf("SetBootstrap: %v", err)
	}
	idToken := h.idp.IDToken(h.idp.ClientID, "")
	admin, err := h.svc.OnboardAdmin(ctx, "idp", idToken, token)
	if err != nil {
		t.Fatalf("OnboardAdmin: %v", err)
	}
	if admin.Subject != h.idp.Subject {
		t.Fatalf("admin = %+v", admin)
	}
	if !h.rec.IsAdmin(ctx, h.idp.Issuer(), h.idp.Subject) {
		t.Fatal("the subject is not bound")
	}
	if _, err := h.svc.OnboardAdmin(ctx, "idp", idToken, token); !errors.Is(err, records.ErrBootstrapUsed) {
		t.Fatalf("second onboarding: %v", err)
	}
}

func TestOnboardAdminChecksItsInput(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.svc.OnboardAdmin(ctx, "idp", "", "token"); !errors.Is(err, login.ErrNoIDToken) {
		t.Errorf("no id token: %v", err)
	}
	if _, err := h.svc.OnboardAdmin(ctx, "missing", "x.y.z", "token"); !errors.Is(err, oidcflow.ErrProviderNotFound) {
		t.Errorf("unknown provider: %v", err)
	}
	if _, err := h.svc.OnboardAdmin(ctx, "idp", "not-a-token", "token"); err == nil {
		t.Error("a broken id token was accepted")
	}
}

func TestVerifyIDTokenAcceptsARotatedKey(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	p, err := h.svc.Providers().Get("idp")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := h.svc.VerifyIDToken(ctx, p, h.idp.IDToken(h.idp.ClientID, "")); err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	h.idp.RotateKey()
	if _, err := h.svc.VerifyIDToken(ctx, p, h.idp.IDToken(h.idp.ClientID, "")); err != nil {
		t.Fatalf("VerifyIDToken after a rotation: %v", err)
	}
}

func TestLogoutRevokesTheSession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.rec.BindAdmin(ctx, h.idp.Issuer(), h.idp.Subject); err != nil {
		t.Fatalf("BindAdmin: %v", err)
	}
	session, _ := h.login(t, "")
	claims, err := h.svc.Session(ctx, session)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	form := url.Values{oidcflow.CSRFField: {h.svc.CSRFToken(claims.SID)}}
	req, err := http.NewRequest(http.MethodPost, h.server.URL+"/auth/logout", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+session)
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status = %d", res.StatusCode)
	}
	if _, err := h.svc.Session(ctx, session); !errors.Is(err, oidcflow.ErrSessionRevoked) {
		t.Fatalf("the session still works: %v", err)
	}
}

func TestEndReportsAnInvalidToken(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.End(context.Background(), "broken"); err == nil {
		t.Fatal("End accepted a broken token")
	}
}

func TestAccessorsAreWired(t *testing.T) {
	h := newHarness(t)
	if h.svc.Signer() == nil || h.svc.Providers() == nil {
		t.Fatal("an accessor returned nothing")
	}
	if h.svc.Cookie().Name != h.cfg.CookieName || h.svc.Cookie().Secure {
		t.Fatalf("cookie = %+v", h.svc.Cookie())
	}
	if !h.svc.CSRF().Check("sid", h.svc.CSRFToken("sid")) {
		t.Fatal("the CSRF maker does not check its own token")
	}
	if h.svc.Handlers().Cookie.Name != h.cfg.CookieName {
		t.Fatal("the handlers have no cookie name")
	}
}

func TestTheDisplayNameFallsBackToThePreferredUsername(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.idp.Claims["preferred_username"] = "amina"
	if _, err := h.rec.BindAdmin(ctx, h.idp.Issuer(), h.idp.Subject); err != nil {
		t.Fatalf("BindAdmin: %v", err)
	}
	session, _ := h.login(t, "")
	claims, err := h.svc.Session(ctx, session)
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if claims.Name != "amina" {
		t.Fatalf("name = %q", claims.Name)
	}
	h.idp.Claims["name"] = "Amina Ali"
	second, _ := h.login(t, "")
	claims, err = h.svc.Session(ctx, second)
	if err != nil || claims.Name != "Amina Ali" {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
}

func TestACallbackWithAnUnknownStateFails(t *testing.T) {
	h := newHarness(t)
	res, err := h.client.Get(h.server.URL + "/auth/callback?state=nothing&code=x")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", res.StatusCode)
	}
}

// bare builds a second service over the same registry and records, with
// no audit log and with an own secret resolver.
func (h *harness) bare(t *testing.T, secrets oidcflow.SecretResolver) *login.Service {
	t.Helper()
	cache := oidcflow.NewCache(nil, 0)
	svc, err := login.New(login.Deps{
		Cfg:       h.cfg,
		Flow:      &oidcflow.Flow{Cache: cache, Secrets: secrets},
		Cache:     cache,
		Providers: h.svc.Providers(),
		Signer:    h.svc.Signer(),
		CSRF:      h.svc.CSRF(),
		Records:   h.rec,
	})
	if err != nil {
		t.Fatalf("login.New: %v", err)
	}
	return svc
}

// roundTrip runs one login on svc and returns the state and the code.
func (h *harness) roundTrip(t *testing.T, svc *login.Service) (string, string) {
	t.Helper()
	u, err := svc.Start(context.Background(), "idp", "")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	back, err := h.idp.Authorize(u)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	parsed, err := url.Parse(back)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return parsed.Query().Get("state"), parsed.Query().Get("code")
}

func TestALoginWorksWithoutAnAuditLog(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.rec.BindAdmin(ctx, h.idp.Issuer(), h.idp.Subject); err != nil {
		t.Fatalf("BindAdmin: %v", err)
	}
	svc := h.bare(t, nil)
	state, code := h.roundTrip(t, svc)
	token, claims, _, err := svc.Complete(ctx, state, code, "")
	if err != nil || token == "" || !claims.HasRole(login.RoleSuperAdmin) {
		t.Fatalf("Complete = %v, %v", claims, err)
	}
}

func TestCompleteReportsAProviderError(t *testing.T) {
	h := newHarness(t)
	svc := h.bare(t, nil)
	state, _ := h.roundTrip(t, svc)
	if _, _, _, err := svc.Complete(context.Background(), state, "", "access_denied"); !errors.Is(err, oidcflow.ErrProviderError) {
		t.Fatalf("Complete = %v", err)
	}
}

func TestTheDeviceEndpointUsesTheConfiguredSecretResolver(t *testing.T) {
	h := newHarness(t)
	id := h.deviceProvider(t)
	p, err := h.svc.Providers().Get(id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	p.ClientSecret = oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: "VCA_TEST_CLIENT_SECRET"}
	if _, err := h.svc.Providers().Put(p); err != nil {
		t.Fatalf("Put: %v", err)
	}
	calls := 0
	svc := h.bare(t, func(ref oidcflow.SecretRef) (string, error) {
		calls++
		return "secret-value", nil
	})
	req := httptest.NewRequest(http.MethodPost, "/device_authorization",
		strings.NewReader(url.Values{"provider": {id}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.DeviceAuthorization(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if calls == 0 {
		t.Fatal("the service did not use the secret resolver")
	}
}

func TestTheDeviceEndpointReportsAnUnreachableProvider(t *testing.T) {
	h := newHarness(t)
	if _, err := h.svc.Providers().Put(oidcflow.Provider{
		ID: "gone", DiscoveryURL: "http://127.0.0.1:1/.well-known/openid-configuration",
		ClientID: "x", Enabled: true,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	status, body := h.post(t, "/device_authorization", url.Values{"provider": {"gone"}})
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d body = %v", status, body)
	}
}
