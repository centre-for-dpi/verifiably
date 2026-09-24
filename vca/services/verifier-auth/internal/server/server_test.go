// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	verifierauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/signin"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/roles"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/server"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func baseConfig(t *testing.T) config.Config {
	t.Helper()
	c, err := config.FromEnv(func(k string) string {
		switch k {
		case "VCA_PUBLIC_URL":
			return "http://localhost:8081"
		case "VCA_VERIFIER_AUTH_STATE_DIR":
			return filepath.Join(t.TempDir(), "state")
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestSeedProviderIsKeycloakWithRealmAndConsole is ADR-035 decision 2:
// the seed of the stack is a record of kind keycloak with the realm of
// the verifier role, the console of that realm, and the default flag.
func TestSeedProviderIsKeycloakWithRealmAndConsole(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Seed = config.SeedProvider{
		DiscoveryURL:   "http://waltid-keycloak:8080/realms/vca-verifier-realm/.well-known/openid-configuration",
		ClientID:       "vca-verifier",
		ClientSecret:   "S",
		RolesClaimPath: "realm_access.roles",
		PublicURL:      "http://localhost:17010",
	}
	svc, err := server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Providers().Get(oidcflow.SeedID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != oidcflow.KindKeycloak || p.Realm != "vca-verifier-realm" || !p.IsDefault ||
		p.ConsoleURL != "http://localhost:17010/admin/vca-verifier-realm/console/" {
		t.Errorf("seed profile = %+v", p.Profile)
	}
	if len(p.Roles) != 1 || p.Roles[0] != "verifier" || p.RolesClaimPath != "realm_access.roles" {
		t.Errorf("seed record = %+v", p)
	}
}

func TestBuild(t *testing.T) {
	cfg := baseConfig(t)
	svc, err := server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if len(svc.Providers().List()) != 0 {
		t.Fatal("no seed expected")
	}
	// A seed provider from the environment lands under id "default".
	cfg.Seed = config.SeedProvider{DiscoveryURL: "https://idp/.well-known/openid-configuration", ClientID: "c", ClientSecret: "S", RolesClaimPath: "roles"}
	svc, err = server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Providers().Get("default")
	if err != nil || p.ClientSecret.Name != "VCA_OIDC_CLIENT_SECRET" || !p.Enabled {
		t.Fatalf("seed: %+v %v", p, err)
	}
	// A second build keeps the stored record and does not overwrite it.
	if _, providersErr := svc.Providers().Put(oidcflow.Provider{ID: "default", DisplayName: "Kept", DiscoveryURL: p.DiscoveryURL, ClientID: "c", Enabled: true}); providersErr != nil {
		t.Fatalf("unexpected error: %v", providersErr)
	}
	svc, buildErr := server.Build(cfg, quiet)
	if buildErr != nil {
		t.Fatalf("unexpected error: %v", buildErr)
	}
	if p, ierr := svc.Providers().Get("default"); ierr != nil || p.DisplayName != "Kept" {
		t.Fatal("seed overwrote the stored provider")
	}
	// A signing key file is used, and its kid is stable.
	key, verr := oidcflow.GenerateKey()
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	pem, verr := oidcflow.EncodeKeyPEM(key)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	cfg.SigningKeyPath = filepath.Join(t.TempDir(), "key.pem")
	if cerr := os.WriteFile(cfg.SigningKeyPath, pem, 0o600); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	cfg.SessionKey = "0123456789abcdef0123456789abcdef"
	cfg.AdminToken = "t"
	a, verr := server.Build(cfg, quiet)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	b, verr := server.Build(cfg, quiet)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	if a.Signer().KeyID() != b.Signer().KeyID() {
		t.Fatal("kid differs between builds")
	}
	// Failures.
	cfg.SigningKeyPath = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("missing key accepted")
	}
	if cerr := os.WriteFile(cfg.SigningKeyPath, []byte("junk"), 0o600); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("bad key accepted")
	}
	cfg.SigningKeyPath = ""
	cfg.SessionKey = "short"
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("short session key accepted")
	}
	cfg.SessionKey = ""
	cfg.StateDir = t.TempDir()
	cfg.Seed.DiscoveryURL = "nope"
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("bad seed accepted")
	}
	cfg.Seed = config.SeedProvider{}
	file := filepath.Join(t.TempDir(), "file")
	if cerr := os.WriteFile(file, nil, 0o600); cerr != nil {
		t.Fatalf("unexpected error: %v", cerr)
	}
	cfg.StateDir = filepath.Join(file, "x")
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("bad state dir accepted")
	}
	for _, doc := range []string{"providers", "role_mappings", "clients"} {
		dir := t.TempDir()
		if cerr := os.WriteFile(filepath.Join(dir, doc+".json"), []byte("{bad"), 0o600); cerr != nil {
			t.Fatalf("unexpected error: %v", cerr)
		}
		cfg.StateDir = dir
		if _, err := server.Build(cfg, quiet); err == nil {
			t.Fatalf("corrupt %s accepted", doc)
		}
	}
}

func TestHandlerRoutes(t *testing.T) {
	svc, err := server.Build(baseConfig(t), quiet)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	server.Handler(svc).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("jwks: %d", rec.Code)
	}
}

func TestReadyMessage(t *testing.T) {
	svc, err := server.Build(baseConfig(t), quiet)
	if err != nil {
		t.Fatal(err)
	}
	if msg := server.ReadyMessage(svc)(); !strings.Contains(msg, "providers=") {
		t.Fatalf("ready message = %q", msg)
	}
}

// TestAuthRootServesChooser is P1-08: GET /auth/ shows the sign in
// chooser of the verifier role with the seeded Keycloak realm, /auth/
// providers.json lists it without a secret, /auth/register sends the
// browser to the registration endpoint of the realm, and a provider with
// no register action gives 404. The routes exist at the root too.
func TestAuthRootServesChooser(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	realm := oidctest.New()
	defer realm.Close()
	cfg := baseConfig(t)
	cfg.LandingURL = "https://vca.example"
	svc, err := server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Providers().Put(oidcflow.Provider{
		ID: "default", DisplayName: "Keycloak", DiscoveryURL: realm.DiscoveryURL(), ClientID: realm.ClientID, Enabled: true,
		Profile: oidcflow.Profile{Kind: oidcflow.KindKeycloak, Realm: "vca-verifier-realm", IsDefault: true},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Providers().Put(oidcflow.Provider{ID: "other", DisplayName: "Other", DiscoveryURL: idp.DiscoveryURL(), ClientID: idp.ClientID, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	h := server.Handler(svc)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}
	for _, path := range []string{"/auth/?return_to=/portal/", "/"} {
		rec := get(path)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", path, rec.Code, rec.Body.String())
		}
		doc := rec.Body.String()
		a11ytest.AssertPage(t, doc)
		for _, want := range []string{
			`<h1>Sign in as a verifier.</h1>`, `<span class="signin-meta">vca-verifier-realm</span>`, `href="/auth/login?provider=default&amp;return_to=%2Fportal%2F"`,
			`href="/auth/register?provider=default&amp;return_to=%2Fportal%2F"`, `<a class="signin-back" href="https://vca.example/roles/"`,
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s missing %q\n%s", path, want, doc)
			}
		}
		if strings.Contains(doc, "register?provider=other") {
			t.Errorf("%s: a generic provider without prompt=create offers no registration", path)
		}
	}
	rec := get("/auth/providers.json")
	var listing signin.Listing
	if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("providers.json: %d %v %s", rec.Code, err, rec.Body.String())
	}
	if listing.Role != "verifier" || len(listing.Providers) != 2 || listing.Providers[0].Realm != "vca-verifier-realm" || !listing.Providers[0].Register || listing.Providers[1].Register {
		t.Errorf("listing = %+v", listing)
	}
	if strings.Contains(rec.Body.String(), realm.ClientID) || strings.Contains(rec.Body.String(), "discovery") {
		t.Errorf("providers.json leaks: %s", rec.Body.String())
	}
	rec = get("/auth/register?provider=default&return_to=/portal/")
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc, realm.Issuer()+"/protocol/openid-connect/registrations?") || !strings.Contains(loc, "code_challenge_method=S256") {
		t.Errorf("register: %d %q", rec.Code, loc)
	}
	if rec := get("/register?provider=other"); rec.Code != http.StatusNotFound {
		t.Errorf("register without support: %d %s", rec.Code, rec.Body.String())
	}
	// The kit assets serve from the auth service too, so the page has its
	// stylesheet when it runs alone.
	if rec := get("/static/vca.css"); rec.Code != http.StatusOK {
		t.Errorf("stylesheet: %d", rec.Code)
	}
}

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := baseConfig(t)
	cfg.ThemeFile = path
	_, err := server.Build(cfg, quiet)
	uikittest.AssertBadThemeError(t, err, path)
}

// flowFixture builds the service over a fake OpenID Provider whose ID
// tokens carry the given realm roles, and returns the handler.
func flowFixture(t *testing.T, realmRoles ...string) (*oidctest.Provider, http.Handler) {
	t.Helper()
	idp := oidctest.New()
	t.Cleanup(idp.Close)
	idp.Claims = map[string]any{"realm_access": map[string]any{"roles": realmRoles}, "name": "Verifier One"}
	cfg := baseConfig(t)
	cfg.InsecureCookie = true
	svc, err := server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Providers().Put(oidcflow.Provider{
		ID: "idp", DisplayName: "Test IdP", DiscoveryURL: idp.DiscoveryURL(), ClientID: idp.ClientID, Enabled: true,
		RolesClaimPath: "realm_access.roles", Roles: []string{"verifier"},
	}); err != nil {
		t.Fatal(err)
	}
	return idp, server.Handler(svc)
}

// login runs the browser flow through the handler and returns the
// session cookie value and the status of the callback.
func login(t *testing.T, idp *oidctest.Provider, h http.Handler) (string, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login?provider=idp&return_to=/portal/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login start: %d %s", rec.Code, rec.Body.String())
	}
	back, err := idp.Authorize(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, back, nil))
	for _, c := range rec.Result().Cookies() {
		if c.Name == "vca_verifier_session" {
			return c.Value, rec.Code
		}
	}
	return "", rec.Code
}

// TestLoginFlowAgainstFakeOP is ADR-036 decision 1: the verifier staff
// login runs the same code flow with PKCE as issuer-auth, ends at the
// return path with the session cookie, and the session endpoint reads
// the claims back.
func TestLoginFlowAgainstFakeOP(t *testing.T) {
	idp, h := flowFixture(t, "verifier-operator")
	token, status := login(t, idp, h)
	if token == "" || status != http.StatusSeeOther {
		t.Fatalf("callback: %d, cookie %q", status, token)
	}
	if idp.Requests["/token"] != 1 || idp.LastTokenForm.Get("code_verifier") == "" {
		t.Errorf("token request: %v", idp.LastTokenForm)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: "vca_verifier_session", Value: token})
	h.ServeHTTP(rec, req)
	var body struct {
		Claims struct {
			Roles []string `json:"roles"`
			Name  string   `json:"name"`
		} `json:"claims"`
		CSRF string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("session: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Join(body.Claims.Roles, ",") != "verifier-operator" || body.Claims.Name != "Verifier One" || body.CSRF == "" {
		t.Errorf("session body = %+v", body)
	}
}

// TestSessionAudienceIsVcaVerifier is ADR-036 decision 1: every session
// JWT carries aud vca-verifier, so an issuer or wallet token never
// passes a verifier guard.
func TestSessionAudienceIsVcaVerifier(t *testing.T) {
	if server.Audience != "vca-verifier" {
		t.Fatalf("Audience = %q", server.Audience)
	}
	idp, h := flowFixture(t, "verifier-viewer")
	token, _ := login(t, idp, h)
	claims, err := jose.PeekPayload(token)
	if err != nil {
		t.Fatal(err)
	}
	if got := anyval.Must(json.Marshal(claims["aud"])); string(got) != `["vca-verifier"]` {
		t.Errorf("aud = %s", got)
	}
	if claims["iss"] != "http://localhost:8081" {
		t.Errorf("iss = %v", claims["iss"])
	}
}

// TestRoleMappingVerifierRoles is ADR-036 decision 1: the roles are
// verifier-admin, verifier-operator, and verifier-viewer. The default
// mapping takes them from the realm roles claim by name, and a subject
// with none of them cannot log in.
func TestRoleMappingVerifierRoles(t *testing.T) {
	if roles.Admin != "verifier-admin" || roles.Operator != "verifier-operator" || roles.Viewer != "verifier-viewer" {
		t.Fatalf("roles = %q %q %q", roles.Admin, roles.Operator, roles.Viewer)
	}
	for name, want := range map[string]verifierauthv1.VerifierRole{
		roles.Admin:    verifierauthv1.VerifierRole_VERIFIER_ROLE_ADMIN,
		roles.Operator: verifierauthv1.VerifierRole_VERIFIER_ROLE_OPERATOR,
		roles.Viewer:   verifierauthv1.VerifierRole_VERIFIER_ROLE_VIEWER,
		"issuer-admin": verifierauthv1.VerifierRole_VERIFIER_ROLE_UNSPECIFIED,
	} {
		if got := roles.Value(name); got != want {
			t.Errorf("Value(%q) = %v, want %v", name, got, want)
		}
	}
	idp, h := flowFixture(t, "verifier-admin", "verifier-viewer", "issuer-admin")
	token, _ := login(t, idp, h)
	claims, err := jose.PeekPayload(token)
	if err != nil {
		t.Fatal(err)
	}
	if got := anyval.Must(json.Marshal(claims["roles"])); string(got) != `["verifier-admin","verifier-viewer"]` {
		t.Errorf("roles = %s", got)
	}
	// An issuer staff member holds no verifier role, so the login fails
	// with ErrRoleDenied, which the handler reports as 400.
	idp, h = flowFixture(t, "issuer-admin")
	if token, status := login(t, idp, h); token != "" || status != oidcflow.HTTPStatus(oidcflow.ErrRoleDenied) {
		t.Errorf("issuer staff: %d %q", status, token)
	}
}
