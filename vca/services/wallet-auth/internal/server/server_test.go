// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow/oidctest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/signin"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/limits"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/server"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func baseConfig(t *testing.T) config.Config {
	t.Helper()
	c, err := config.FromEnv(func(k string) string {
		switch k {
		case "VCA_PUBLIC_URL":
			return "http://localhost:8083"
		case "VCA_WALLET_AUTH_STATE_DIR":
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
// the holder role, the console of that realm, and the default flag.
func TestSeedProviderIsKeycloakWithRealmAndConsole(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Seed = config.SeedProvider{
		DiscoveryURL: "http://inji-keycloak:8080/realms/vca-holder-realm/.well-known/openid-configuration",
		ClientID:     "vca-holder",
		PublicURL:    "http://localhost:17080",
	}
	svc, err := server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Providers().Get(oidcflow.SeedID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != oidcflow.KindKeycloak || p.Realm != "vca-holder-realm" || !p.IsDefault ||
		p.ConsoleURL != "http://localhost:17080/admin/vca-holder-realm/console/" {
		t.Errorf("seed profile = %+v", p.Profile)
	}
	if len(p.Roles) != 1 || p.Roles[0] != "holder" || len(p.Scopes) != 1 || p.Scopes[0] != "openid" || !p.ClientSecret.IsZero() {
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
	cfg.Seed = config.SeedProvider{DiscoveryURL: "https://idp/.well-known/openid-configuration", ClientID: "c", ClientSecret: "S"}
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
	cfg.AdminJWKSURL = "http://admin.invalid/.well-known/jwks.json"
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
	// Redis is selected but this build has no client.
	cfg.StateDir = t.TempDir()
	cfg.RedisURL = "redis://cache:6379"
	if _, err := server.Build(cfg, quiet); !errors.Is(err, limits.ErrNotConfigured) {
		t.Fatalf("redis: %v", err)
	}
	cfg.RedisURL = ""
	// A holder backend URL selects the Connect registrar.
	cfg.HolderBackendURL = "http://adapter:8090"
	cfg.Salt = []byte("0123456789abcdef")
	cfg.GrantKey = []byte("0123456789abcdef0123456789abcdef")
	if _, err := server.Build(cfg, quiet); err != nil {
		t.Fatal(err)
	}
	cfg.HolderBackendURL = ""
	for _, doc := range []string{"providers", "wallets", "grants"} {
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

// TestAuthRootServesChooser is P1-08 for the holder: the chooser, the
// listing, and the register start answer under every prefix the pair
// proxy and a peer use, the register start honours the login rate
// limit, and a provider with no register action gives 404.
func TestAuthRootServesChooser(t *testing.T) {
	realm := oidctest.New()
	defer realm.Close()
	cfg := baseConfig(t)
	cfg.LandingURL = "https://vca.example"
	cfg.LoginRate = 2
	svc, err := server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Providers().Put(oidcflow.Provider{
		ID: "default", DisplayName: "Keycloak", DiscoveryURL: realm.DiscoveryURL(), ClientID: realm.ClientID, Enabled: true,
		Profile: oidcflow.Profile{Kind: oidcflow.KindKeycloak, Realm: "vca-holder-realm", IsDefault: true},
	}); err != nil {
		t.Fatal(err)
	}
	h := server.Handler(svc)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.0.0.9:1234"
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, prefix := range server.Prefixes {
		rec := get(prefix + "/")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s/: status %d: %s", prefix, rec.Code, rec.Body.String())
		}
		doc := rec.Body.String()
		a11ytest.AssertPage(t, doc)
		for _, want := range []string{
			`<h1>Sign in as a holder.</h1>`, `<span class="signin-meta">vca-holder-realm</span>`,
			`href="/auth/login?provider=default&amp;return_to=%2Fwallet%2F"`, `href="/auth/register?provider=default&amp;return_to=%2Fwallet%2F"`,
			`href="https://vca.example/roles/"`,
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("%s/ missing %q\n%s", prefix, want, doc)
			}
		}
		var listing signin.Listing
		if rec := get(prefix + "/providers.json"); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &listing) != nil || listing.Role != "holder" || len(listing.Providers) != 1 || !listing.Providers[0].Register {
			t.Errorf("%s/providers.json: %d %s", prefix, rec.Code, rec.Body.String())
		}
	}
	rec := get("/auth/register?provider=default")
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || !strings.HasPrefix(loc, realm.Issuer()+"/protocol/openid-connect/registrations?") {
		t.Errorf("register: %d %q", rec.Code, loc)
	}
	if rec := get("/register?provider=nope"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown provider: %d", rec.Code)
	}
	// The third start from the same address in a minute is refused.
	if rec := get("/wallet/auth/register?provider=default"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("rate limit: %d", rec.Code)
	}
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
