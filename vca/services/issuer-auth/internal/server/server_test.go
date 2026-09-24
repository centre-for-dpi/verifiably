// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/server"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func baseConfig(t *testing.T) config.Config {
	t.Helper()
	c, err := config.FromEnv(func(k string) string {
		switch k {
		case "VCA_PUBLIC_URL":
			return "http://localhost:8081"
		case "VCA_ISSUER_AUTH_STATE_DIR":
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
// the issuer role, the console of that realm, and the default flag.
func TestSeedProviderIsKeycloakWithRealmAndConsole(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Seed = config.SeedProvider{
		DiscoveryURL:   "http://waltid-keycloak:8080/realms/vca-issuer-realm/.well-known/openid-configuration",
		ClientID:       "vca-issuer",
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
	if p.Kind != oidcflow.KindKeycloak || p.Realm != "vca-issuer-realm" || !p.IsDefault ||
		p.ConsoleURL != "http://localhost:17010/admin/vca-issuer-realm/console/" {
		t.Errorf("seed profile = %+v", p.Profile)
	}
	if len(p.Roles) != 1 || p.Roles[0] != "issuer" || p.RolesClaimPath != "realm_access.roles" {
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
