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
	cfg.Seed = config.SeedProvider{DiscoveryURL: "https://idp/.well-known/openid-configuration", ClientID: "c", ClientSecretEnv: "S", RolesClaimPath: "roles"}
	svc, err = server.Build(cfg, quiet)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Providers().Get("default")
	if err != nil || p.ClientSecret.Name != "S" || !p.Enabled {
		t.Fatalf("seed: %+v %v", p, err)
	}
	// A second build keeps the stored record and does not overwrite it.
	_, _ = svc.Providers().Put(oidcflow.Provider{ID: "default", DisplayName: "Kept", DiscoveryURL: p.DiscoveryURL, ClientID: "c", Enabled: true})
	svc, _ = server.Build(cfg, quiet)
	if p, _ := svc.Providers().Get("default"); p.DisplayName != "Kept" {
		t.Fatal("seed overwrote the stored provider")
	}
	// A signing key file is used, and its kid is stable.
	key, _ := oidcflow.GenerateKey()
	pem, _ := oidcflow.EncodeKeyPEM(key)
	cfg.SigningKeyPath = filepath.Join(t.TempDir(), "key.pem")
	_ = os.WriteFile(cfg.SigningKeyPath, pem, 0o600)
	cfg.SessionKey = "0123456789abcdef0123456789abcdef"
	cfg.AdminToken = "t"
	a, _ := server.Build(cfg, quiet)
	b, _ := server.Build(cfg, quiet)
	if a.Signer().KeyID() != b.Signer().KeyID() {
		t.Fatal("kid differs between builds")
	}
	// Failures.
	cfg.SigningKeyPath = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("missing key accepted")
	}
	_ = os.WriteFile(cfg.SigningKeyPath, []byte("junk"), 0o600)
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
	_ = os.WriteFile(file, nil, 0o600)
	cfg.StateDir = filepath.Join(file, "x")
	if _, err := server.Build(cfg, quiet); err == nil {
		t.Fatal("bad state dir accepted")
	}
	for _, doc := range []string{"providers", "role_mappings", "clients"} {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, doc+".json"), []byte("{bad"), 0o600)
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
