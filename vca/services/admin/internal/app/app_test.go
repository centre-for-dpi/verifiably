// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// quiet returns a logger that writes nothing to the test output.
func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func baseConfig() config.Config {
	return config.Config{
		Listen: ":0", PublicURL: "https://admin.example", RedirectURI: "https://admin.example/auth/callback",
		CookieName: "vca_admin_session", SessionTTL: 15 * time.Minute, Timeout: 5 * time.Second,
		PortalPrefix: "/admin", LogoutRedirect: "/admin/",
	}
}

func TestBuildWiresEveryRoute(t *testing.T) {
	a, err := app.Build(baseConfig(), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.Service == nil || a.Login == nil || a.Portal == nil || a.Mux == nil {
		t.Fatal("the wiring left a part out")
	}
	if a.BootstrapToken == "" {
		t.Fatal("the wiring printed no bootstrap token")
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	res, err := srv.Client().Get(srv.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	defer res.Body.Close()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		t.Fatalf("jwks body: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0]["alg"] != "ES256" {
		t.Fatalf("jwks = %+v", set.Keys)
	}
	static, err := srv.Client().Get(srv.URL + "/static/vca.css")
	if err != nil {
		t.Fatalf("assets: %v", err)
	}
	defer static.Body.Close()
	if static.StatusCode != http.StatusOK {
		t.Fatalf("assets status = %d", static.StatusCode)
	}
	rpc, err := srv.Client().Post(srv.URL+"/vca.admin.v1.AdminService/ListCommands", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("rpc: %v", err)
	}
	defer rpc.Body.Close()
	if rpc.StatusCode != http.StatusOK {
		t.Fatalf("rpc status = %d", rpc.StatusCode)
	}
}

func TestBuildKeepsTheStateOnDisk(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig()
	cfg.StateDir = dir
	cfg.BootstrapToken = "a-long-enough-bootstrap-token"
	first, err := app.Build(cfg, app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if first.BootstrapToken != cfg.BootstrapToken {
		t.Fatalf("token = %q", first.BootstrapToken)
	}
	if _, err := first.Login.Providers().Put(oidcflow.Provider{
		ID: "kept", DiscoveryURL: "https://idp.example/.well-known/openid-configuration",
		ClientID: "client", Enabled: true,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	second, err := app.Build(cfg, app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	if _, err := second.Login.Providers().Get("kept"); err != nil {
		t.Fatalf("the provider did not survive the restart: %v", err)
	}
	if second.BootstrapToken != cfg.BootstrapToken {
		t.Fatalf("the second start changed the token: %q", second.BootstrapToken)
	}
}

func TestBuildReportsABadStateDirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := baseConfig()
	cfg.StateDir = file
	if _, err := app.Build(cfg, app.Deps{Log: quiet()}); err == nil {
		t.Fatal("Build accepted a file as the state directory")
	}
}

func TestBuildReportsAMissingSigningKey(t *testing.T) {
	cfg := baseConfig()
	cfg.SigningKeyPath = filepath.Join(t.TempDir(), "absent.pem")
	if _, err := app.Build(cfg, app.Deps{Log: quiet()}); err == nil {
		t.Fatal("Build accepted a missing key file")
	}
}

func TestBuildReadsASigningKeyFile(t *testing.T) {
	key, err := oidcflow.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pem, err := oidcflow.EncodeKeyPEM(key)
	if err != nil {
		t.Fatalf("EncodeKeyPEM: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg := baseConfig()
	cfg.SigningKeyPath = path
	cfg.SessionKey = "0123456789abcdef0123456789abcdef"
	a, err := app.Build(cfg, app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.Login.Signer().KeyID() == "" {
		t.Fatal("the signer has no key id")
	}
}

func TestBuildBuildsATrustClientFromTheURL(t *testing.T) {
	cfg := baseConfig()
	cfg.TrustURL = "https://trust.example"
	if _, err := app.Build(cfg, app.Deps{Log: quiet()}); err != nil {
		t.Fatalf("Build: %v", err)
	}
}

func TestPersisterRoundTrip(t *testing.T) {
	p := app.Persister{KV: store.Memory()}
	var out []string
	if err := p.Load("providers", &out); err != nil || out != nil {
		t.Fatalf("Load of a missing document = %v, %v", out, err)
	}
	if err := p.Save("providers", []string{"one"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := p.Load("providers", &out); err != nil || len(out) != 1 || out[0] != "one" {
		t.Fatalf("Load = %v, %v", out, err)
	}
	var wrong int
	if err := p.Load("providers", &wrong); err == nil {
		t.Error("Load accepted a wrong type")
	}
	if err := p.Save("bad name", []string{"x"}); err == nil {
		t.Error("Save accepted a bad key")
	}
	if err := p.Load("bad name", &out); err == nil {
		t.Error("Load accepted a bad key")
	}
	if err := p.Save("providers", func() {}); err == nil {
		t.Error("Save accepted a value that is not JSON")
	}
}

func TestBootstrapIsSkippedWhenAnAdminExists(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig()
	cfg.StateDir = dir
	a, err := app.Build(cfg, app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.BootstrapToken == "" {
		t.Fatal("the first start printed no token")
	}
	// Bind an admin, then start again. The second start prints no token.
	if _, err := a.Login.OnboardAdmin(context.Background(), "", "", ""); err == nil {
		t.Fatal("OnboardAdmin accepted an empty request")
	}
	kv, err := store.File(filepath.Join(dir, "records"))
	if err != nil {
		t.Fatalf("store.File: %v", err)
	}
	if err := kv.Put(context.Background(), "admins/manual", []byte(`{"issuer":"https://idp.example","subject":"user"}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	second, err := app.Build(cfg, app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	if second.BootstrapToken != "" {
		t.Fatal("the second start printed a token although an admin exists")
	}
}

func TestBuildFillsTheOptionalDependencies(t *testing.T) {
	previous := slog.Default()
	slog.SetDefault(quiet())
	defer slog.SetDefault(previous)
	a, err := app.Build(baseConfig(), app.Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/admin/" {
		t.Fatalf("status = %d location = %q", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestBuildReportsNoTokenWhenTheBootstrapIsSpent(t *testing.T) {
	dir := t.TempDir()
	kv, err := store.File(filepath.Join(dir, "records"))
	if err != nil {
		t.Fatalf("store.File: %v", err)
	}
	spent := `{"hash":"0000","used_at":"2026-01-01T00:00:00Z"}`
	if err := kv.Put(context.Background(), "bootstrap", []byte(spent)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	cfg := baseConfig()
	cfg.StateDir = dir
	cfg.BootstrapToken = "another-long-bootstrap-token"
	a, err := app.Build(cfg, app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.BootstrapToken == "" {
		t.Fatal("a new token replaces a spent token, so the start prints one")
	}
}

func TestBuildReportsASignerFault(t *testing.T) {
	cfg := baseConfig()
	cfg.PublicURL = ""
	if _, err := app.Build(cfg, app.Deps{Log: quiet()}); err == nil {
		t.Fatal("Build accepted a configuration without a public URL")
	}
}

func TestBuildPrintsNoTokenWhenTheSameTokenIsSpent(t *testing.T) {
	dir := t.TempDir()
	kv, err := store.File(filepath.Join(dir, "records"))
	if err != nil {
		t.Fatalf("store.File: %v", err)
	}
	token := "a-spent-bootstrap-token-value"
	doc := `{"hash":"` + records.Hash(token) + `","used_at":"2026-01-01T00:00:00Z"}`
	if err := kv.Put(context.Background(), "bootstrap", []byte(doc)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	cfg := baseConfig()
	cfg.StateDir = dir
	cfg.BootstrapToken = token
	a, err := app.Build(cfg, app.Deps{Log: quiet()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.BootstrapToken != "" {
		t.Fatal("the start printed a token that is already spent")
	}
}
