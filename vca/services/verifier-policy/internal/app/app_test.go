// SPDX-License-Identifier: Apache-2.0

package app

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/config"
)

// quiet returns a logger that writes nothing.
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func base(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBuildMemory(t *testing.T) {
	a, err := Build(base(t), Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if a.Mux == nil || !a.Service.Ready() || a.Sets == nil {
		t.Fatal("want a wired service")
	}
}

func TestBuildWithState(t *testing.T) {
	cfg := base(t)
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	cfg.TrustURL = "http://trust.example"
	cfg.Audience = "verifier"
	if _, err := Build(cfg, Deps{Log: quiet()}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildBadState(t *testing.T) {
	cfg := base(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := writeFile(file); err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = filepath.Join(file, "state")
	if _, err := Build(cfg, Deps{Log: quiet()}); err == nil {
		t.Fatal("want an error for a state directory under a file")
	}
}

func TestBuildBadConfig(t *testing.T) {
	if _, err := Build(config.Config{}, Deps{Log: quiet()}); err == nil {
		t.Fatal("want a configuration error")
	}
}

func TestHandlerServes(t *testing.T) {
	a, err := Build(base(t), Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	resp, err := srv.Client().Post(srv.URL+"/vca.policy.v1.PolicyService/ListChecks",
		"application/json", stringReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
}

func TestConnectClientDefault(t *testing.T) {
	if connectClient(base(t), Deps{}) == nil {
		t.Fatal("want a client")
	}
	if connectClient(base(t), Deps{ConnectClient: http.DefaultClient}) == nil {
		t.Fatal("want the injected client")
	}
}

// writeFile makes an empty file at path.
func writeFile(path string) error { return os.WriteFile(path, nil, 0o600) }

// stringReader returns a reader over s.
func stringReader(s string) io.Reader { return strings.NewReader(s) }
