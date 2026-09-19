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

	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/config"
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
	if a.Mux == nil || !a.Service.Ready() || a.Templates == nil {
		t.Fatal("want a wired service")
	}
}

func TestBuildWithClients(t *testing.T) {
	cfg := base(t)
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	cfg.PolicyURL = "http://policy.example"
	cfg.DiscoveryURL = "http://discovery.example"
	cfg.ResultsURL = "http://results.example"
	if _, err := Build(cfg, Deps{Log: quiet()}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildWithDefaultLogger(t *testing.T) {
	if _, err := Build(base(t), Deps{}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildBadState(t *testing.T) {
	cfg := base(t)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
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
	resp, err := srv.Client().Post(srv.URL+"/vca.combined.v1.CombinedService/List",
		"application/json", strings.NewReader("{}"))
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
