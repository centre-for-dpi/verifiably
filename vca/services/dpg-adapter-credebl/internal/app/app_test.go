// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/fake"
)

const testdata = "../../testdata"

// settings returns a working configuration for the fake.
func settings(f *fake.Server) config.Config {
	return config.Config{
		Listen:      ":0",
		APIURL:      f.URL(),
		Email:       "admin@example.org",
		Password:    "secret",
		CryptoKey:   "key",
		OrgID:       "org-1",
		IssuerID:    "issuer-1",
		PublicURL:   "https://credebl.example.org",
		InternalURL: "http://credebl-agent:8001",
		DpgVersion:  "2.x",
		Timeout:     5 * time.Second,
		MaxBytes:    1 << 20,
	}
}

func TestBuildServesEveryBackendService(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	a, err := app.Build(settings(f), app.Deps{HTTP: f.Client()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !a.Service.Ready() {
		t.Fatal("the service is not ready")
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	paths := []string{
		"/vca.backend.v1.CapabilityService/GetCapabilities",
		"/vca.backend.v1.IssuerBackendService/GetIssuerMetadata",
		"/vca.backend.v1.HolderBackendService/Register",
		"/vca.backend.v1.VerifierBackendService/CreateRequest",
		"/vca.backend.v1.CatalogBackendService/ListCredentialTypes",
	}
	for _, path := range paths {
		resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Fatalf("%s is not served", path)
		}
	}
}

func TestBuildWarnsWithoutAHostRewrite(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	cfg := settings(f)
	cfg.PublicURL = ""
	a, err := app.Build(cfg, app.Deps{HTTP: f.Client()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.Mux == nil {
		t.Fatal("the mux is missing")
	}
}

func TestBuildOpensAFileStore(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	cfg := settings(f)
	cfg.StoreFile = filepath.Join(t.TempDir(), "state")
	if _, err := app.Build(cfg, app.Deps{HTTP: f.Client()}); err != nil {
		t.Fatalf("Build: %v", err)
	}
}

func TestBuildReportsABadStoreDirectory(t *testing.T) {
	f := fake.New(testdata)
	defer f.Close()
	blocking := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocking, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := settings(f)
	cfg.StoreFile = filepath.Join(blocking, "state")
	if _, err := app.Build(cfg, app.Deps{HTTP: f.Client()}); err == nil {
		t.Fatal("Build accepted a store path inside a file")
	}
}
