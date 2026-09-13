// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/fake"
)

func TestBuildServesEveryBackendService(t *testing.T) {
	f := fake.New("../../testdata")
	defer f.Close()
	a, err := app.Build(config.Config{
		Listen:      ":0",
		IssuerURL:   f.URL(),
		VerifierURL: f.URL(),
		WalletURL:   f.URL(),
		DpgVersion:  "0.18.2",
	}, app.Deps{HTTP: f.Client()})
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

func TestBuildOpensAFileStore(t *testing.T) {
	dir := t.TempDir()
	a, err := app.Build(config.Config{
		IssuerURL: "http://issuer.example",
		StoreFile: filepath.Join(dir, "state"),
	}, app.Deps{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if a.Mux == nil {
		t.Fatal("the mux is missing")
	}
}

func TestBuildReportsABadStoreDirectory(t *testing.T) {
	dir := t.TempDir()
	blocking := filepath.Join(dir, "file")
	if err := writeFile(blocking); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := app.Build(config.Config{
		IssuerURL: "http://issuer.example",
		StoreFile: filepath.Join(blocking, "state"),
	}, app.Deps{})
	if err == nil {
		t.Fatal("Build accepted a store path inside a file")
	}
}

// writeFile creates an empty file at the path.
func writeFile(path string) error {
	return osWriteFile(path)
}
