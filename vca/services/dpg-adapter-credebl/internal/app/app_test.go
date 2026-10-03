// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/peerauth/peertest"
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
		DpgVersion:  "latest",
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
		"/vca.backend.v1.TenantBackendService/ListTenants",
		"/vca.backend.v1.NotificationBackendService/GetWebhook",
		"/vca.backend.v1.BulkImportBackendService/ListBulkFiles",
	}
	for _, path := range paths {
		resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
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

// TestBuildWiresTheHolderAgent is ADR-062 decision 7: with the agent
// the adapter serves the holder role, and without it the role is off.
func TestBuildWiresTheHolderAgent(t *testing.T) {
	peers := peertest.New(t)
	f := fake.New(testdata)
	defer f.Close()
	agent := fake.NewAgent(testdata)
	defer agent.Close()
	cfg := settings(f)
	cfg.AgentURL, cfg.AgentAPIKey, cfg.HolderLabel = agent.URL(), fake.AgentAPIKey, "Wallet"
	a, err := buildPeered(peers, cfg, app.Deps{HTTP: f.Client()})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	resp, err := peers.Client(srv.Client()).Post(srv.URL+"/vca.backend.v1.HolderBackendService/Register", "application/json",
		strings.NewReader(`{"pairwiseSubject":"s-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); cerr != nil || err != nil {
		t.Fatalf("read: %v %v", err, cerr)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), fake.FirstTenant) {
		t.Fatalf("Register: %d %s", resp.StatusCode, body)
	}
}

// TestBuildWiresTheStatusList lists revocation when the settings name
// the status list host of the stack (P6-C5b).
func TestBuildWiresTheStatusList(t *testing.T) {
	peers := peertest.New(t)
	f := fake.New(testdata)
	defer f.Close()
	for _, on := range []bool{false, true} {
		cfg := settings(f)
		cfg.StatusList = on
		a, err := buildPeered(peers, cfg, app.Deps{HTTP: f.Client()})
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		srv := httptest.NewServer(a.Mux)
		resp, err := peers.Client(srv.Client()).Post(srv.URL+"/vca.backend.v1.CapabilityService/GetCapabilities", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		if cerr := resp.Body.Close(); cerr != nil || err != nil {
			t.Fatalf("read: %v %v", err, cerr)
		}
		srv.Close()
		if strings.Contains(string(body), "FEATURE_REVOCATION") != on {
			t.Errorf("status list %v: %s", on, body)
		}
	}
}

// buildPeered builds the service with an identity that lets the client
// of peers call every RPC (ADR-075).
func buildPeered(peers *peertest.Kit, cfg config.Config, deps app.Deps) (*app.App, error) {
	cfg.Peer = peers.Open("dpg-adapter-credebl")
	return app.Build(cfg, deps)
}
