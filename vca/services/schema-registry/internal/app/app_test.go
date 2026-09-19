// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	schemav1 "github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

const doc = `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`

var now = time.Date(2024, 1, 31, 10, 0, 0, 0, time.UTC)

// fakeBackend records the configurations the service registers.
type fakeBackend struct {
	backendv1connect.UnimplementedIssuerBackendServiceHandler
	ids []string
}

func (f *fakeBackend) RegisterCredentialConfiguration(_ context.Context, req *connect.Request[backendv1.RegisterCredentialConfigurationRequest]) (*connect.Response[backendv1.RegisterCredentialConfigurationResponse], error) {
	id := req.Msg.GetConfiguration().GetId()
	f.ids = append(f.ids, id)
	return connect.NewResponse(&backendv1.RegisterCredentialConfigurationResponse{Id: "dpg-" + id}), nil
}

func build(t *testing.T, cfg config.Config, backend backendv1connect.IssuerBackendServiceClient) *App {
	t.Helper()
	a, err := Build(cfg, Deps{
		Backend: backend, Now: func() time.Time { return now },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func settings(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load(func(k string) string {
		if k == "VCA_SCHEMA_STORE_FILE" {
			return filepath.Join(t.TempDir(), "schemas.json")
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestBuildServesEveryRoute(t *testing.T) {
	backend := &fakeBackend{}
	a := build(t, settings(t), backend)
	if !a.Service.Ready() {
		t.Fatal("not ready")
	}
	created, err := a.Service.Create(context.Background(), connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: "UniversityDegree", JsonSchema: doc,
		Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
		Display: []*schemav1.Display{{Name: "Degree", Locale: "en"}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSchema().GetId()
	if _, err := a.Service.Publish(context.Background(), connect.NewRequest(&schemav1.PublishRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	if len(backend.ids) != 1 {
		t.Fatalf("backend calls %v", backend.ids)
	}
	cases := []struct {
		path   string
		status int
		want   string
	}{
		{"/", http.StatusSeeOther, ""},
		{a.Portal.Prefix() + "/", http.StatusOK, "Schemas"},
		{a.Portal.Prefix() + "/schemas/" + id, http.StatusOK, "UniversityDegree"},
		{metadata.SchemasPath, http.StatusOK, "UniversityDegree"},
		{metadata.IssuerMetadataPath, http.StatusOK, "credential_configurations_supported"},
		{metadata.VctPrefix + "UniversityDegree", http.StatusOK, "vct"},
		{"/schemas/" + id + "/1", http.StatusOK, "$id"},
		{ui.Prefix + "vca.css", http.StatusOK, ""},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.status {
			t.Fatalf("%s: status %d want %d", c.path, rec.Code, c.status)
		}
		if c.want != "" && !strings.Contains(rec.Body.String(), c.want) {
			t.Fatalf("%s: body has no %q", c.path, c.want)
		}
	}
}

func TestConnectHandlerIsMounted(t *testing.T) {
	a := build(t, settings(t), nil)
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	client := schemaClient(srv.URL)
	resp, err := client.List(context.Background(), connect.NewRequest(&schemav1.ListRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Msg.GetSchemas()) != 0 {
		t.Fatalf("schemas %v", resp.Msg.GetSchemas())
	}
	meta, err := client.GetIssuerMetadata(context.Background(), connect.NewRequest(&schemav1.GetIssuerMetadataRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(meta.Msg.GetMetadata()), &out); err != nil {
		t.Fatal(err)
	}
	if out["credential_issuer"] != "http://localhost:8080" {
		t.Fatalf("issuer %v", out["credential_issuer"])
	}
}

func TestBuildMemoryStoreAndBackendURL(t *testing.T) {
	cfg, err := config.Load(func(k string) string {
		if k == "VCA_SCHEMA_BACKEND_URL" {
			return "http://adapter.invalid"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Build(cfg, Deps{})
	if err != nil {
		t.Fatal(err)
	}
	if a.Mux == nil || storeName(cfg) != "memory" {
		t.Fatal("memory store")
	}
	if storeName(config.Config{StoreFile: "/data/x.json"}) != "/data/x.json" {
		t.Fatal("store name")
	}
}

func TestBuildRejectsABadStoreFile(t *testing.T) {
	cfg := settings(t)
	cfg.StoreFile = filepath.Join(t.TempDir(), "missing", "schemas.json")
	if _, err := Build(cfg, Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err != nil {
		t.Fatal("a missing file is an empty store")
	}
	bad := filepath.Join(t.TempDir(), "broken.json")
	if err := writeFile(bad, "{"); err != nil {
		t.Fatal(err)
	}
	cfg.StoreFile = bad
	if _, err := Build(cfg, Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}); err == nil {
		t.Fatal("want a parse error")
	}
}

// writeFile writes text to path, for the broken store test.
func writeFile(path, text string) error {
	return os.WriteFile(path, []byte(text), 0o600)
}

// schemaClient builds a Connect client for the test server.
func schemaClient(base string) schemav1connect.SchemaServiceClient {
	return schemav1connect.NewSchemaServiceClient(http.DefaultClient, base)
}
