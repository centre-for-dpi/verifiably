// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
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

// staff stands in for issuer-auth: it signs the sessions the tests send.
func staff(t *testing.T) *staffsessiontest.Issuer {
	t.Helper()
	return staffsessiontest.New(t, staffsession.IssuerAudience, now)
}

func build(t *testing.T, cfg config.Config, backend backendv1connect.IssuerBackendServiceClient) *App {
	t.Helper()
	return buildWith(t, cfg, backend, staff(t))
}

func buildWith(t *testing.T, cfg config.Config, backend backendv1connect.IssuerBackendServiceClient, issuer *staffsessiontest.Issuer) *App {
	t.Helper()
	a, err := Build(cfg, Deps{
		Backend: backend, Now: func() time.Time { return now }, SessionKeys: issuer.Keys(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// serve answers one request, with the session cookie when token is set.
func serve(a *App, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	return rec
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
	issuer := staff(t)
	a := buildWith(t, settings(t), backend, issuer)
	token := issuer.Token(t, "kc|alice", "issuer-operator")
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
		rec := serve(a, http.MethodGet, c.path, token)
		if rec.Code != c.status {
			t.Fatalf("%s: status %d want %d", c.path, rec.Code, c.status)
		}
		if c.want != "" && !strings.Contains(rec.Body.String(), c.want) {
			t.Fatalf("%s: body has no %q", c.path, c.want)
		}
	}
	// The action form of a draft carries the token of the session, and
	// the guard accepts the form only with it.
	draft, createErr := a.Service.Create(context.Background(), connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: "Diploma", JsonSchema: doc, Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
		Display: []*schemav1.Display{{Name: "Diploma", Locale: "en"}},
	}}))
	if createErr != nil {
		t.Fatal(createErr)
	}
	page := serve(a, http.MethodGet, a.Portal.Prefix()+"/schemas/"+draft.Msg.GetSchema().GetId(), token)
	_, after, ok := strings.Cut(page.Body.String(), `name="`+staffsession.Field+`" value="`)
	if !ok {
		t.Fatal("the action form has no token")
	}
	csrf, _, _ := strings.Cut(after, `"`)
	publish := a.Portal.Prefix() + "/schemas/" + draft.Msg.GetSchema().GetId() + "/publish"
	form := url.Values{staffsession.Field: {csrf}, "version": {"1"}}
	req := httptest.NewRequest(http.MethodPost, publish, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: token})
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("publish: status %d body %s", rec.Code, rec.Body)
	}
	if len(backend.ids) != 2 {
		t.Fatalf("backend calls %v", backend.ids)
	}
}

// TestPortalNeedsSession proves that no staff page answers without a
// session (ADR-036 decision 3): a page request goes to the chooser with
// return_to and a POST gets 401.
func TestPortalNeedsSession(t *testing.T) {
	cfg := settings(t)
	cfg.Auth.LoginURL = "https://issuer-waltid.example/auth/"
	issuer := staff(t)
	a := buildWith(t, cfg, &fakeBackend{}, issuer)
	for _, path := range []string{a.Portal.Prefix() + "/", a.Portal.Prefix() + "/schemas/x", a.Portal.Prefix() + "/schemas/x/versions"} {
		rec := serve(a, http.MethodGet, path, "")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d, want 303", path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != cfg.Auth.LoginURL+"?return_to="+url.QueryEscape(path) {
			t.Fatalf("%s: location %q", path, got)
		}
	}
	if rec := serve(a, http.MethodPost, a.Portal.Prefix()+"/schemas/x/publish", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post: status %d, want 401", rec.Code)
	}
	// A session of the verifier realm does not open the issuer pages.
	verifier := staffsessiontest.New(t, staffsession.VerifierAudience, now)
	if rec := serve(a, http.MethodGet, a.Portal.Prefix()+"/", verifier.Token(t, "kc|bob")); rec.Code != http.StatusSeeOther {
		t.Fatalf("verifier session: status %d, want 303", rec.Code)
	}
	// A POST with a session but without the form token is refused.
	if rec := serve(a, http.MethodPost, a.Portal.Prefix()+"/schemas/x/publish", issuer.Token(t, "kc|alice")); rec.Code != http.StatusForbidden {
		t.Fatalf("post without token: status %d, want 403", rec.Code)
	}
	// Without a key source the service starts and lets nobody in.
	cfg.Auth.LoginURL = ""
	bare, err := Build(cfg, Deps{Backend: &fakeBackend{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(bare, http.MethodGet, bare.Portal.Prefix()+"/", issuer.Token(t, "kc|alice")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key source: status %d, want 401", rec.Code)
	}
}

// TestPublicEndpointsStayOpen proves that the OID4VCI metadata, the
// schema documents, and the JSON listing need no session (ADR-036
// decision 2).
func TestPublicEndpointsStayOpen(t *testing.T) {
	a := build(t, settings(t), &fakeBackend{})
	created, err := a.Service.Create(context.Background(), connect.NewRequest(&schemav1.CreateRequest{Schema: &schemav1.Schema{
		Type: "UniversityDegree", JsonSchema: doc, Formats: []commonv1.Format{commonv1.Format_FORMAT_DC_SD_JWT},
		Display: []*schemav1.Display{{Name: "Degree", Locale: "en"}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Msg.GetSchema().GetId()
	if _, err := a.Service.Publish(context.Background(), connect.NewRequest(&schemav1.PublishRequest{Id: id})); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		metadata.IssuerMetadataPath, metadata.SchemasPath, "/schemas/" + id + "/1",
		metadata.VctPrefix + "UniversityDegree", ui.Prefix + "vca.css", "/",
	} {
		rec := serve(a, http.MethodGet, path, "")
		if rec.Code != http.StatusOK && rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if rec.Header().Get("Location") != "" && !strings.HasPrefix(rec.Header().Get("Location"), a.Portal.Prefix()) {
			t.Fatalf("%s: sent to %q", path, rec.Header().Get("Location"))
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
		switch k {
		case "VCA_SCHEMA_BACKEND_URL":
			return "http://adapter.invalid"
		case "VCA_SCHEMA_ISSUED_URL":
			return "http://issued.invalid"
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

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := settings(t)
	cfg.ThemeFile = path
	_, err := Build(cfg, Deps{})
	uikittest.AssertBadThemeError(t, err, path)
}
