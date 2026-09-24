// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/fake"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/a11ytest"
)

const document = `{"type":"object","title":"Diploma","properties":{"given_name":{"type":"string"}},"required":["given_name"]}`

func settings(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	values["REGISTRY_URL"] = "http://registry.test"
	cfg, err := config.Load(func(name string) string { return values[strings.TrimPrefix(name, config.Prefix)] })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// staff is one signed in issuer operator. Its issuer stands in for
// issuer-auth and signs the one session the requests of a test carry.
type staff struct {
	issuer *staffsessiontest.Issuer
	token  string
}

func login(t *testing.T) staff {
	t.Helper()
	// The wiring reads the real clock, so the session is minted now.
	issuer := staffsessiontest.New(t, staffsession.IssuerAudience, time.Now())
	return staff{issuer: issuer, token: issuer.Token(t, "kc|alice", "issuer-operator")}
}

// deps adds the key set of the staff issuer to d.
func (s staff) deps(d app.Deps) app.Deps {
	d.SessionKeys = s.issuer.Keys()
	return d
}

// request builds a request that carries the session.
func (s staff) request(method, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: s.token})
	return req
}

func build(t *testing.T, cfg config.Config, deps app.Deps) *app.App {
	t.Helper()
	deps.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := app.Build(cfg, deps)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return a
}

// csrfOf reads the form token out of a rendered page.
func csrfOf(t *testing.T, page string) string {
	t.Helper()
	_, after, ok := strings.Cut(page, `name="`+staffsession.Field+`" value="`)
	if !ok {
		t.Fatalf("no form token in %s", page)
	}
	value, _, _ := strings.Cut(after, `"`)
	return value
}

func TestWiring(t *testing.T) {
	registry := &fake.Registry{}
	catalog := &fake.Catalog{Entries: []*backendv1.CredentialConfiguration{{
		Id: "diploma", Format: commonv1.Format_FORMAT_DC_SD_JWT, Type: "Diploma", JsonSchema: document,
	}}}
	s := login(t)
	a := build(t, settings(t, map[string]string{}), s.deps(app.Deps{Registry: registry, Catalog: catalog}))
	if !a.Service.Ready() {
		t.Error("the service must be ready")
	}

	t.Run("the root redirects to the builder", func(t *testing.T) {
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("status = %d", rec.Code)
		}
		if got := rec.Header().Get("Location"); got != "/builder/" {
			t.Errorf("location = %q", got)
		}
	})

	t.Run("the builder page renders", func(t *testing.T) {
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, s.request(http.MethodGet, "/builder/", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		a11ytest.AssertPage(t, rec.Body.String())
	})

	t.Run("the import page lists the catalogue", func(t *testing.T) {
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, s.request(http.MethodGet, "/builder/import", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "diploma") {
			t.Error("the catalogue entry must show")
		}
	})

	t.Run("the assets are served", func(t *testing.T) {
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/vca.css", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, prefix %s", rec.Code, ui.Prefix)
		}
	})

	t.Run("the RPC handler answers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/vca.schemabuilder.v1.SchemaBuilderService/SampleData",
			strings.NewReader(`{"jsonSchema":`+quote(document)+`}`))
		req.Header.Set("Content-Type", "application/json")
		a.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "given_name") {
			t.Errorf("body = %s", rec.Body.String())
		}
	})

	t.Run("the PDF preview is served", func(t *testing.T) {
		page := httptest.NewRecorder()
		a.Mux.ServeHTTP(page, s.request(http.MethodGet, "/builder/", nil))
		values := url.Values{
			"type": {"Diploma"}, "field.0.name": {"given_name"}, "field.0.type": {"string"},
			staffsession.Field: {csrfOf(t, page.Body.String())},
		}
		req := s.request(http.MethodPost, "/builder/preview", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, req)
		body := rec.Body.String()
		i := strings.Index(body, "/pdf/preview/")
		if i < 0 {
			t.Fatalf("no PDF link: %s", body)
		}
		rest := body[i:]
		pdf := httptest.NewRecorder()
		a.Mux.ServeHTTP(pdf, httptest.NewRequest(http.MethodGet, rest[:strings.IndexAny(rest, `"<`)], nil))
		if pdf.Code != http.StatusOK {
			t.Fatalf("status = %d", pdf.Code)
		}
	})
}

// quote renders a JSON string for the RPC body.
func quote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func TestWiringWithoutACatalog(t *testing.T) {
	s := login(t)
	a := build(t, settings(t, map[string]string{"PREFIX": "/edit"}), s.deps(app.Deps{Registry: &fake.Registry{}}))
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, s.request(http.MethodGet, "/edit/import", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "no DPG catalogue") {
		t.Error("the page must say there is no catalogue")
	}
}

func TestWiringBuildsItsOwnClients(t *testing.T) {
	cfg := settings(t, map[string]string{"CATALOG_URL": "http://dpg.test"})
	s := login(t)
	a := build(t, cfg, s.deps(app.Deps{}))
	if a.Pages == nil {
		t.Error("the pages must be wired")
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, s.request(http.MethodGet, "/builder/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
}

// TestPortalNeedsSession proves that no builder page answers without a
// session (ADR-036 decision 3).
func TestPortalNeedsSession(t *testing.T) {
	cfg := settings(t, map[string]string{"LOGIN_URL": "https://issuer-waltid.example/auth/"})
	s := login(t)
	a := build(t, cfg, s.deps(app.Deps{Registry: &fake.Registry{}}))
	for _, path := range []string{"/builder/", "/builder/import", "/builder/?id=abc"} {
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d, want 303", path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != cfg.Auth.LoginURL+"?return_to="+url.QueryEscape(path) {
			t.Fatalf("%s: location %q", path, got)
		}
	}
	for _, path := range []string{"/builder/preview", "/builder/fields", "/builder/sample", "/builder/save", "/builder/import"} {
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", path, rec.Code)
		}
		// With a session but without the form token the post is refused.
		rec = httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, s.request(http.MethodPost, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", path, rec.Code)
		}
	}
	// A session of the verifier realm does not open the issuer pages.
	verifier := staffsessiontest.New(t, staffsession.VerifierAudience, time.Now())
	req := httptest.NewRequest(http.MethodGet, "/builder/", nil)
	req.AddCookie(&http.Cookie{Name: staffsession.IssuerCookie, Value: verifier.Token(t, "kc|bob")})
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("verifier session: status %d, want 303", rec.Code)
	}
}

// TestPublicEndpointsStayOpen proves the root redirect, the assets, the
// RPC, and the preview documents need no session.
func TestPublicEndpointsStayOpen(t *testing.T) {
	a := build(t, settings(t, map[string]string{}), login(t).deps(app.Deps{Registry: &fake.Registry{}}))
	for path, want := range map[string]int{"/": http.StatusSeeOther, "/static/vca.css": http.StatusOK, "/pdf/preview/missing": http.StatusNotFound} {
		rec := httptest.NewRecorder()
		a.Mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Fatalf("%s: status %d, want %d", path, rec.Code, want)
		}
	}
}

func TestWiringNeedsARegistry(t *testing.T) {
	if _, err := app.Build(config.Config{}, app.Deps{}); err == nil {
		t.Error("a build without a registry must fail")
	}
}

func TestWiringUsesTheDefaultLogger(t *testing.T) {
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer slog.SetDefault(previous)
	if _, err := app.Build(settings(t, map[string]string{}), app.Deps{Registry: &fake.Registry{}}); err != nil {
		t.Errorf("build: %v", err)
	}
}

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := settings(t, map[string]string{})
	cfg.ThemeFile = path
	_, err := app.Build(cfg, app.Deps{Registry: &fake.Registry{}})
	uikittest.AssertBadThemeError(t, err, path)
}
