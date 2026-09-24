// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"errors"
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

	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/app"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/config"
)

// quiet drops the log messages of the tests.
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeTrust answers one trusted issuer.
type fakeTrust struct {
	trustv1connect.UnimplementedTrustServiceHandler
	endpoint string
	calls    int
}

func (f *fakeTrust) ListEntries(context.Context, *connect.Request[trustv1.ListEntriesRequest]) (*connect.Response[trustv1.ListEntriesResponse], error) {
	f.calls++
	return connect.NewResponse(&trustv1.ListEntriesResponse{Entries: []*trustv1.TrustEntry{{
		Identifier:      &trustv1.TrustEntry_Identifier{Id: &trustv1.TrustEntry_Identifier_Did{Did: "did:web:a"}},
		DisplayName:     "Alpha",
		ServiceEndpoint: f.endpoint,
	}}}), nil
}

func (f *fakeTrust) TrustLookup(context.Context, *connect.Request[trustv1.TrustLookupRequest]) (*connect.Response[trustv1.TrustLookupResponse], error) {
	return connect.NewResponse(&trustv1.TrustLookupResponse{Outcome: trustv1.TrustLookupResponse_OUTCOME_TRUSTED}), nil
}

// issuerServer answers the metadata and the schema list.
func issuerServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", func(w http.ResponseWriter, r *http.Request) {
		mustWrite(t, w, []byte(`{"credential_issuer":"`+"http://"+r.Host+`",
			"credential_configurations_supported":{"pid":{"format":"dc+sd-jwt","vct":"pid"}}}`))
	})
	mux.HandleFunc("GET /api/schemas", func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte(`{"schemas":[]}`))
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// settings returns a configuration for the tests.
func settings(t *testing.T, values map[string]string) config.Config {
	t.Helper()
	base := map[string]string{
		"VCA_DISCOVERY_ALLOW_PLAIN_HTTP":      "true",
		"VCA_DISCOVERY_ALLOW_PRIVATE_NETWORK": "true",
		"VCA_DISCOVERY_STATE_DIR":             filepath.Join(t.TempDir(), "state"),
	}
	for k, v := range values {
		base[k] = v
	}
	cfg, err := config.Load(func(name string) string { return base[name] })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

var now = time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)

// staff stands in for verifier-auth: it signs the sessions the tests send.
func staff(t *testing.T) *staffsessiontest.Issuer {
	t.Helper()
	return staffsessiontest.New(t, staffsession.VerifierAudience, now)
}

// serve answers one request, with the session cookie when token is set.
func serve(a *app.App, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.VerifierCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	return rec
}

func TestBuildAndServe(t *testing.T) {
	issuer := issuerServer(t)
	trust := &fakeTrust{endpoint: issuer.URL}
	auth := staff(t)
	a, err := app.Build(settings(t, nil), app.Deps{Trust: trust, Log: quiet(), SessionKeys: auth.Keys(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Service.Ready() || !a.Crawler.Enabled() {
		t.Fatal("the wiring returns a ready service with a crawler")
	}
	s := httptest.NewServer(a.Mux)
	defer s.Close()
	if _, err := a.Crawler.Run(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/catalog", "/catalog/issuers", "/catalog/types", "/portal/", "/static/vca.css"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(auth.Cookie(staffsession.VerifierCookie, auth.Token(t, "kc|carol", "verifier-operator")))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s answered %d", path, resp.StatusCode)
		}
	}
}

// TestPortalNeedsSession proves that no staff page answers without a
// session (ADR-036 decision 2) and that a post needs the form token.
func TestPortalNeedsSession(t *testing.T) {
	auth := staff(t)
	cfg := settings(t, map[string]string{"VCA_DISCOVERY_LOGIN_URL": "https://verifier-waltid.example/auth/"})
	trust := &fakeTrust{endpoint: issuerServer(t).URL}
	a, err := app.Build(cfg, app.Deps{Trust: trust, Log: quiet(), SessionKeys: auth.Keys(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/portal/", "/portal/types", "/portal/templates", "/portal/templates/x"} {
		rec := serve(a, http.MethodGet, path, "")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d, want 303", path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != cfg.Auth.LoginURL+"?return_to="+url.QueryEscape(path) {
			t.Fatalf("%s: location %q", path, got)
		}
	}
	token := auth.Token(t, "kc|carol", "verifier-operator")
	for _, path := range []string{"/portal/crawl", "/portal/templates", "/portal/templates/x/delete"} {
		if rec := serve(a, http.MethodPost, path, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", path, rec.Code)
		}
		if rec := serve(a, http.MethodPost, path, token); rec.Code != http.StatusForbidden {
			t.Fatalf("%s with a session: status %d, want 403", path, rec.Code)
		}
	}
	// The crawl form of the issuer page carries the token, and the guard
	// takes it.
	page := serve(a, http.MethodGet, "/portal/", token)
	_, after, ok := strings.Cut(page.Body.String(), `name="`+staffsession.Field+`" value="`)
	if !ok {
		t.Fatal("the crawl form has no token")
	}
	csrf, _, _ := strings.Cut(after, `"`)
	form := url.Values{staffsession.Field: {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/portal/crawl", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(auth.Cookie(staffsession.VerifierCookie, token))
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("crawl: status %d body %s", rec.Code, rec.Body)
	}
	// A session of the issuer realm does not open the verifier pages.
	other := staffsessiontest.New(t, staffsession.IssuerAudience, now)
	if rec := serve(a, http.MethodGet, "/portal/", other.Token(t, "kc|alice")); rec.Code != http.StatusSeeOther {
		t.Fatalf("issuer session: status %d, want 303", rec.Code)
	}
}

// TestPublicEndpointsStayOpen proves the catalogue endpoints need no
// session (ADR-036 decision 2).
func TestPublicEndpointsStayOpen(t *testing.T) {
	cfg := settings(t, map[string]string{"VCA_DISCOVERY_LOGIN_URL": "https://verifier-waltid.example/auth/"})
	a, err := app.Build(cfg, app.Deps{Log: quiet(), SessionKeys: staff(t).Keys()})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/catalog", "/catalog/issuers", "/catalog/types", "/static/vca.css"} {
		if rec := serve(a, http.MethodGet, path, ""); rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
	}
	// Without a key source the service starts and lets nobody in.
	bare, err := app.Build(settings(t, nil), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(bare, http.MethodGet, "/portal/", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key source: status %d, want 401", rec.Code)
	}
	cfg.Auth.JWKSFile = filepath.Join(t.TempDir(), "missing.json")
	if _, err := app.Build(cfg, app.Deps{Log: quiet()}); err == nil {
		t.Fatal("a missing key set file built")
	}
}

func TestBuildWithoutTrustRegistry(t *testing.T) {
	a, err := app.Build(settings(t, map[string]string{"VCA_DISCOVERY_STATE_DIR": ""}), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if a.Crawler.Enabled() {
		t.Error("a deployment without a trust URL has no crawler")
	}
}

func TestBuildWithTrustURL(t *testing.T) {
	a, err := app.Build(settings(t, map[string]string{"VCA_DISCOVERY_TRUST_URL": "http://127.0.0.1:1/"}), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Crawler.Enabled() {
		t.Error("a trust URL builds a client")
	}
}

func TestBuildRejectsBadStateDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := writeFile(file); err != nil {
		t.Fatal(err)
	}
	_, err := app.Build(settings(t, map[string]string{"VCA_DISCOVERY_STATE_DIR": file}), app.Deps{Log: quiet()})
	if err == nil {
		t.Error("a state directory that is a file wants an error")
	}
}

// writeFile makes an empty file at path.
func writeFile(path string) error {
	return os.WriteFile(path, nil, 0o600)
}

func TestCrawlJob(t *testing.T) {
	issuer := issuerServer(t)
	trust := &fakeTrust{endpoint: issuer.URL}
	a, err := app.Build(settings(t, map[string]string{"VCA_DISCOVERY_CRAWL_INTERVAL": "10ms"}), app.Deps{Trust: trust, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	a.Crawl(ctx, quiet())
	if trust.calls == 0 {
		t.Error("the scheduled crawl reads the trust list")
	}
}

func TestCrawlJobOff(t *testing.T) {
	a, err := app.Build(settings(t, map[string]string{"VCA_DISCOVERY_CRAWL_INTERVAL": "0s"}), app.Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	// The job returns at once, so the test does not block.
	a.Crawl(context.Background(), quiet())
}

func TestCrawlJobLogsFailure(t *testing.T) {
	trust := &fakeTrust{endpoint: "http://127.0.0.1:1"}
	a, err := app.Build(settings(t, map[string]string{"VCA_DISCOVERY_CRAWL_INTERVAL": "10ms"}), app.Deps{Trust: trust, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	a.Crawl(ctx, quiet())
}

func TestBuildWithDefaultDeps(t *testing.T) {
	if _, err := app.Build(settings(t, nil), app.Deps{}); err != nil {
		t.Fatalf("the wiring fills the missing side effects: %v", err)
	}
}

// failingTrust answers an error.
type failingTrust struct {
	trustv1connect.UnimplementedTrustServiceHandler
}

func (failingTrust) ListEntries(context.Context, *connect.Request[trustv1.ListEntriesRequest]) (*connect.Response[trustv1.ListEntriesResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("the registry is down"))
}

func TestCrawlJobWithBrokenRegistry(t *testing.T) {
	a, err := app.Build(settings(t, map[string]string{"VCA_DISCOVERY_CRAWL_INTERVAL": "10ms"}),
		app.Deps{Trust: failingTrust{}, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	a.Crawl(ctx, quiet())
}

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := settings(t, nil)
	cfg.ThemeFile = path
	_, err := app.Build(cfg, app.Deps{Log: quiet()})
	uikittest.AssertBadThemeError(t, err, path)
}
