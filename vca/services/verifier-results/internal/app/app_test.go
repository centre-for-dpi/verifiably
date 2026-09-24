// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession/staffsessiontest"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit/uikittest"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/config"
)

var testNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

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

// fakePolicy answers Evaluate with a fixed response.
type fakePolicy struct {
	policyv1connect.PolicyServiceClient
}

func (fakePolicy) Evaluate(context.Context, *connect.Request[policyv1.EvaluateRequest]) (
	*connect.Response[policyv1.EvaluateResponse], error) {
	return connect.NewResponse(&policyv1.EvaluateResponse{
		Verdict: policyv1.EvaluateResponse_VERDICT_VALID, EvaluatedAt: timestamppb.New(testNow),
	}), nil
}

func TestBuildMemory(t *testing.T) {
	a, err := Build(base(t), Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if a.Mux == nil || !a.Service.Ready() || a.Store == nil || a.Portal == nil {
		t.Fatal("want a wired service")
	}
}

func TestBuildWithStateAndPolicy(t *testing.T) {
	cfg := base(t)
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	cfg.PolicyURL = "http://policy.example"
	if _, err := Build(cfg, Deps{Log: quiet()}); err != nil {
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

func TestBuildBadRetention(t *testing.T) {
	cfg := base(t)
	cfg.PageSizeMax = 1
	cfg.Retention = time.Hour
	cfg.RawRetention = time.Hour
	if _, err := Build(cfg, Deps{Log: quiet()}); err != nil {
		t.Fatal(err)
	}
}

// staff stands in for verifier-auth: it signs the sessions the tests send.
func staff(t *testing.T) *staffsessiontest.Issuer {
	t.Helper()
	return staffsessiontest.New(t, staffsession.VerifierAudience, testNow)
}

// serve answers one request, with the session cookie when token is set.
func serve(a *App, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: staffsession.VerifierCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	return rec
}

func TestHandlerServes(t *testing.T) {
	issuer := staff(t)
	a, err := Build(base(t), Deps{Log: quiet(), Policy: fakePolicy{}, Now: func() time.Time { return testNow }, SessionKeys: issuer.Keys()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Mux)
	defer srv.Close()
	resp, err := srv.Client().Post(srv.URL+"/vca.results.v1.ResultsService/Query",
		"application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	pageReq, err := http.NewRequest(http.MethodGet, srv.URL+a.Portal.Prefix()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	pageReq.AddCookie(&http.Cookie{Name: staffsession.VerifierCookie, Value: issuer.Token(t, "kc|carol", "verifier-viewer")})
	page, err := srv.Client().Do(pageReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := page.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if page.StatusCode != http.StatusOK {
		t.Fatalf("want the portal page, got %d", page.StatusCode)
	}
	css, err := srv.Client().Get(srv.URL + "/static/vca.css")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := css.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	if css.StatusCode != http.StatusOK {
		t.Fatalf("want the stylesheet, got %d", css.StatusCode)
	}
	check, err := srv.Client().PostForm(srv.URL+a.Portal.PublicPrefix()+"/",
		map[string][]string{"presentation": {`{"@context":["x"],"issuer":"did:web:a"}`}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := check.Body.Close(); cerr != nil {
			t.Errorf("the close failed: %v", cerr)
		}
	}()
	body, err := io.ReadAll(check.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Verification summary") {
		t.Fatalf("want the citizen card, got %s", body)
	}
}

// TestPortalNeedsSession proves that no staff page answers without a
// session (ADR-036 decision 2): a page request goes to the chooser with
// return_to.
func TestPortalNeedsSession(t *testing.T) {
	cfg := base(t)
	cfg.Auth.LoginURL = "https://verifier-waltid.example/auth/"
	issuer := staff(t)
	a, err := Build(cfg, Deps{Log: quiet(), Policy: fakePolicy{}, SessionKeys: issuer.Keys(), Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{a.Portal.Prefix() + "/", a.Portal.Prefix() + "/results/x", a.Portal.Prefix() + "/export?format=csv"} {
		rec := serve(a, http.MethodGet, path, "")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: status %d, want 303", path, rec.Code)
		}
		if got := rec.Header().Get("Location"); got != cfg.Auth.LoginURL+"?return_to="+url.QueryEscape(path) {
			t.Fatalf("%s: location %q", path, got)
		}
	}
	// A session of the issuer realm does not open the verifier pages.
	other := staffsessiontest.New(t, staffsession.IssuerAudience, testNow)
	if rec := serve(a, http.MethodGet, a.Portal.Prefix()+"/", other.Token(t, "kc|alice")); rec.Code != http.StatusSeeOther {
		t.Fatalf("issuer session: status %d, want 303", rec.Code)
	}
	if rec := serve(a, http.MethodGet, a.Portal.Prefix()+"/", issuer.Token(t, "kc|carol")); rec.Code != http.StatusOK {
		t.Fatalf("verifier session: status %d, want 200", rec.Code)
	}
	// Without a key source the service starts and lets nobody in.
	bare, err := Build(base(t), Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(bare, http.MethodGet, bare.Portal.Prefix()+"/", issuer.Token(t, "kc|carol")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key source: status %d, want 401", rec.Code)
	}
}

func TestBuildBadKeySetFile(t *testing.T) {
	cfg := base(t)
	cfg.Auth.JWKSFile = filepath.Join(t.TempDir(), "missing.json")
	if _, err := Build(cfg, Deps{Log: quiet()}); err == nil {
		t.Fatal("a missing key set file built")
	}
}

// TestPublicEndpointsStayOpen proves the citizen check page and its
// form need no session (ADR-036 decision 2).
func TestPublicEndpointsStayOpen(t *testing.T) {
	cfg := base(t)
	cfg.Auth.LoginURL = "https://verifier-waltid.example/auth/"
	a, err := Build(cfg, Deps{Log: quiet(), Policy: fakePolicy{}, SessionKeys: staff(t).Keys(), Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	if rec := serve(a, http.MethodGet, a.Portal.PublicPrefix()+"/", ""); rec.Code != http.StatusOK {
		t.Fatalf("citizen page: status %d", rec.Code)
	}
	form := url.Values{"presentation": {`{"@context":["x"],"issuer":"did:web:a"}`}}
	req := httptest.NewRequest(http.MethodPost, a.Portal.PublicPrefix()+"/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Verification summary") {
		t.Fatalf("citizen check: status %d body %s", rec.Code, rec.Body)
	}
	if rec := serve(a, http.MethodGet, "/static/vca.css", ""); rec.Code != http.StatusOK {
		t.Fatalf("assets: status %d", rec.Code)
	}
}

func TestPurgeJob(t *testing.T) {
	cfg := base(t)
	cfg.PurgeInterval = time.Millisecond
	a, err := Build(cfg, Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	stale := &resultsv1.VerificationResult{
		Id: "stale", RawRef: "raw", EvaluatedAt: timestamppb.New(time.Now().Add(-2000 * time.Hour)),
	}
	if _, serr := a.Store.Put(context.Background(), stale); serr != nil {
		t.Fatal(serr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	a.Purge(ctx, nil)
	if _, serr := a.Store.Get(context.Background(), "stale"); serr == nil {
		t.Fatal("want the stale result purged")
	}

	off, err := Build(base(t), Deps{Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	off.PurgeInterval = 0
	off.Purge(context.Background(), quiet())
}

func TestBuildWithDefaultLogger(t *testing.T) {
	if _, err := Build(base(t), Deps{}); err != nil {
		t.Fatal(err)
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

// TestAppFailsOnBadThemeFile proves the service stops at start when the
// theme file fails a kit pairing, and that the error names the pairing.
func TestAppFailsOnBadThemeFile(t *testing.T) {
	path := uikittest.LowContrastFile(t)
	cfg := base(t)
	cfg.ThemeFile = path
	_, err := Build(cfg, Deps{Log: quiet()})
	uikittest.AssertBadThemeError(t, err, path)
}
