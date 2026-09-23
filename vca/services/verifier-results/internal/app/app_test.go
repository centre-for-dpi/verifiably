// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
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
	"google.golang.org/protobuf/types/known/timestamppb"

	policyv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
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

func TestHandlerServes(t *testing.T) {
	a, err := Build(base(t), Deps{Log: quiet(), Policy: fakePolicy{}, Now: func() time.Time { return testNow }})
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
	page, err := srv.Client().Get(srv.URL + a.Portal.Prefix() + "/")
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
