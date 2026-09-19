// SPDX-License-Identifier: Apache-2.0

package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"

	trustv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
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

func TestBuildAndServe(t *testing.T) {
	issuer := issuerServer(t)
	trust := &fakeTrust{endpoint: issuer.URL}
	a, err := app.Build(settings(t, nil), app.Deps{Trust: trust, Log: quiet()})
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
