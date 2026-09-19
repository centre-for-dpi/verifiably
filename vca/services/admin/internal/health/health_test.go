// SPDX-License-Identifier: Apache-2.0

package health_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/health"
)

var at = time.Date(2026, 4, 1, 8, 0, 0, 0, time.UTC)

func clock() func() time.Time { return func() time.Time { return at } }

func TestCheckReportsAReadyService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(health.VersionHeader, "1.2.3")
		mustWrite(t, w, []byte("ready\n"))
	}))
	defer srv.Close()
	p := health.New(nil, time.Second, clock())
	res := p.Check(context.Background(), health.Target{Name: "trust-registry", URL: srv.URL + "/readyz"})
	if !res.Ready || res.Error != "" {
		t.Fatalf("result = %+v", res)
	}
	if res.Version != "1.2.3" || !res.CheckedAt.Equal(at) {
		t.Fatalf("result = %+v", res)
	}
}

func TestCheckReadsTheVersionFromTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("ready version=0.9.1 providers=2"))
	}))
	defer srv.Close()
	res := health.New(nil, 0, nil).Check(context.Background(), health.Target{Name: "issuer-auth", URL: srv.URL})
	if res.Version != "0.9.1" || !res.Ready {
		t.Fatalf("result = %+v", res)
	}
}

func TestCheckReportsANotReadyService(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	res := health.New(nil, time.Second, clock()).Check(context.Background(), health.Target{Name: "s", URL: srv.URL})
	if res.Ready || res.Error == "" {
		t.Fatalf("result = %+v", res)
	}
}

func TestCheckReportsAnUnreachableService(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	res := health.New(nil, time.Second, clock()).Check(context.Background(), health.Target{Name: "s", URL: url})
	if res.Ready || res.Error != "the service could not be reached" {
		t.Fatalf("result = %+v", res)
	}
}

func TestCheckReportsAMissingOrBadURL(t *testing.T) {
	p := health.New(nil, time.Second, clock())
	empty := p.Check(context.Background(), health.Target{Name: "s"})
	if empty.Error != "the service has no readiness URL" {
		t.Errorf("empty = %+v", empty)
	}
	bad := p.Check(context.Background(), health.Target{Name: "s", URL: "http://%zz"})
	if bad.Ready || bad.Error == "" {
		t.Errorf("bad = %+v", bad)
	}
}

func TestCheckReportsATimeout(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		srv.Close()
	}()
	res := health.New(&http.Client{}, time.Millisecond, clock()).Check(context.Background(), health.Target{Name: "s", URL: srv.URL})
	if res.Ready || res.Error != "the service did not answer in time" {
		t.Fatalf("result = %+v", res)
	}
}

func TestCheckAllSortsByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mustWrite(t, w, []byte("ready"))
	}))
	defer srv.Close()
	p := health.New(nil, time.Second, clock())
	got := p.CheckAll(context.Background(), []health.Target{
		{Name: "wallet-auth", URL: srv.URL},
		{Name: "admin", URL: srv.URL},
		{Name: "issuer-auth", URL: ""},
	})
	if len(got) != 3 {
		t.Fatalf("results = %d", len(got))
	}
	if got[0].Name != "admin" || got[1].Name != "issuer-auth" || got[2].Name != "wallet-auth" {
		t.Fatalf("order = %q %q %q", got[0].Name, got[1].Name, got[2].Name)
	}
	if got[1].Ready {
		t.Error("a target without a URL is ready")
	}
}

func TestCheckAllWithNoTargets(t *testing.T) {
	if got := health.New(nil, 0, nil).CheckAll(context.Background(), nil); len(got) != 0 {
		t.Fatalf("results = %v", got)
	}
}

func TestVersionPrefersTheHeader(t *testing.T) {
	if got := health.Version(" 2.0.0 ", "ready version=1.0.0"); got != "2.0.0" {
		t.Errorf("Version = %q", got)
	}
	if got := health.Version("", "ready"); got != "" {
		t.Errorf("Version = %q", got)
	}
}
