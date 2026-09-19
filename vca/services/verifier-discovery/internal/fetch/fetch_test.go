// SPDX-License-Identifier: Apache-2.0

package fetch_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/fetch"
)

// public resolves every host to one public address.
func public(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}

func TestGuardAcceptsPublicHTTPS(t *testing.T) {
	g := fetch.Guard{Resolve: public}
	u, err := g.Check(context.Background(), " https://issuer.example/path ")
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "issuer.example" {
		t.Errorf("host = %q", u.Host)
	}
}

func TestGuardRefuses(t *testing.T) {
	cases := map[string]struct {
		guard fetch.Guard
		url   string
	}{
		"not a URL":          {fetch.Guard{Resolve: public}, "https://a b.example"},
		"plain http":         {fetch.Guard{Resolve: public}, "http://issuer.example"},
		"other scheme":       {fetch.Guard{Resolve: public}, "file:///etc/passwd"},
		"user name":          {fetch.Guard{Resolve: public}, "https://user@issuer.example"},
		"no host":            {fetch.Guard{Resolve: public}, "https:///path"},
		"host not allowed":   {fetch.Guard{Resolve: public, AllowedHosts: []string{"other.example"}}, "https://issuer.example"},
		"loopback literal":   {fetch.Guard{Resolve: public}, "https://127.0.0.1/x"},
		"private literal":    {fetch.Guard{Resolve: public}, "https://10.1.2.3/x"},
		"link local":         {fetch.Guard{Resolve: public}, "https://169.254.169.254/x"},
		"unspecified":        {fetch.Guard{Resolve: public}, "https://0.0.0.0/x"},
		"multicast":          {fetch.Guard{Resolve: public}, "https://239.1.1.1/x"},
		"shared space":       {fetch.Guard{Resolve: public}, "https://100.100.1.1/x"},
		"ipv6 loopback":      {fetch.Guard{Resolve: public}, "https://[::1]/x"},
		"mapped loopback":    {fetch.Guard{Resolve: public}, "https://[::ffff:127.0.0.1]/x"},
		"private by name":    {fetch.Guard{Resolve: privateResolve}, "https://internal.example"},
		"resolver fails":     {fetch.Guard{Resolve: failResolve}, "https://issuer.example"},
		"resolves to none":   {fetch.Guard{Resolve: emptyResolve}, "https://issuer.example"},
		"link local ipv6":    {fetch.Guard{Resolve: public}, "https://[fe80::1]/x"},
		"interface local":    {fetch.Guard{Resolve: public}, "https://[ff01::1]/x"},
		"private ipv6 range": {fetch.Guard{Resolve: public}, "https://[fd00::1]/x"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.guard.Check(context.Background(), c.url)
			if err == nil {
				t.Fatal("want an error")
			}
			if !errors.Is(err, fetch.ErrRefused) {
				t.Errorf("error = %v, want ErrRefused", err)
			}
		})
	}
}

func privateResolve(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.168.1.10")}, nil
}

func failResolve(_ context.Context, _ string) ([]netip.Addr, error) {
	return nil, errors.New("no such host")
}

func emptyResolve(_ context.Context, _ string) ([]netip.Addr, error) {
	return nil, nil
}

func TestGuardAllowList(t *testing.T) {
	g := fetch.Guard{Resolve: public, AllowedHosts: []string{"issuer.example", ".gov.example"}}
	for _, host := range []string{"https://issuer.example", "https://ISSUER.example.", "https://ministry.gov.example"} {
		if _, err := g.Check(context.Background(), host); err != nil {
			t.Errorf("Check(%q) = %v", host, err)
		}
	}
	if _, err := g.Check(context.Background(), "https://other.example"); err == nil {
		t.Error("a host outside the list wants an error")
	}
}

func TestGuardDevelopmentSettings(t *testing.T) {
	g := fetch.Guard{AllowPlainHTTP: true, AllowPrivateNetwork: true}
	if _, err := g.Check(context.Background(), "http://127.0.0.1:8080/x"); err != nil {
		t.Errorf("a development deployment reaches loopback, got %v", err)
	}
}

// server returns a test server that answers with body and an entity tag.
func server(t *testing.T, body string, etag string, hits *int) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		if etag != "" {
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)
	return s
}

// devFetcher returns a fetcher that reaches a test server.
func devFetcher(t *testing.T, ttl time.Duration, now func() time.Time) *fetch.Fetcher {
	t.Helper()
	return fetch.New(fetch.Options{
		Guard: fetch.Guard{AllowPlainHTTP: true, AllowPrivateNetwork: true},
		TTL:   ttl, Now: now,
	})
}

func TestGetCachesWithTTL(t *testing.T) {
	hits := 0
	s := server(t, `{"a":1}`, "", &hits)
	clock := time.Unix(1700000000, 0).UTC()
	f := devFetcher(t, time.Minute, func() time.Time { return clock })
	doc, err := f.Get(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(doc.Body) != `{"a":1}` || doc.FromCache {
		t.Errorf("doc = %+v", doc)
	}
	doc, err = f.Get(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.FromCache || hits != 1 {
		t.Errorf("the second read comes from the cache, hits = %d, doc = %+v", hits, doc)
	}
	clock = clock.Add(2 * time.Minute)
	if _, err = f.Get(context.Background(), s.URL); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("a stale document goes to the server, hits = %d", hits)
	}
	if f.Size() != 1 {
		t.Errorf("cache size = %d", f.Size())
	}
	f.Forget(s.URL + "/")
	f.Forget(s.URL)
	if f.Size() != 0 {
		t.Errorf("Forget empties the cache, size = %d", f.Size())
	}
}

func TestGetUsesEntityTag(t *testing.T) {
	hits := 0
	s := server(t, `{"a":1}`, `"v1"`, &hits)
	f := devFetcher(t, 0, nil)
	first, err := f.Get(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if first.ETag != `"v1"` {
		t.Errorf("etag = %q", first.ETag)
	}
	second, err := f.Get(context.Background(), s.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !second.NotModified || string(second.Body) != `{"a":1}` {
		t.Errorf("a 304 answer keeps the cached body, got %+v", second)
	}
	if hits != 2 {
		t.Errorf("hits = %d", hits)
	}
}

func TestGetErrors(t *testing.T) {
	f := devFetcher(t, time.Minute, nil)
	if _, err := f.Get(context.Background(), "https://10.0.0.1/x"); err == nil {
		t.Error("a guarded URL wants an error")
	}
	missing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer missing.Close()
	if _, err := f.Get(context.Background(), missing.URL); err == nil {
		t.Error("a 404 answer wants an error")
	}
	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := closed.URL
	closed.Close()
	if _, err := f.Get(context.Background(), url); err == nil {
		t.Error("a server that is gone wants an error")
	}
}

func TestGetSizeLimit(t *testing.T) {
	hits := 0
	s := server(t, strings.Repeat("a", 100), "", &hits)
	f := fetch.New(fetch.Options{
		Guard:    fetch.Guard{AllowPlainHTTP: true, AllowPrivateNetwork: true},
		MaxBytes: 10,
	})
	if _, err := f.Get(context.Background(), s.URL); err == nil {
		t.Error("a document over the limit wants an error")
	}
}

func TestGetRefusesBadRequest(t *testing.T) {
	f := devFetcher(t, time.Minute, nil)
	if _, err := f.Get(context.Background(), "http://example.test/\x7f"); err == nil {
		t.Error("a URL the request builder refuses wants an error")
	}
}

func TestSystemResolverRefusesUnknownHost(t *testing.T) {
	g := fetch.Guard{}
	_, err := g.Check(context.Background(), "https://host.invalid")
	if err == nil {
		t.Error("an unknown host wants an error")
	}
}
