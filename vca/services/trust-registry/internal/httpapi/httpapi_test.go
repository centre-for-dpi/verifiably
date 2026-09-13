// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

type source struct{ snap *publish.Snapshot }

func (s source) Snapshot() *publish.Snapshot { return s.snap }
func (s source) JWKSJSON() []byte            { return []byte(`{"keys":[]}`) }

func server(t *testing.T) *httptest.Server {
	t.Helper()
	snap, err := publish.NewSnapshot(
		publish.Publication{Method: "etsi", Files: map[string]publish.File{
			"/trust-list/etsi.json": {ContentType: "application/json", Body: []byte(`{"entities":[]}`)},
			"/trust-list/etsi.jws":  {ContentType: "application/jose", Body: []byte("a.b.c")},
		}},
		publish.Publication{Method: "dedi", Files: map[string]publish.File{
			"/.well-known/dedi.index.json": {ContentType: "application/json", Body: []byte(`{"document":{}}`)},
			"/dedi/dedi.issuers.json":      {ContentType: "application/json", Body: []byte(`{"records":[]}`)},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	New(source{snap: snap}, 5*time.Minute).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, method, path string, headers map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestServeFiles(t *testing.T) {
	srv := server(t)
	cases := map[string]string{
		"/trust-list/etsi.json":         "application/json",
		"/trust-list/etsi.jws":          "application/jose",
		"/.well-known/jwks.json":        "application/json",
		"/.well-known/dedi.index.json":  "application/json",
		"/dedi/dedi.issuers.json":       "application/json",
		"/trust/etsi/list.json":         "application/jose",
		"/trust/dedi/dedi.issuers.json": "application/json",
	}
	for path, ct := range cases {
		resp := get(t, srv, http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != ct {
			t.Errorf("%s: %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if resp.Header.Get("ETag") == "" || resp.Header.Get("Cache-Control") != "public, max-age=300" {
			t.Errorf("%s: headers %v", path, resp.Header)
		}
	}
	for _, path := range []string{"/trust-list/nope.json", "/dedi/other.json", "/.well-known/x", "/trust/other"} {
		if resp := get(t, srv, http.MethodGet, path, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
}

func TestConditionalAndHead(t *testing.T) {
	srv := server(t)
	first := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", nil)
	etag := first.Header.Get("ETag")
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", map[string]string{"If-None-Match": etag}); resp.StatusCode != http.StatusNotModified || resp.Header.Get("ETag") != etag {
		t.Fatalf("if-none-match: %d", resp.StatusCode)
	}
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", map[string]string{"If-None-Match": `"other", W/` + etag}); resp.StatusCode != http.StatusNotModified {
		t.Fatalf("weak match: %d", resp.StatusCode)
	}
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", map[string]string{"If-None-Match": "*"}); resp.StatusCode != http.StatusNotModified {
		t.Fatalf("star: %d", resp.StatusCode)
	}
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", map[string]string{"If-None-Match": `"stale"`}); resp.StatusCode != http.StatusOK {
		t.Fatalf("no match: %d", resp.StatusCode)
	}
	head := get(t, srv, http.MethodHead, "/trust-list/etsi.jws", nil)
	if head.StatusCode != http.StatusOK || head.Header.Get("Content-Length") != "5" {
		t.Fatalf("head: %d %s", head.StatusCode, head.Header.Get("Content-Length"))
	}
	if resp := get(t, srv, http.MethodPost, "/trust-list/etsi.jws", nil); resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("post: %d", resp.StatusCode)
	}
}

func TestNothingPublished(t *testing.T) {
	mux := http.NewServeMux()
	New(source{}, time.Minute).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.json", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("nil snapshot: %d", resp.StatusCode)
	}
	if resp := get(t, srv, http.MethodGet, "/.well-known/jwks.json", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks: %d", resp.StatusCode)
	}
}
