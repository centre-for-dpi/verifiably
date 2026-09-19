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

// answer holds the part of an HTTP response that the tests read.
type answer struct {
	status int
	header http.Header
}

func get(t *testing.T, srv *httptest.Server, method, path string, headers map[string]string) answer {
	t.Helper()
	req, verr := http.NewRequest(method, srv.URL+path, nil)
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := resp.Body.Close(); cerr != nil {
		t.Errorf("the close failed: %v", cerr)
	}
	return answer{status: resp.StatusCode, header: resp.Header}
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
		if resp.status != http.StatusOK || resp.header.Get("Content-Type") != ct {
			t.Errorf("%s: %d %s", path, resp.status, resp.header.Get("Content-Type"))
		}
		if resp.header.Get("ETag") == "" || resp.header.Get("Cache-Control") != "public, max-age=300" {
			t.Errorf("%s: headers %v", path, resp.header)
		}
	}
	for _, path := range []string{"/trust-list/nope.json", "/dedi/other.json", "/.well-known/x", "/trust/other"} {
		if resp := get(t, srv, http.MethodGet, path, nil); resp.status != http.StatusNotFound {
			t.Errorf("%s: %d", path, resp.status)
		}
	}
}

func TestConditionalAndHead(t *testing.T) {
	srv := server(t)
	first := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", nil)
	etag := first.header.Get("ETag")
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", map[string]string{"If-None-Match": etag}); resp.status != http.StatusNotModified || resp.header.Get("ETag") != etag {
		t.Fatalf("if-none-match: %d", resp.status)
	}
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", map[string]string{"If-None-Match": `"other", W/` + etag}); resp.status != http.StatusNotModified {
		t.Fatalf("weak match: %d", resp.status)
	}
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", map[string]string{"If-None-Match": "*"}); resp.status != http.StatusNotModified {
		t.Fatalf("star: %d", resp.status)
	}
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.jws", map[string]string{"If-None-Match": `"stale"`}); resp.status != http.StatusOK {
		t.Fatalf("no match: %d", resp.status)
	}
	head := get(t, srv, http.MethodHead, "/trust-list/etsi.jws", nil)
	if head.status != http.StatusOK || head.header.Get("Content-Length") != "5" {
		t.Fatalf("head: %d %s", head.status, head.header.Get("Content-Length"))
	}
	if resp := get(t, srv, http.MethodPost, "/trust-list/etsi.jws", nil); resp.status != http.StatusMethodNotAllowed || resp.header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("post: %d", resp.status)
	}
}

func TestNothingPublished(t *testing.T) {
	mux := http.NewServeMux()
	New(source{}, time.Minute).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if resp := get(t, srv, http.MethodGet, "/trust-list/etsi.json", nil); resp.status != http.StatusNotFound {
		t.Fatalf("nil snapshot: %d", resp.status)
	}
	if resp := get(t, srv, http.MethodGet, "/.well-known/jwks.json", nil); resp.status != http.StatusOK {
		t.Fatalf("jwks: %d", resp.status)
	}
}
