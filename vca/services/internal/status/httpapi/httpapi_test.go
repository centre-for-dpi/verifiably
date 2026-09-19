// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
)

// fakeSource serves one list with two media types.
type fakeSource struct {
	types  []string
	signed lists.Signed
	err    error
}

func (f fakeSource) Signed(_ context.Context, id string) (lists.Record, lists.Signed, error) {
	if f.err != nil {
		return lists.Record{}, lists.Signed{}, f.err
	}
	if id != f.signed.ListID {
		return lists.Record{}, lists.Signed{}, lists.ErrNotFound
	}
	return lists.Record{ID: id}, f.signed, nil
}

func (f fakeSource) MediaTypes() []string { return f.types }
func (f fakeSource) JWKS() []byte         { return []byte(`{"keys":[]}`) }

func newSource() fakeSource {
	jwt := []byte("header.payload.signature")
	cwt := []byte{0xd2, 0x84, 0x41, 0xa0}
	return fakeSource{
		types: []string{"application/statuslist+jwt", "application/statuslist+cwt"},
		signed: lists.Signed{
			ListID: "abc",
			Artifacts: []lists.Artifact{
				{MediaType: "application/statuslist+jwt", Body: jwt, ETag: lists.ETagOf(jwt)},
				{MediaType: "application/statuslist+cwt", Body: cwt, ETag: lists.ETagOf(cwt)},
			},
		},
	}
}

func newServer(src Source, maxAge time.Duration) *httptest.Server {
	mux := http.NewServeMux()
	New(src, maxAge).Register(mux)
	return httptest.NewServer(mux)
}

func get(t *testing.T, url, accept, inm string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if inm != "" {
		req.Header.Set("If-None-Match", inm)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestServeListDefaultAndAccept(t *testing.T) {
	src := newSource()
	srv := newServer(src, time.Minute)
	defer srv.Close()
	url := srv.URL + ListPrefix + "abc"

	resp := get(t, url, "", "")
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("resp.Body.Close: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/statuslist+jwt" {
		t.Fatalf("content type = %s", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "public, max-age=60" {
		t.Fatalf("cache control = %s", got)
	}
	etag := resp.Header.Get("ETag")
	if etag != src.signed.Artifacts[0].ETag {
		t.Fatalf("etag = %s", etag)
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(src.signed.Artifacts[0].Body)) {
		t.Fatalf("content length = %s", got)
	}

	cwt := get(t, url, "application/statuslist+cwt", "")
	defer func() {
		if err := cwt.Body.Close(); err != nil {
			t.Errorf("cwt.Body.Close: %v", err)
		}
	}()
	if cwt.Header.Get("Content-Type") != "application/statuslist+cwt" {
		t.Fatalf("cwt content type = %s", cwt.Header.Get("Content-Type"))
	}

	notModified := get(t, url, "", etag)
	defer func() {
		if err := notModified.Body.Close(); err != nil {
			t.Errorf("notModified.Body.Close: %v", err)
		}
	}()
	if notModified.StatusCode != http.StatusNotModified {
		t.Fatalf("status = %d", notModified.StatusCode)
	}

	star := get(t, url, "", "*")
	defer func() {
		if err := star.Body.Close(); err != nil {
			t.Errorf("star.Body.Close: %v", err)
		}
	}()
	if star.StatusCode != http.StatusNotModified {
		t.Fatal("If-None-Match: * must match")
	}

	weak := get(t, url, "", `W/`+etag+`, "other"`)
	defer func() {
		if err := weak.Body.Close(); err != nil {
			t.Errorf("weak.Body.Close: %v", err)
		}
	}()
	if weak.StatusCode != http.StatusNotModified {
		t.Fatal("weak tag must match")
	}
}

func TestServeListErrors(t *testing.T) {
	srv := newServer(newSource(), 0)
	defer srv.Close()
	missing := get(t, srv.URL+ListPrefix+"none", "", "")
	defer func() {
		if err := missing.Body.Close(); err != nil {
			t.Errorf("missing.Body.Close: %v", err)
		}
	}()
	if missing.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", missing.StatusCode)
	}
	bad := get(t, srv.URL+ListPrefix+"abc", "text/plain", "")
	defer func() {
		if err := bad.Body.Close(); err != nil {
			t.Errorf("bad.Body.Close: %v", err)
		}
	}()
	if bad.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("status = %d", bad.StatusCode)
	}
	// The source offers a media type that has no artifact.
	src := newSource()
	src.types = append(src.types, "application/other")
	other := newServer(src, 0)
	defer other.Close()
	resp := get(t, other.URL+ListPrefix+"abc", "application/other", "")
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("resp.Body.Close: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusNotAcceptable {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	broken := newServer(fakeSource{types: []string{"a/b"}, err: errors.New("store down")}, 0)
	defer broken.Close()
	down := get(t, broken.URL+ListPrefix+"abc", "", "")
	defer func() {
		if err := down.Body.Close(); err != nil {
			t.Errorf("down.Body.Close: %v", err)
		}
	}()
	if down.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", down.StatusCode)
	}
}

func TestServeJWKS(t *testing.T) {
	srv := newServer(newSource(), 0)
	defer srv.Close()
	resp := get(t, srv.URL+JWKSPath, "", "")
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("resp.Body.Close: %v", err)
		}
	}()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("status %d type %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("default max age = %s", resp.Header.Get("Cache-Control"))
	}
	again := get(t, srv.URL+JWKSPath, "", resp.Header.Get("ETag"))
	defer func() {
		if err := again.Body.Close(); err != nil {
			t.Errorf("again.Body.Close: %v", err)
		}
	}()
	if again.StatusCode != http.StatusNotModified {
		t.Fatal("jwks etag")
	}
}

func TestHeadSendsNoBody(t *testing.T) {
	src := newSource()
	h := New(src, time.Minute)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodHead, ListPrefix+"abc", nil)
	req.SetPathValue("listID", "abc")
	h.serveList(rec, req)
	if rec.Body.Len() != 0 || rec.Code != http.StatusOK {
		t.Fatalf("head: %d bytes, status %d", rec.Body.Len(), rec.Code)
	}
}

func TestNegotiate(t *testing.T) {
	offers := []string{"application/statuslist+jwt", "application/statuslist+cwt"}
	cases := []struct {
		accept string
		want   string
		fail   bool
	}{
		{"", "application/statuslist+jwt", false},
		{"  ", "application/statuslist+jwt", false},
		{"*/*", "application/statuslist+jwt", false},
		{"application/*", "application/statuslist+jwt", false},
		{"application/statuslist+cwt", "application/statuslist+cwt", false},
		{"APPLICATION/STATUSLIST+CWT", "application/statuslist+cwt", false},
		{"application/statuslist+jwt;q=0.2, application/statuslist+cwt;q=0.9", "application/statuslist+cwt", false},
		{"application/statuslist+cwt;q=0, application/statuslist+jwt", "application/statuslist+jwt", false},
		{"application/statuslist+cwt;q=bad", "application/statuslist+cwt", false},
		{"application/statuslist+cwt;q=7", "application/statuslist+cwt", false},
		{"application/statuslist+cwt;charset=utf-8", "application/statuslist+cwt", false},
		{" , application/statuslist+cwt", "application/statuslist+cwt", false},
		{"text/plain", "", true},
		{"text/*", "", true},
	}
	for _, tc := range cases {
		got, err := Negotiate(tc.accept, offers)
		if tc.fail {
			if err == nil {
				t.Errorf("%q: expected an error", tc.accept)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v", tc.accept, got, err)
		}
	}
	if _, err := Negotiate("*/*", nil); err == nil {
		t.Fatal("no offer must fail")
	}
}
