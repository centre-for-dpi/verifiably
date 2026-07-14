package waltid

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// B4: waitForHTTPReady reports readiness only when the app actually responds —
// so callers wait out the gap between State.Running and issuer-api serving.
func TestWaitForHTTPReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if !waitForHTTPReady(srv.URL, 2*time.Second) {
		t.Fatal("a live server should report ready")
	}
	if waitForHTTPReady("", time.Second) {
		t.Fatal("empty base URL is not ready")
	}
	// Nothing listening -> connection refused each attempt -> times out to false.
	if waitForHTTPReady("http://127.0.0.1:1", 500*time.Millisecond) {
		t.Fatal("unreachable base URL should time out to false")
	}
}
