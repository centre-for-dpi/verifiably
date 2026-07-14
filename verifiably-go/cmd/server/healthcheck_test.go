package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// runHealthcheck is the distroless container probe: GET /healthz on the local
// listen port, 2xx -> exit 0, anything else / unreachable -> exit 1.
func TestRunHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	t.Setenv("VERIFIABLY_ADDR", ":"+portOf(t, ok.URL))
	if got := runHealthcheck(); got != 0 {
		t.Fatalf("healthy /healthz: got exit %d, want 0", got)
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	t.Setenv("VERIFIABLY_ADDR", ":"+portOf(t, down.URL))
	if got := runHealthcheck(); got != 1 {
		t.Fatalf("503 /healthz: got exit %d, want 1", got)
	}

	// Nothing listening on this port -> connection refused -> exit 1.
	t.Setenv("VERIFIABLY_ADDR", ":1")
	if got := runHealthcheck(); got != 1 {
		t.Fatalf("unreachable: got exit %d, want 1", got)
	}

	// Empty addr -> defaults to :8080 (nothing listening in the test container).
	t.Setenv("VERIFIABLY_ADDR", "")
	if got := runHealthcheck(); got != 1 {
		t.Fatalf("empty addr: got exit %d, want 1", got)
	}
	// Malformed addr (no host:port) -> port fallback 8080 -> exit 1.
	t.Setenv("VERIFIABLY_ADDR", "no-colon-here")
	if got := runHealthcheck(); got != 1 {
		t.Fatalf("malformed addr: got exit %d, want 1", got)
	}
}

func portOf(t *testing.T, url string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", url, err)
	}
	return port
}
