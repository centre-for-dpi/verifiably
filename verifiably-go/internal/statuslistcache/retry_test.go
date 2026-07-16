package statuslistcache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// B4: fetchLiveRetry retries a cold endpoint before giving up, so a transient
// first-attempt failure (status list just after issuance / cold hairpin) doesn't
// fail-closed.
func TestFetchLiveRetry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("header.payload.sig"))
	}))
	defer srv.Close()

	f := &Fetcher{}
	raw, err := f.fetchLiveRetry(context.Background(), srv.URL)
	if err != nil || raw != "header.payload.sig" {
		t.Fatalf("retry should succeed by the 3rd attempt: raw=%q err=%v", raw, err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}

	// Persistent failure -> error after the retries are exhausted.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if _, err := f.fetchLiveRetry(context.Background(), bad.URL); err == nil {
		t.Fatal("persistent failure should return an error")
	}

	// A cancelled context aborts the retry backoff.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.fetchLiveRetry(cctx, bad.URL); err == nil {
		t.Fatal("cancelled context should abort the retry")
	}
}
