package credebl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// withAuthSrv builds an httptest.Server whose /v1/auth/signin always succeeds
// and whose /test endpoint returns statusSeq[i] on the i-th call (wrapping to
// the last element once exhausted).
func withAuthSrv(statusSeq []int, authCount, fnCount *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/signin" {
			if authCount != nil {
				atomic.AddInt32(authCount, 1)
			}
			// Return a minimal JWT with a far-future exp so the cache accepts it.
			payload, _ := json.Marshal(map[string]any{"exp": int64(9999999999)})
			tok := "h." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]string{"access_token": tok},
			})
			return
		}
		n := int(atomic.AddInt32(fnCount, 1)) - 1
		idx := n
		if idx >= len(statusSeq) {
			idx = len(statusSeq) - 1
		}
		w.WriteHeader(statusSeq[idx])
	}))
}

// newTestAdapter constructs an Adapter pointed at baseURL with dummy credentials.
func newTestAdapter(t *testing.T, baseURL string) *Adapter {
	t.Helper()
	cfg := Config{
		BaseURL:          baseURL,
		Email:            "test@example.com",
		Password:         "test-password",
		CryptoPrivateKey: "test-key",
		DefaultPIN:       "1234",
	}
	a, err := New(cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func callTest(a *Adapter) func(context.Context) error {
	return func(ctx context.Context) error {
		return a.client.DoJSON(ctx, http.MethodGet, "/test", nil, nil, nil)
	}
}

func TestWithAuth_HappyPath(t *testing.T) {
	var authCount, fnCount int32
	srv := withAuthSrv([]int{http.StatusOK}, &authCount, &fnCount)
	defer srv.Close()

	a := newTestAdapter(t, srv.URL)
	if err := a.withAuth(context.Background(), callTest(a)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := atomic.LoadInt32(&authCount); n != 1 {
		t.Errorf("auth calls: got %d, want 1", n)
	}
	if n := atomic.LoadInt32(&fnCount); n != 1 {
		t.Errorf("fn calls: got %d, want 1", n)
	}
}

func TestWithAuth_Retry401ReAuthsAndSucceeds(t *testing.T) {
	// First fn call returns 401 → withAuth clears cache and re-auths → second call succeeds.
	var authCount, fnCount int32
	srv := withAuthSrv([]int{http.StatusUnauthorized, http.StatusOK}, &authCount, &fnCount)
	defer srv.Close()

	a := newTestAdapter(t, srv.URL)
	if err := a.withAuth(context.Background(), callTest(a)); err != nil {
		t.Fatalf("unexpected error after 401 retry: %v", err)
	}
	if n := atomic.LoadInt32(&authCount); n != 2 {
		t.Errorf("auth calls: got %d, want 2 (initial + re-auth on 401)", n)
	}
	if n := atomic.LoadInt32(&fnCount); n != 2 {
		t.Errorf("fn calls: got %d, want 2 (initial 401 + retry)", n)
	}
}

func TestWithAuth_Retry401TwiceFails(t *testing.T) {
	// Both fn calls return 401 → withAuth exhausts retries and returns error.
	var authCount, fnCount int32
	srv := withAuthSrv([]int{http.StatusUnauthorized}, &authCount, &fnCount)
	defer srv.Close()

	a := newTestAdapter(t, srv.URL)
	if err := a.withAuth(context.Background(), callTest(a)); err == nil {
		t.Fatal("expected error when both fn calls return 401")
	}
	if n := atomic.LoadInt32(&fnCount); n != 2 {
		t.Errorf("fn calls: got %d, want 2 (initial + one retry)", n)
	}
}

func TestWithAuth_Retry5xxSucceeds(t *testing.T) {
	// First fn call returns 503 → withAuth retries with same token → second succeeds.
	// No re-auth expected (5xx retries reuse the existing token).
	var authCount, fnCount int32
	srv := withAuthSrv([]int{http.StatusServiceUnavailable, http.StatusOK}, &authCount, &fnCount)
	defer srv.Close()

	a := newTestAdapter(t, srv.URL)
	if err := a.withAuth(context.Background(), callTest(a)); err != nil {
		t.Fatalf("unexpected error after 5xx retry: %v", err)
	}
	if n := atomic.LoadInt32(&authCount); n != 1 {
		t.Errorf("auth calls: got %d, want 1 (no re-auth for 5xx, only for 401)", n)
	}
	if n := atomic.LoadInt32(&fnCount); n != 2 {
		t.Errorf("fn calls: got %d, want 2 (initial 5xx + retry)", n)
	}
}

func TestWithAuth_Retry5xxBothFail(t *testing.T) {
	// Both fn calls return 502 → error propagated after one retry.
	var fnCount int32
	srv := withAuthSrv([]int{http.StatusBadGateway}, nil, &fnCount)
	defer srv.Close()

	a := newTestAdapter(t, srv.URL)
	if err := a.withAuth(context.Background(), callTest(a)); err == nil {
		t.Fatal("expected error when both fn calls return 5xx")
	}
	if n := atomic.LoadInt32(&fnCount); n != 2 {
		t.Errorf("fn calls: got %d, want 2 (initial + one retry)", n)
	}
}
