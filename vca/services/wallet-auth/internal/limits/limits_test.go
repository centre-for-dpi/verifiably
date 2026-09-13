// SPDX-License-Identifier: Apache-2.0

package limits_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/limits"
)

func TestMemoryLimiter(t *testing.T) {
	now := time.Now()
	m := limits.NewMemory(2, time.Minute, time.Minute, func() time.Time { return now })
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if ok, _ := m.Allow(ctx, "a"); !ok {
			t.Fatalf("request %d blocked", i)
		}
	}
	if ok, _ := m.Allow(ctx, "a"); ok {
		t.Fatal("third request allowed")
	}
	if ok, _ := m.Allow(ctx, "b"); !ok {
		t.Fatal("other key blocked")
	}
	now = now.Add(2 * time.Minute)
	if ok, _ := m.Allow(ctx, "a"); !ok {
		t.Fatal("new window blocked")
	}
	if limits.NewMemory(0, 0, 0, nil) == nil {
		t.Fatal("defaults")
	}
}

func TestMemoryOTP(t *testing.T) {
	now := time.Now()
	m := limits.NewMemory(1, time.Minute, time.Minute, func() time.Time { return now })
	ctx := context.Background()
	c, err := m.Issue(ctx, "phone")
	if err != nil || len(c) != 6 {
		t.Fatalf("%q %v", c, err)
	}
	if ok, _ := m.Check(ctx, "phone", "000000"+c); ok {
		t.Fatal("wrong code accepted")
	}
	c, _ = m.Issue(ctx, "phone")
	if ok, _ := m.Check(ctx, "phone", c); !ok {
		t.Fatal("code rejected")
	}
	if ok, _ := m.Check(ctx, "phone", c); ok {
		t.Fatal("code reused")
	}
	c, _ = m.Issue(ctx, "phone")
	_, _ = m.Issue(ctx, "old")
	now = now.Add(2 * time.Minute)
	if ok, _ := m.Check(ctx, "phone", c); ok {
		t.Fatal("expired code accepted")
	}
	_, _ = m.Issue(ctx, "new")
	if ok, _ := m.Check(ctx, "old", "x"); ok {
		t.Fatal("swept code accepted")
	}
}

func TestRedisStub(t *testing.T) {
	if _, err := limits.NewRedisLimiter("redis://localhost"); !errors.Is(err, limits.ErrNotConfigured) {
		t.Fatal(err)
	}
	if _, err := limits.NewRedisLimiter(""); !errors.Is(err, limits.ErrNotConfigured) {
		t.Fatal(err)
	}
	var r limits.RedisLimiter
	if _, err := r.Allow(context.Background(), "k"); !errors.Is(err, limits.ErrNotConfigured) {
		t.Fatal(err)
	}
	if _, err := r.Issue(context.Background(), "k"); !errors.Is(err, limits.ErrNotConfigured) {
		t.Fatal(err)
	}
	if _, err := r.Check(context.Background(), "k", "c"); !errors.Is(err, limits.ErrNotConfigured) {
		t.Fatal(err)
	}
}

func TestClientKeyAndMiddleware(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.2")
	if limits.ClientKey(r, false) != "10.0.0.1" || limits.ClientKey(r, true) != "203.0.113.5" {
		t.Fatal("client key")
	}
	r.RemoteAddr = "bare"
	if limits.ClientKey(r, false) != "bare" {
		t.Fatal("bare addr")
	}
	m := limits.NewMemory(1, time.Minute, time.Minute, nil)
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := limits.Middleware(m, false, ok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
		t.Fatal(rec.Code)
	}
	rec = httptest.NewRecorder()
	limits.Middleware(&limits.RedisLimiter{}, false, ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatal(rec.Code)
	}
}
