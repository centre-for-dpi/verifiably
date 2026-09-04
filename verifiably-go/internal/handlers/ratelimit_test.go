package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEnvInt(t *testing.T) {
	cases := []struct {
		val  string
		want int
	}{
		{"", 7}, {"abc", 7}, {"0", 7}, {"-3", 7}, {"42", 42},
	}
	for _, c := range cases {
		t.Setenv("VERIFIABLY_RATE_TEST_INT", c.val)
		if got := envInt("VERIFIABLY_RATE_TEST_INT", 7); got != c.want {
			t.Errorf("envInt(%q) = %d, want %d", c.val, got, c.want)
		}
	}
}

func TestNewRateLimiter_EnvAndTrustedProxies(t *testing.T) {
	t.Setenv("VERIFIABLY_RATE_KEY_RPM", "5")
	t.Setenv("VERIFIABLY_RATE_IP_RPM", "3")
	t.Setenv("VERIFIABLY_TRUSTED_PROXIES", " 10.0.0.0/8, ,not-a-cidr,192.168.1.0/24 ")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rl := NewRateLimiter(ctx)
	if rl.keyLimit != 5 || rl.ipLimit != 3 {
		t.Errorf("limits = %d/%d, want 5/3", rl.keyLimit, rl.ipLimit)
	}
	if len(rl.trustedNets) != 2 || rl.trustedNets[0].String() != "10.0.0.0/8" || rl.trustedNets[1].String() != "192.168.1.0/24" {
		t.Errorf("trustedNets = %v, want the two valid CIDRs (blank + invalid skipped)", rl.trustedNets)
	}
	if rl.byKey == nil || rl.byIP == nil {
		t.Error("maps must be initialised")
	}
}

func TestNewRateLimiter_Defaults(t *testing.T) {
	t.Setenv("VERIFIABLY_RATE_KEY_RPM", "")
	t.Setenv("VERIFIABLY_RATE_IP_RPM", "")
	t.Setenv("VERIFIABLY_TRUSTED_PROXIES", "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rl := NewRateLimiter(ctx)
	if rl.keyLimit != defaultKeyRPM || rl.ipLimit != defaultIPRPM || len(rl.trustedNets) != 0 {
		t.Errorf("defaults wrong: %+v", rl)
	}
}

func TestRateLimiter_CleanupLoopExitsOnCancel(t *testing.T) {
	rl := &RateLimiter{byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rl.cleanupLoop(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanupLoop did not exit after ctx cancel")
	}
}

func TestRateLimiter_CleanupPurgesIdleEntriesOnly(t *testing.T) {
	rl := &RateLimiter{keyLimit: 10, ipLimit: 10, byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
	stale := time.Now().Add(-2 * time.Minute)
	rl.byKey["idle-old"] = &rateEntry{hits: []time.Time{stale}}
	rl.byKey["idle-empty"] = &rateEntry{}
	rl.byKey["active"] = &rateEntry{hits: []time.Time{time.Now()}}
	rl.byIP["10.1.1.1"] = &rateEntry{hits: []time.Time{stale}}
	rl.byIP["10.2.2.2"] = &rateEntry{hits: []time.Time{time.Now()}}

	rl.cleanup()

	if _, ok := rl.byKey["active"]; !ok {
		t.Error("active key entry must survive cleanup")
	}
	if _, ok := rl.byKey["idle-old"]; ok {
		t.Error("stale key entry must be purged")
	}
	if _, ok := rl.byKey["idle-empty"]; ok {
		t.Error("empty key entry must be purged")
	}
	if _, ok := rl.byIP["10.1.1.1"]; ok {
		t.Error("stale ip entry must be purged")
	}
	if _, ok := rl.byIP["10.2.2.2"]; !ok {
		t.Error("active ip entry must survive cleanup")
	}
}

func TestRateLimiter_CleanupSkipsEntryRemovedBetweenPhases(t *testing.T) {
	// The `!ok` branch: a key present in the phase-1 snapshot but gone by the
	// time phase 2 looks it up. Hold both entries' mutexes so cleanup blocks
	// on the first entry it visits, delete both keys, then release: the second
	// key is then missing from the map when phase 2 reaches it.
	rl := &RateLimiter{byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
	a, b := &rateEntry{}, &rateEntry{}
	rl.byKey["a"], rl.byKey["b"] = a, b
	a.mu.Lock()
	b.mu.Lock()
	done := make(chan struct{})
	go func() { rl.cleanup(); close(done) }()
	time.Sleep(100 * time.Millisecond) // let cleanup snapshot and block on an entry mutex
	rl.mu.Lock()
	delete(rl.byKey, "a")
	delete(rl.byKey, "b")
	rl.mu.Unlock()
	a.mu.Unlock()
	b.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cleanup hung")
	}
	if len(rl.byKey) != 0 {
		t.Errorf("byKey = %v, want empty", rl.byKey)
	}
}

func TestRateLimiter_ClientIP(t *testing.T) {
	mk := func(remote, xff string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	legacy := &RateLimiter{}
	if got := legacy.clientIP(mk("203.0.113.9:1234", "")); got != "203.0.113.9" {
		t.Errorf("no XFF: got %q", got)
	}
	if got := legacy.clientIP(mk("203.0.113.9", "")); got != "203.0.113.9" {
		t.Errorf("RemoteAddr without port: got %q", got)
	}
	if got := legacy.clientIP(mk("203.0.113.9:1234", " 198.51.100.7 , 10.0.0.1")); got != "198.51.100.7" {
		t.Errorf("legacy XFF first hop: got %q", got)
	}
	if got := legacy.clientIP(mk("203.0.113.9:1234", " 198.51.100.8 ")); got != "198.51.100.8" {
		t.Errorf("legacy XFF single: got %q", got)
	}

	t.Setenv("VERIFIABLY_TRUSTED_PROXIES", "10.0.0.0/8")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guarded := NewRateLimiter(ctx)
	if got := guarded.clientIP(mk("10.5.5.5:80", "198.51.100.7, 10.5.5.5")); got != "198.51.100.7" {
		t.Errorf("trusted proxy must honour XFF: got %q", got)
	}
	if got := guarded.clientIP(mk("203.0.113.9:80", "1.1.1.1")); got != "203.0.113.9" {
		t.Errorf("untrusted source must NOT honour XFF: got %q", got)
	}
	if got := guarded.clientIP(mk("garbage", "1.1.1.1")); got != "garbage" {
		t.Errorf("unparseable RemoteAddr with trusted list: got %q", got)
	}
}

func TestRateLimiter_AllowEnforcesBothLimits(t *testing.T) {
	rl := &RateLimiter{keyLimit: 5, ipLimit: 1, byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:1"
	if !rl.Allow("k", r) {
		t.Fatal("first request must pass")
	}
	if rl.Allow("k", r) {
		t.Fatal("second request from same IP must be throttled by ipLimit=1")
	}
	keyed := &RateLimiter{keyLimit: 1, ipLimit: 100, byKey: map[string]*rateEntry{}, byIP: map[string]*rateEntry{}}
	if !keyed.Allow("k", r) || keyed.Allow("k", r) {
		t.Fatal("keyLimit=1 must throttle the second request for the same key")
	}
	if _, hit := keyed.byIP["203.0.113.9"]; !hit {
		t.Error("first allowed request must record the IP entry")
	}
}
