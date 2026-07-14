package handlers

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default sliding-window rate limits for the issue API endpoints.
// Override per-deployment via VERIFIABLY_RATE_KEY_RPM / VERIFIABLY_RATE_IP_RPM.
const (
	defaultKeyRPM = 60 // requests per minute per API key name
	defaultIPRPM  = 20 // requests per minute per source IP
)

// rateEntry tracks request timestamps in a sliding 1-minute window.
type rateEntry struct {
	mu   sync.Mutex
	hits []time.Time
}

// allow returns true and records a hit if fewer than limit requests have been
// seen in the last 60 seconds. Returns false without recording if limit is reached.
func (e *rateEntry) allow(limit int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	j := 0
	for _, t := range e.hits {
		if t.After(cutoff) {
			e.hits[j] = t
			j++
		}
	}
	e.hits = e.hits[:j]
	if len(e.hits) >= limit {
		return false
	}
	e.hits = append(e.hits, now)
	return true
}

// RateLimiter is an in-memory sliding-window throttle for the issue API.
// Two independent limits are enforced: per API-key name (generous, for the
// key owner's quota) and per client IP (tighter, to blunt stuffing from one
// source). For multi-instance deployments, replace the in-process maps with
// a Redis counter while keeping the same VERIFIABLY_RATE_* env-var interface.
type RateLimiter struct {
	keyLimit     int
	ipLimit      int
	trustedNets  []*net.IPNet // from VERIFIABLY_TRUSTED_PROXIES
	mu           sync.Mutex
	byKey        map[string]*rateEntry
	byIP         map[string]*rateEntry
}

// NewRateLimiter builds a RateLimiter reading VERIFIABLY_RATE_KEY_RPM,
// VERIFIABLY_RATE_IP_RPM, and VERIFIABLY_TRUSTED_PROXIES (comma-separated
// CIDR list, e.g. "10.0.0.0/8,172.16.0.0/12"). X-Forwarded-For is only
// trusted when the request arrives from one of the trusted proxy CIDRs; if
// the list is empty any XFF header is honoured (legacy behaviour).
// ctx controls the background cleanup goroutine — pass the server shutdown
// context so the goroutine exits cleanly on SIGTERM/SIGINT.
func NewRateLimiter(ctx context.Context) *RateLimiter {
	rl := &RateLimiter{
		keyLimit: envInt("VERIFIABLY_RATE_KEY_RPM", defaultKeyRPM),
		ipLimit:  envInt("VERIFIABLY_RATE_IP_RPM", defaultIPRPM),
		byKey:    make(map[string]*rateEntry),
		byIP:     make(map[string]*rateEntry),
	}
	if cidrs := os.Getenv("VERIFIABLY_TRUSTED_PROXIES"); cidrs != "" {
		for _, s := range strings.Split(cidrs, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				slog.Warn("rate limiter: ignoring invalid CIDR in VERIFIABLY_TRUSTED_PROXIES",
					"cidr", s, "err", err)
				continue
			}
			rl.trustedNets = append(rl.trustedNets, n)
		}
	}
	go rl.cleanupLoop(ctx)
	return rl
}

// cleanupLoop removes stale map entries every 5 minutes until ctx is done.
func (rl *RateLimiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

// cleanup removes byKey and byIP entries whose last hit is older than the
// 1-minute sliding window, reclaiming memory from rotated IPs/keys.
// Lock ordering: rl.mu and entry.mu are never held simultaneously to prevent
// deadlocks with concurrent Allow calls.
func (rl *RateLimiter) cleanup() {
	cutoff := time.Now().Add(-time.Minute)

	purge := func(m map[string]*rateEntry) {
		// Phase 1: snapshot keys without blocking Allow.
		rl.mu.Lock()
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		rl.mu.Unlock()

		// Phase 2: check each entry independently (no rl.mu held).
		for _, k := range keys {
			rl.mu.Lock()
			e, ok := m[k]
			rl.mu.Unlock()
			if !ok {
				continue
			}
			e.mu.Lock()
			idle := len(e.hits) == 0 || e.hits[len(e.hits)-1].Before(cutoff)
			e.mu.Unlock()
			if idle {
				rl.mu.Lock()
				delete(m, k)
				rl.mu.Unlock()
			}
		}
	}

	purge(rl.byKey)
	purge(rl.byIP)
}

func (rl *RateLimiter) entry(m map[string]*rateEntry, key string) *rateEntry {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := m[key]
	if !ok {
		e = &rateEntry{}
		m[key] = e
	}
	return e
}

// Allow returns true when both the per-key and per-IP limits permit the request.
// keyName is the authenticated API key name; r provides the client address.
func (rl *RateLimiter) Allow(keyName string, r *http.Request) bool {
	if !rl.entry(rl.byKey, keyName).allow(rl.keyLimit) {
		return false
	}
	return rl.entry(rl.byIP, rl.clientIP(r)).allow(rl.ipLimit)
}

// clientIP returns the real client IP.  X-Forwarded-For is trusted only when:
//   - VERIFIABLY_TRUSTED_PROXIES is not set (legacy / dev behaviour), OR
//   - the direct connection's RemoteAddr is within one of the trusted CIDRs.
//
// Without this guard an attacker could bypass the per-IP rate limit by
// spoofing X-Forwarded-For: 1.1.1.1 from any network.
func (rl *RateLimiter) clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteHost
	}

	// Only honour XFF when we have no trusted-proxy list (legacy) or when the
	// direct connection comes from a trusted proxy.
	if len(rl.trustedNets) > 0 {
		remoteIP := net.ParseIP(remoteHost)
		trusted := false
		for _, n := range rl.trustedNets {
			if remoteIP != nil && n.Contains(remoteIP) {
				trusted = true
				break
			}
		}
		if !trusted {
			return remoteHost
		}
	}

	if i := strings.IndexByte(xff, ','); i >= 0 {
		return strings.TrimSpace(xff[:i])
	}
	return strings.TrimSpace(xff)
}

// envInt reads an integer from an environment variable. Returns def when the
// variable is absent, empty, or not a positive integer.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
