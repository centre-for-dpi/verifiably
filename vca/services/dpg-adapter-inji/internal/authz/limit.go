// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimit is a token bucket: Burst requests at once, refilled at
// PerSecond.
type RateLimit struct {
	// PerSecond is the refill rate.
	PerSecond float64
	// Burst is the size of the bucket.
	Burst int
}

// Limits are the rate limits of the public routes (ADR-056 decision 5).
type Limits struct {
	// Browser limits authorize and callback per source. A person
	// signs in a few times a minute at most.
	Browser RateLimit
	// Client limits token, metadata and the key set per source. Mimoto
	// trades the codes of every Inji Web holder from one address.
	Client RateLimit
	// Authorize limits authorize over all sources together, so a flood
	// from many addresses still keeps few sign in records.
	Authorize RateLimit
}

// DefaultLimits bound the sign in records to a few megabytes: authorize
// keeps at most Authorize.PerSecond times RequestTTL records of at most
// a few kilobytes each.
var DefaultLimits = Limits{
	Browser:   RateLimit{PerSecond: 1, Burst: 20},
	Client:    RateLimit{PerSecond: 20, Burst: 200},
	Authorize: RateLimit{PerSecond: 20, Burst: 200},
}

// maxSources bounds the number of buckets one limiter keeps.
const maxSources = 10000

// withDefaults fills each unset limit from DefaultLimits.
func (l Limits) withDefaults() Limits {
	pick := func(v, d RateLimit) RateLimit {
		if v.PerSecond <= 0 || v.Burst <= 0 {
			return d
		}
		return v
	}
	return Limits{
		Browser:   pick(l.Browser, DefaultLimits.Browser),
		Client:    pick(l.Client, DefaultLimits.Client),
		Authorize: pick(l.Authorize, DefaultLimits.Authorize),
	}
}

// bucket is the state of one source.
type bucket struct {
	tokens float64
	last   time.Time
}

// limiter keeps one bucket per key.
type limiter struct {
	mu      sync.Mutex
	rate    RateLimit
	buckets map[string]*bucket
}

func newLimiter(rate RateLimit) *limiter {
	return &limiter{rate: rate, buckets: map[string]*bucket{}}
}

// allow takes one token of the bucket of key at now.
func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxSources {
			l.prune(now)
		}
		b = &bucket{tokens: float64(l.rate.Burst), last: now}
		l.buckets[key] = b
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(float64(l.rate.Burst), b.tokens+elapsed*l.rate.PerSecond)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// prune drops the buckets that refilled, so they hold no state. When
// every source is still busy, it drops them all: the limit of all
// sources together still holds.
func (l *limiter) prune(now time.Time) {
	for key, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate.PerSecond >= float64(l.rate.Burst) {
			delete(l.buckets, key)
		}
	}
	if len(l.buckets) >= maxSources {
		clear(l.buckets)
	}
}

// sourceOf returns the address a request came from. The proxy of the
// pair sets X-Forwarded-For and drops the value a client sent, so the
// last entry is the client. Without the header the peer is the source.
func sourceOf(r *http.Request) string {
	if list := r.Header.Get("X-Forwarded-For"); list != "" {
		parts := strings.Split(list, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
			return last
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// guard wraps the routes of the server in their rate limits.
type guard struct {
	browser, client, authorize *limiter
	now                        func() time.Time
}

func newGuard(l Limits, now func() time.Time) *guard {
	l = l.withDefaults()
	return &guard{browser: newLimiter(l.Browser), client: newLimiter(l.Client), authorize: newLimiter(l.Authorize), now: now}
}

// wrap answers 429 when the request is over a limit.
func (g *guard) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now, source := g.now(), sourceOf(r)
		var ok bool
		switch r.URL.Path {
		case AuthorizePath:
			ok = g.browser.allow(source, now) && g.authorize.allow("", now)
		case CallbackPath:
			ok = g.browser.allow(source, now)
		default:
			ok = g.client.allow(source, now)
		}
		if !ok {
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Too many requests. Try again in a moment.", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
