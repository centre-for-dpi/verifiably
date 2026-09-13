// SPDX-License-Identifier: Apache-2.0

// Package limits defines the rate limiter and the one time password
// hooks of the wallet login (ADR-020 decision 6). The in-memory
// implementations serve one replica. The Redis implementation is a stub:
// the build network cannot fetch a Redis client, so it returns
// ErrNotConfigured until the dependency lands.
package limits

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
)

// ErrNotConfigured reports a backend that this build cannot use.
var ErrNotConfigured = errors.New("limits: redis limiter is not available in this build")

// ErrLimited reports a client that made too many requests.
var ErrLimited = errors.New("limits: too many requests")

// Limiter counts requests per key in a window.
type Limiter interface {
	// Allow reports whether key can make one more request now.
	Allow(ctx context.Context, key string) (bool, error)
}

// OTP issues and checks one time passwords per key.
type OTP interface {
	// Issue makes a code for key and returns it for delivery.
	Issue(ctx context.Context, key string) (string, error)
	// Check consumes the code of key and reports whether it matched.
	Check(ctx context.Context, key, code string) (bool, error)
}

// Memory is a fixed window Limiter and OTP in process memory.
type Memory struct {
	limit  int
	window time.Duration
	otpTTL time.Duration
	now    func() time.Time
	mu     sync.Mutex
	counts map[string]window
	codes  map[string]code
}

type window struct {
	start time.Time
	n     int
}

type code struct {
	value string
	exp   time.Time
}

// NewMemory returns a limiter that allows limit requests per window and
// keeps one time passwords for otpTTL.
func NewMemory(limit int, win, otpTTL time.Duration, now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	if limit <= 0 {
		limit = 1
	}
	if win <= 0 {
		win = time.Minute
	}
	if otpTTL <= 0 {
		otpTTL = 5 * time.Minute
	}
	return &Memory{limit: limit, window: win, otpTTL: otpTTL, now: now, counts: map[string]window{}, codes: map[string]code{}}
}

// Allow implements Limiter.
func (m *Memory) Allow(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.now()
	for k, w := range m.counts {
		if t.Sub(w.start) >= m.window {
			delete(m.counts, k)
		}
	}
	w := m.counts[key]
	if t.Sub(w.start) >= m.window {
		w = window{start: t}
	}
	if w.n >= m.limit {
		m.counts[key] = w
		return false, nil
	}
	w.n++
	m.counts[key] = w
	return true, nil
}

// Issue implements OTP. The code has 6 digits.
func (m *Memory) Issue(_ context.Context, key string) (string, error) {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	n := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) % 1000000
	value := fmt.Sprintf("%06d", n)
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.now()
	for k, c := range m.codes {
		if t.After(c.exp) {
			delete(m.codes, k)
		}
	}
	m.codes[key] = code{value: value, exp: t.Add(m.otpTTL)}
	return value, nil
}

// Check implements OTP. A code works once.
func (m *Memory) Check(_ context.Context, key, given string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[key]
	if !ok {
		return false, nil
	}
	delete(m.codes, key)
	if m.now().After(c.exp) {
		return false, nil
	}
	return subtle.ConstantTimeCompare([]byte(c.value), []byte(given)) == 1, nil
}

// RedisLimiter is the Redis backed Limiter and OTP of ADR-020 decision 6.
// This build has no Redis client, because the restricted network cannot
// fetch one. NewRedisLimiter returns ErrNotConfigured. When the client
// lands, the type keeps this shape: INCR with EXPIRE per key for Allow,
// SET with EX and GETDEL for the one time passwords.
type RedisLimiter struct{}

// NewRedisLimiter returns ErrNotConfigured.
func NewRedisLimiter(url string) (*RedisLimiter, error) {
	if url == "" {
		return nil, fmt.Errorf("%w: empty URL", ErrNotConfigured)
	}
	return nil, ErrNotConfigured
}

// Allow implements Limiter. It always returns ErrNotConfigured.
func (*RedisLimiter) Allow(context.Context, string) (bool, error) { return false, ErrNotConfigured }

// Issue implements OTP. It always returns ErrNotConfigured.
func (*RedisLimiter) Issue(context.Context, string) (string, error) { return "", ErrNotConfigured }

// Check implements OTP. It always returns ErrNotConfigured.
func (*RedisLimiter) Check(context.Context, string, string) (bool, error) {
	return false, ErrNotConfigured
}

// ClientKey returns the client address of a request as a limiter key.
// It trusts X-Forwarded-For only when trustProxy is true.
func ClientKey(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	return Host(r.RemoteAddr)
}

// Host returns the host part of a host:port address, or addr itself
// when it has no port.
func Host(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// Middleware rejects requests over the limit with 429.
func Middleware(l Limiter, trustProxy bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, err := l.Allow(r.Context(), ClientKey(r, trustProxy))
		if err != nil {
			oidcflow.WriteError(w, http.StatusServiceUnavailable, "temporarily_unavailable", err.Error())
			return
		}
		if !ok {
			w.Header().Set("Retry-After", "60")
			oidcflow.WriteError(w, http.StatusTooManyRequests, "slow_down", ErrLimited.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}
