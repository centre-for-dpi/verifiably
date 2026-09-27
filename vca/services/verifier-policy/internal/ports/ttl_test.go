// SPDX-License-Identifier: Apache-2.0

package ports

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// statusToken returns an IETF Token Status List token with a ttl claim,
// or with none for a zero ttl.
// The cache reads the payload only, so the signature is a placeholder.
func statusToken(t *testing.T, ttl int) []byte {
	t.Helper()
	claims := map[string]any{
		"sub": "https://status.example.org/lists/1", "iat": 1_780_000_000,
		"status_list": map[string]any{"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
	}
	if ttl != 0 {
		claims["ttl"] = ttl
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return []byte(enc.EncodeToString([]byte(`{"alg":"ES256","typ":"statuslist+jwt"}`)) + "." +
		enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("signature")))
}

// counting returns a fetcher that answers body and counts its calls.
func counting(body []byte, calls *int) func(context.Context, string) ([]byte, error) {
	return func(context.Context, string) ([]byte, error) {
		*calls++
		return body, nil
	}
}

// TestCacheHonoursTheTtlOfAStatusListToken: a status list token names
// how long a verifier may keep it. The cache keeps the token for the
// shorter of that ttl and its own.
func TestCacheHonoursTheTtlOfAStatusListToken(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		ttl        int
		kept, gone time.Duration
	}{
		"token shorter":  {ttl: 60, kept: 59 * time.Second, gone: 61 * time.Second},
		"cache shorter":  {ttl: 900, kept: 4 * time.Minute, gone: 5*time.Minute + time.Second},
		"no ttl in list": {ttl: 0, kept: 4 * time.Minute, gone: 5*time.Minute + time.Second},
	} {
		now := time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)
		start := now
		cache := NewCache(5*time.Minute, 8, func() time.Time { return now })
		calls := 0
		fetch := cache.Wrap(counting(statusToken(t, c.ttl), &calls))
		for _, at := range []time.Duration{0, c.kept} {
			now = start.Add(at)
			if _, err := fetch(ctx, "https://status.example.org/lists/1"); err != nil {
				t.Fatal(err)
			}
		}
		if calls != 1 {
			t.Fatalf("%s: %d reads before the ttl ran out, want 1", name, calls)
		}
		now = start.Add(c.gone)
		if _, err := fetch(ctx, "https://status.example.org/lists/1"); err != nil {
			t.Fatal(err)
		}
		if calls != 2 {
			t.Fatalf("%s: %d reads after the ttl ran out, want 2", name, calls)
		}
	}
}

// TestCacheStoreReplacesTheOnlineCopy: a sync hands the fresh list to
// the cache, so the next check reads it without waiting for the ttl.
func TestCacheStoreReplacesTheOnlineCopy(t *testing.T) {
	ctx := context.Background()
	cache := NewCache(5*time.Minute, 8, nil)
	calls := 0
	fetch := cache.Wrap(counting([]byte("old list"), &calls))
	if _, err := fetch(ctx, "https://status.example.org/lists/1"); err != nil {
		t.Fatal(err)
	}
	cache.Store("https://status.example.org/lists/1", []byte("new list"))
	got, err := fetch(ctx, "https://status.example.org/lists/1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new list" || calls != 1 {
		t.Fatalf("read %q after %d fetches, want the stored list and no new fetch", got, calls)
	}
}

// TestListTTLReadsOnlyAStatusListToken: the ttl of another JWT, a token
// that does not parse, and a plain document leave the cache ttl alone.
func TestListTTLReadsOnlyAStatusListToken(t *testing.T) {
	enc := base64.RawURLEncoding
	other := enc.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." + enc.EncodeToString([]byte(`{"ttl":5}`)) + ".c2ln"
	for name, body := range map[string]string{
		"another JWT":   other,
		"broken token":  "a.b.c",
		"plain doc":     `{"ttl":5}`,
		"negative ttl":  string(statusToken(t, -5)),
		"status list 0": string(statusToken(t, 0)),
	} {
		if got := listTTL([]byte(body)); got != 0 {
			t.Errorf("%s: ttl = %s, want none", name, got)
		}
	}
	if got := listTTL(statusToken(t, 30)); got != 30*time.Second {
		t.Errorf("ttl = %s, want 30s", got)
	}
}
