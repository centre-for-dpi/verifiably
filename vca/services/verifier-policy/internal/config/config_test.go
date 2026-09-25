// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// env returns a getenv function for a map.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[strings.TrimPrefix(k, Prefix)] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8086" || c.PageSizeMax != 50 || c.StatusFailMode != "closed" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadOverride(t *testing.T) {
	c, err := Load(env(map[string]string{"LISTEN": ":9000", "TRUST_URL": "http://trust:8080"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9000" || c.TrustURL != "http://trust:8080" {
		t.Fatalf("unexpected settings: %+v", c)
	}
}

func TestLoadBadValue(t *testing.T) {
	if _, err := Load(env(map[string]string{"CACHE_TTL": "never"})); err == nil {
		t.Fatal("want an error for a bad duration")
	}
}

func TestCheckProblems(t *testing.T) {
	c := Config{}
	err := c.Check()
	if err == nil {
		t.Fatal("want problems for an empty configuration")
	}
	for _, want := range []string{"FETCH_TIMEOUT", "TRUST_TIMEOUT", "CACHE_TTL", "CACHE_ENTRIES",
		"FETCH_MAX_BYTES", "PAGE_SIZE_MAX", "STATUS_FAIL_MODE"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("want %s in %v", want, err)
		}
	}
	bad := Config{Leeway: -1}
	if !strings.Contains(bad.Check().Error(), "LEEWAY") {
		t.Fatal("want a leeway problem")
	}
}

func TestDescribeAndRedact(t *testing.T) {
	vars, err := Describe()
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) == 0 || vars[0].Name != Prefix+"LISTEN" {
		t.Fatalf("unexpected variables: %+v", vars)
	}
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	values, err := c.Redact()
	if err != nil {
		t.Fatal(err)
	}
	if values[Prefix+"LISTEN"] != ":8086" {
		t.Fatalf("unexpected values: %v", values)
	}
}

// TestCacheSettings reads the trust cache policy of ADR-041 and refuses
// a window over seven days and a negative tick.
func TestCacheSettings(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	p := c.CachePolicy()
	if p.TrustRefresh != 6*time.Hour || p.KeysRefresh != 24*time.Hour || p.StatusRefresh != time.Hour ||
		p.AllowOffline || p.Window != 24*time.Hour || !p.MarkStale || !p.RefuseStaleStatus || c.CacheTick != time.Minute {
		t.Fatalf("cache defaults = %+v, tick %v", p, c.CacheTick)
	}
	c, err = Load(env(map[string]string{"CACHE_ALLOW_OFFLINE": "true", "CACHE_OFFLINE_WINDOW": "72h", "CACHE_TICK": "0s"}))
	if err != nil || !c.CachePolicy().AllowOffline || c.CachePolicy().Window != 72*time.Hour || c.CacheTick != 0 {
		t.Fatalf("cache settings = %+v, %v", c, err)
	}
	_, err = Load(env(map[string]string{"CACHE_OFFLINE_WINDOW": "200h", "CACHE_TICK": "-1s"}))
	if err == nil || !strings.Contains(err.Error(), "CACHE_OFFLINE_WINDOW") || !strings.Contains(err.Error(), "CACHE_TICK") {
		t.Fatalf("want the window and the tick refused, got %v", err)
	}
}
