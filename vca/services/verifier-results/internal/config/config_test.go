// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[strings.TrimPrefix(k, Prefix)] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8087" || c.Retention != 720*time.Hour || c.PortalPrefix != "/portal" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadOverride(t *testing.T) {
	c, err := Load(env(map[string]string{"RETENTION": "48h", "RAW_RETENTION": "1h"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Retention != 48*time.Hour || c.RawRetention != time.Hour {
		t.Fatalf("unexpected settings: %+v", c)
	}
}

func TestLoadBadValue(t *testing.T) {
	if _, err := Load(env(map[string]string{"RETENTION": "never"})); err == nil {
		t.Fatal("want an error for a bad duration")
	}
}

func TestCheckProblems(t *testing.T) {
	err := Config{}.Check()
	if err == nil {
		t.Fatal("want problems for an empty configuration")
	}
	for _, want := range []string{"RETENTION", "RAW_RETENTION", "POLICY_TIMEOUT", "MAX_PASTE_BYTES", "PAGE_SIZE_MAX"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("want %s in %v", want, err)
		}
	}
	long := Config{Retention: time.Hour, RawRetention: 2 * time.Hour, PolicyTimeout: time.Second,
		MaxPasteBytes: 1, PageSizeMax: 1}
	if !strings.Contains(long.Check().Error(), "RAW_RETENTION must not be longer") {
		t.Fatal("want a raw retention problem")
	}
	negative := Config{Retention: time.Hour, RawRetention: time.Hour, PurgeInterval: -1,
		PolicyTimeout: time.Second, MaxPasteBytes: 1, PageSizeMax: 1}
	if !strings.Contains(negative.Check().Error(), "PURGE_INTERVAL") {
		t.Fatal("want a purge interval problem")
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
	if values[Prefix+"LISTEN"] != ":8087" {
		t.Fatalf("unexpected values: %v", values)
	}
}
