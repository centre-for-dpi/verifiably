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
	if c.Listen != ":8088" || c.PageSizeMax != 50 || c.CallTimeout != 10*time.Second {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadOverride(t *testing.T) {
	c, err := Load(env(map[string]string{"POLICY_URL": "http://policy:8086", "PAGE_SIZE_MAX": "5"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PolicyURL != "http://policy:8086" || c.PageSizeMax != 5 {
		t.Fatalf("unexpected settings: %+v", c)
	}
}

func TestLoadBadValue(t *testing.T) {
	if _, err := Load(env(map[string]string{"CALL_TIMEOUT": "soon"})); err == nil {
		t.Fatal("want an error for a bad duration")
	}
}

func TestCheckProblems(t *testing.T) {
	err := Config{}.Check()
	if err == nil {
		t.Fatal("want problems for an empty configuration")
	}
	for _, want := range []string{"CALL_TIMEOUT", "PAGE_SIZE_MAX"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("want %s in %v", want, err)
		}
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
	if values[Prefix+"LISTEN"] != ":8088" {
		t.Fatalf("unexpected values: %v", values)
	}
}
