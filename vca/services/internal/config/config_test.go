// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

type settings struct {
	Listen  string        `env:"LISTEN" default:":8080"`
	BaseURL string        `env:"BASE_URL" required:"true"`
	Secret  string        `env:"SECRET" secret:"true"`
	Debug   bool          `env:"DEBUG" default:"false"`
	Count   int           `env:"COUNT" default:"3"`
	Big     int64         `env:"BIG"`
	TTL     time.Duration `env:"TTL" default:"24h"`
	Methods []string      `env:"METHODS" default:"a, b"`
	Ignored string
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaultsAndValues(t *testing.T) {
	var s struct {
		Listen  string        `env:"LISTEN" default:":8080"`
		BaseURL string        `env:"BASE_URL" required:"true"`
		Debug   bool          `env:"DEBUG"`
		Count   int           `env:"COUNT" default:"3"`
		Big     int64         `env:"BIG"`
		TTL     time.Duration `env:"TTL" default:"24h"`
		Methods []string      `env:"METHODS" default:"a, b"`
		Empty   []string      `env:"EMPTY"`
	}
	err := Load("X_", &s, env(map[string]string{"X_BASE_URL": " https://e ", "X_DEBUG": "true", "X_BIG": "42", "X_METHODS": "c,,d"}))
	if err != nil {
		t.Fatal(err)
	}
	if s.Listen != ":8080" || s.BaseURL != "https://e" || !s.Debug || s.Count != 3 || s.Big != 42 || s.TTL != 24*time.Hour {
		t.Fatalf("%+v", s)
	}
	if strings.Join(s.Methods, "|") != "c|d" || s.Empty != nil {
		t.Fatalf("%+v", s)
	}
	var d struct {
		Methods []string      `env:"METHODS" default:"a, b"`
		TTL     time.Duration `env:"TTL"`
		Count   int           `env:"COUNT"`
		Flag    bool          `env:"FLAG"`
	}
	if err := Load("X_", &d, env(nil)); err != nil || strings.Join(d.Methods, "|") != "a|b" || d.TTL != 0 || d.Count != 0 || d.Flag {
		t.Fatalf("defaults: %+v %v", d, err)
	}
}

func TestLoadReportsEveryProblem(t *testing.T) {
	var s struct {
		BaseURL string        `env:"BASE_URL" required:"true"`
		Debug   bool          `env:"DEBUG"`
		Count   int           `env:"COUNT"`
		TTL     time.Duration `env:"TTL"`
	}
	err := Load("X_", &s, env(map[string]string{"X_DEBUG": "maybe", "X_COUNT": "many", "X_TTL": "soon"}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"X_BASE_URL is required", "X_DEBUG must be true or false", "X_COUNT must be a whole number", "X_TTL must be a duration"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q lacks %q", err, want)
		}
	}
}

func TestLoadRejectsBadStructs(t *testing.T) {
	var notStruct int
	if err := Load("X_", &notStruct, env(nil)); err == nil {
		t.Fatal("non struct")
	}
	if err := Load("X_", nil, env(nil)); err == nil {
		t.Fatal("nil")
	}
	var s settings
	if err := Load("X_", s, env(nil)); err == nil {
		t.Fatal("value, not pointer")
	}
	var unexported struct {
		hidden string `env:"HIDDEN"`
	}
	if err := Load("X_", &unexported, env(nil)); err == nil || !strings.Contains(err.Error(), "exported") {
		t.Fatalf("unexported: %v", err)
	}
	var emptyTag struct {
		Field string `env:""`
	}
	if err := Load("X_", &emptyTag, env(nil)); err == nil {
		t.Fatal("empty tag")
	}
	var badType struct {
		Field float64 `env:"FIELD"`
	}
	if err := Load("X_", &badType, env(nil)); err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("bad type: %v", err)
	}
	var badSlice struct {
		Field []int `env:"FIELD"`
	}
	if err := Load("X_", &badSlice, env(nil)); err == nil {
		t.Fatal("bad slice")
	}
}

func TestDescribeAndRedact(t *testing.T) {
	var s struct {
		Listen  string        `env:"LISTEN" default:":8080"`
		Secret  string        `env:"SECRET" secret:"true" required:"true"`
		TTL     time.Duration `env:"TTL" default:"1h"`
		Methods []string      `env:"METHODS"`
		Skip    string
	}
	vars, err := Describe("X_", &s)
	if err != nil || len(vars) != 4 {
		t.Fatalf("%v %v", vars, err)
	}
	if vars[0] != (Variable{Name: "X_LISTEN", Default: ":8080"}) || vars[1] != (Variable{Name: "X_SECRET", Secret: true, Required: true}) {
		t.Fatalf("%+v", vars)
	}
	if gotErr := Load("X_", &s, env(map[string]string{"X_SECRET": "hush", "X_METHODS": "a,b"})); gotErr != nil {
		t.Fatal(err)
	}
	got, err := Redact("X_", &s)
	if err != nil {
		t.Fatal(err)
	}
	if got["X_SECRET"] != "[redacted]" || got["X_LISTEN"] != ":8080" || got["X_TTL"] != "1h0m0s" || got["X_METHODS"] != "a,b" {
		t.Fatalf("%v", got)
	}
	if _, err := Describe("X_", 1); err == nil {
		t.Fatal("describe bad")
	}
	if _, err := Redact("X_", 1); err == nil {
		t.Fatal("redact bad")
	}
}
