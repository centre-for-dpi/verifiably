// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func env(pairs map[string]string) func(string) string {
	return func(k string) string { return pairs[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.PageSizeMax != 50 || c.SQLMaxRows != 10000 {
		t.Fatalf("defaults: %+v", c)
	}
	if c.AllowHTTP || c.AllowPrivate || len(c.AllowHosts) != 0 {
		t.Fatalf("the guard must be closed by default: %+v", c)
	}
	if c.HTTPTimeout != 30*time.Second || c.HTTPMaxBytes != 8<<20 || c.CSVMaxBytes != 32<<20 {
		t.Fatalf("limits: %+v", c)
	}
}

func TestLoadValues(t *testing.T) {
	c, err := Load(env(map[string]string{
		Prefix + "LISTEN":         ":9000",
		Prefix + "STORE_FILE":     "/data/sources.json",
		Prefix + "CSV_DIR":        "/data/csv",
		Prefix + "SECRETS_DIR":    "/run/secrets",
		Prefix + "ALLOW_HOSTS":    "API.example.org, , registry.example.net",
		Prefix + "ALLOW_HTTP":     "true",
		Prefix + "ALLOW_PRIVATE":  "true",
		Prefix + "HTTP_MAX_BYTES": "1024",
		Prefix + "CSV_MAX_BYTES":  "2048",
		Prefix + "HTTP_TIMEOUT":   "5s",
		Prefix + "SQL_MAX_ROWS":   "7",
		Prefix + "PAGE_SIZE_MAX":  "11",
		Prefix + "AUTH_JWKS_FILE": "/run/jwks.json",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.AllowHosts, "|") != "api.example.org|registry.example.net" {
		t.Fatalf("hosts: %v", c.AllowHosts)
	}
	if !c.AllowHTTP || !c.AllowPrivate || c.SQLMaxRows != 7 || c.PageSizeMax != 11 {
		t.Fatalf("values: %+v", c)
	}
	if c.HTTPMaxBytes != 1024 || c.CSVMaxBytes != 2048 || c.HTTPTimeout != 5*time.Second {
		t.Fatalf("limits: %+v", c)
	}
	if c.StoreFile != "/data/sources.json" || c.CSVDir != "/data/csv" || c.SecretsDir != "/run/secrets" || c.AuthJWKSFile != "/run/jwks.json" {
		t.Fatalf("paths: %+v", c)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	for name, value := range map[string]string{
		"ALLOW_HTTP":     "yes please",
		"ALLOW_PRIVATE":  "maybe",
		"HTTP_MAX_BYTES": "0",
		"CSV_MAX_BYTES":  "-1",
		"HTTP_TIMEOUT":   "soon",
		"SQL_MAX_ROWS":   "none",
		"PAGE_SIZE_MAX":  "0",
	} {
		if _, err := Load(env(map[string]string{Prefix + name: value})); err == nil {
			t.Fatalf("%s=%q must fail", name, value)
		}
	}
}
