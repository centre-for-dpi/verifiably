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
	if c.RunTimeout != 2*time.Hour || c.Timeout != 30*time.Second || c.Auth.JWKSTTL != 10*time.Minute {
		t.Fatalf("timeouts: %+v", c)
	}
	if _, bad := Load(env(map[string]string{"VCA_PEERS": "not a peer"})); bad == nil {
		t.Fatal("a bad peer list must fail")
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
		Prefix + "AUTH_JWKS_URL":  "http://issuer-auth:8081/.well-known/jwks.json",
		Prefix + "LOGIN_URL":      "https://issuer.example/auth/",
		Prefix + "PUBLIC_URL":     "https://issuer.example/",
		Prefix + "SCHEMA_URL":     "http://schema-registry:8080",
		Prefix + "ISSUANCE_URL":   "http://issuance:8080",
		Prefix + "RUN_TIMEOUT":    "30m",
		"VCA_THEME_FILE":          " /etc/vca/theme.yaml ",
		"VCA_PEERS":               "issuer-waltid|https://issuer.example|data-source=http://data-source:8083",
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
	if c.StoreFile != "/data/sources.json" || c.CSVDir != "/data/csv" || c.SecretsDir != "/run/secrets" || c.Auth.JWKSFile != "/run/jwks.json" {
		t.Fatalf("paths: %+v", c)
	}
	// The pages sit behind the staff guard of issuer-auth, read the theme
	// file, and reach the schema registry and the issuance service.
	if c.Auth.JWKSURL != "http://issuer-auth:8081/.well-known/jwks.json" || c.Auth.LoginURL != "https://issuer.example/auth/" {
		t.Fatalf("auth: %+v", c.Auth)
	}
	if c.ThemeFile != "/etc/vca/theme.yaml" || c.PublicURL != "https://issuer.example" || len(c.Peers) != 1 {
		t.Fatalf("pages: %+v", c)
	}
	if c.SchemaURL != "http://schema-registry:8080" || c.IssuanceURL != "http://issuance:8080" || c.RunTimeout != 30*time.Minute {
		t.Fatalf("links: %+v", c)
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
		"RUN_TIMEOUT":    "0s",
		"TIMEOUT":        "-1s",
		"AUTH_JWKS_TTL":  "0s",
	} {
		if _, err := Load(env(map[string]string{Prefix + name: value})); err == nil {
			t.Fatalf("%s=%q must fail", name, value)
		}
	}
}
