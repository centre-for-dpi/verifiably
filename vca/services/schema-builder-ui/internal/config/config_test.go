// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/config"
)

// env returns a getenv function over a map.
func env(values map[string]string) func(string) string {
	return func(name string) string { return values[strings.TrimPrefix(name, config.Prefix)] }
}

func TestDefaults(t *testing.T) {
	c, err := config.Load(env(map[string]string{"REGISTRY_URL": "http://registry:8080/"}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != ":8081" {
		t.Errorf("listen = %q", c.Listen)
	}
	if c.RegistryURL != "http://registry:8080" {
		t.Errorf("registry = %q", c.RegistryURL)
	}
	if c.Prefix != "/builder" {
		t.Errorf("prefix = %q", c.Prefix)
	}
	if c.RegistryTimeout != 10*time.Second || c.CatalogTimeout != 10*time.Second {
		t.Errorf("timeouts = %v %v", c.RegistryTimeout, c.CatalogTimeout)
	}
	if c.PDFCacheSize != 64 {
		t.Errorf("cache size = %d", c.PDFCacheSize)
	}
	if c.CatalogURL != "" {
		t.Errorf("catalog = %q", c.CatalogURL)
	}
}

func TestEveryValue(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"LISTEN":           ":9000",
		"REGISTRY_URL":     "http://registry:8080",
		"REGISTRY_TIMEOUT": "3s",
		"CATALOG_URL":      "http://dpg:8082/",
		"CATALOG_TIMEOUT":  "4s",
		"PORTAL_URL":       "http://registry:8080/portal/",
		"PREFIX":           "schema/builder/",
		"ISSUER":           "https://issuer.test/",
		"PDF_CACHE_SIZE":   "8",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != ":9000" || c.Prefix != "/schema/builder" {
		t.Errorf("config = %+v", c)
	}
	if c.CatalogURL != "http://dpg:8082" || c.CatalogTimeout != 4*time.Second {
		t.Errorf("catalog = %q %v", c.CatalogURL, c.CatalogTimeout)
	}
	if c.RegistryTimeout != 3*time.Second {
		t.Errorf("registry timeout = %v", c.RegistryTimeout)
	}
	if c.Issuer != "https://issuer.test" {
		t.Errorf("issuer = %q", c.Issuer)
	}
	if c.PDFCacheSize != 8 {
		t.Errorf("cache size = %d", c.PDFCacheSize)
	}
}

func TestRejectsBadValues(t *testing.T) {
	cases := []struct {
		name   string
		values map[string]string
	}{
		{"no registry", map[string]string{}},
		{"bad registry timeout", map[string]string{"REGISTRY_URL": "http://r", "REGISTRY_TIMEOUT": "soon"}},
		{"zero registry timeout", map[string]string{"REGISTRY_URL": "http://r", "REGISTRY_TIMEOUT": "0s"}},
		{"bad catalog timeout", map[string]string{"REGISTRY_URL": "http://r", "CATALOG_TIMEOUT": "soon"}},
		{"bad cache size", map[string]string{"REGISTRY_URL": "http://r", "PDF_CACHE_SIZE": "many"}},
		{"zero cache size", map[string]string{"REGISTRY_URL": "http://r", "PDF_CACHE_SIZE": "0"}},
		{"bad key set TTL", map[string]string{"REGISTRY_URL": "http://r", "AUTH_JWKS_TTL": "soon"}},
		{"zero key set TTL", map[string]string{"REGISTRY_URL": "http://r", "AUTH_JWKS_TTL": "0s"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := config.Load(env(c.values)); err == nil {
				t.Error("the load must fail")
			}
		})
	}
}

// TestAuthSettings proves the guard variables load under the service
// prefix (ADR-036 decision 3).
func TestAuthSettings(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"REGISTRY_URL": "http://r", "AUTH_JWKS_URL": "http://issuer-auth:8081/.well-known/jwks.json",
		"LOGIN_URL": "https://issuer-waltid.example/auth/",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Auth.Configured() || c.Auth.LoginURL != "https://issuer-waltid.example/auth/" || c.Auth.JWKSTTL != 10*time.Minute {
		t.Fatalf("auth %+v", c.Auth)
	}
}
