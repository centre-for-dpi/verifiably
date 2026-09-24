// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.BaseURL != "http://localhost:8080" {
		t.Fatalf("listen %q base %q", c.Listen, c.BaseURL)
	}
	if c.PortalPrefix != "/portal" || c.PageSizeMax != 200 {
		t.Fatalf("portal %q page %d", c.PortalPrefix, c.PageSizeMax)
	}
	if c.HTTPMaxAge != 5*time.Minute || c.BackendTimeout != 10*time.Second {
		t.Fatalf("durations %v %v", c.HTTPMaxAge, c.BackendTimeout)
	}
	if len(c.Metadata.SigningAlgs) != 2 || c.Metadata.CredentialIssuer != c.BaseURL {
		t.Fatalf("metadata %+v", c.Metadata)
	}
	if c.Metadata.AuthorizationServers != nil || c.BackendURL != "" || c.StoreFile != "" {
		t.Fatalf("optional values %+v", c)
	}
}

func TestEveryValue(t *testing.T) {
	c, err := Load(env(map[string]string{
		"VCA_SCHEMA_LISTEN":                ":9000",
		"VCA_SCHEMA_BASE_URL":              "https://registry.example/",
		"VCA_SCHEMA_STORE_FILE":            "/data/schemas.json",
		"VCA_SCHEMA_BACKEND_URL":           "http://adapter:8080/",
		"VCA_SCHEMA_BACKEND_TIMEOUT":       "3s",
		"VCA_SCHEMA_HTTP_MAX_AGE":          "30s",
		"VCA_SCHEMA_PORTAL_PREFIX":         "staff/",
		"VCA_SCHEMA_BUILDER_URL":           "https://builder.example/",
		"VCA_SCHEMA_CREDENTIAL_ISSUER":     "https://issuer.example/",
		"VCA_SCHEMA_CREDENTIAL_ENDPOINT":   "https://issuer.example/credential",
		"VCA_SCHEMA_AUTHORIZATION_SERVERS": "https://as.example, ",
		"VCA_SCHEMA_SIGNING_ALGS":          "ES256",
		"VCA_SCHEMA_PAGE_SIZE_MAX":         "25",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9000" || c.BaseURL != "https://registry.example" || c.StoreFile != "/data/schemas.json" {
		t.Fatalf("config %+v", c)
	}
	if c.BackendURL != "http://adapter:8080" || c.BackendTimeout != 3*time.Second || c.HTTPMaxAge != 30*time.Second {
		t.Fatalf("backend %+v", c)
	}
	if c.PortalPrefix != "/staff" || c.BuilderURL != "https://builder.example/" || c.PageSizeMax != 25 {
		t.Fatalf("portal %+v", c)
	}
	if c.Metadata.CredentialIssuer != "https://issuer.example" || c.Metadata.CredentialEndpoint != "https://issuer.example/credential" {
		t.Fatalf("issuer %+v", c.Metadata)
	}
	if len(c.Metadata.AuthorizationServers) != 1 || c.Metadata.AuthorizationServers[0] != "https://as.example" {
		t.Fatalf("authorization servers %v", c.Metadata.AuthorizationServers)
	}
	if len(c.Metadata.SigningAlgs) != 1 || c.Metadata.SigningAlgs[0] != "ES256" {
		t.Fatalf("algs %v", c.Metadata.SigningAlgs)
	}
}

func TestErrors(t *testing.T) {
	cases := []struct {
		vars map[string]string
		want string
	}{
		{map[string]string{"VCA_SCHEMA_SIGNING_ALGS": " , "}, "SIGNING_ALGS"},
		{map[string]string{"VCA_SCHEMA_HTTP_MAX_AGE": "0s"}, "HTTP_MAX_AGE"},
		{map[string]string{"VCA_SCHEMA_BACKEND_TIMEOUT": "nope"}, "BACKEND_TIMEOUT"},
		{map[string]string{"VCA_SCHEMA_PAGE_SIZE_MAX": "0"}, "PAGE_SIZE_MAX"},
		{map[string]string{"VCA_SCHEMA_PAGE_SIZE_MAX": "x"}, "PAGE_SIZE_MAX"},
	}
	for _, c := range cases {
		_, err := Load(env(c.vars))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%v: %v", c.vars, err)
		}
	}
}

// TestAuthSettings proves the guard variables load under the service
// prefix and a bad TTL is one config error (ADR-036 decision 3).
func TestAuthSettings(t *testing.T) {
	c, err := Load(env(map[string]string{
		"VCA_SCHEMA_AUTH_JWKS_URL": "http://issuer-auth:8081/.well-known/jwks.json",
		"VCA_SCHEMA_LOGIN_URL":     "https://issuer-waltid.example/auth/",
		"VCA_SCHEMA_AUTH_JWKS_TTL": "1m",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Auth.Configured() || c.Auth.LoginURL != "https://issuer-waltid.example/auth/" || c.Auth.JWKSTTL != time.Minute {
		t.Fatalf("auth %+v", c.Auth)
	}
	for name, values := range map[string]map[string]string{
		"a bad duration": {"VCA_SCHEMA_AUTH_JWKS_TTL": "soon"},
		"a zero TTL":     {"VCA_SCHEMA_AUTH_JWKS_TTL": "0s"},
	} {
		if _, err := Load(env(values)); err == nil || !strings.Contains(err.Error(), "VCA_SCHEMA_AUTH_JWKS_TTL") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
