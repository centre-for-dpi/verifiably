// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/config"
)

func env(m map[string]string) config.Lookup {
	return func(k string) string { return m[k] }
}

func TestFromEnvDefaults(t *testing.T) {
	c, err := config.FromEnv(env(map[string]string{"VCA_PUBLIC_URL": "https://issuer.example/"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8081" || c.PublicBaseURL != "https://issuer.example" || c.RedirectURI != "https://issuer.example/auth/callback" {
		t.Fatalf("%+v", c)
	}
	if c.SessionTTL != 15*time.Minute || c.MachineTokenTTL != time.Hour || c.TenantID != "default" || c.CookieName != "vca_issuer_session" || c.InsecureCookie {
		t.Fatalf("%+v", c)
	}
	if c.Seed.HasSeed() || c.Seed.RolesClaimPath != "realm_access.roles" {
		t.Fatalf("seed: %+v", c.Seed)
	}
}

func TestFromEnvValues(t *testing.T) {
	c, err := config.FromEnv(env(map[string]string{
		"VCA_PUBLIC_URL":                    "http://localhost:8081",
		"VCA_ISSUER_AUTH_LISTEN":            ":9000",
		"VCA_OIDC_REDIRECT_URI":             "http://localhost:8081/callback",
		"VCA_ISSUER_AUTH_SESSION_TTL":       "5m",
		"VCA_ISSUER_AUTH_MACHINE_TOKEN_TTL": "30m",
		"VCA_ISSUER_AUTH_INSECURE_COOKIE":   "true",
		"VCA_ISSUER_AUTH_LOGOUT_REDIRECT":   "/bye",
		"VCA_OIDC_DISCOVERY_URL":            "http://idp/.well-known/openid-configuration",
		"VCA_OIDC_CLIENT_ID":                "c",
		"VCA_OIDC_CLIENT_SECRET":            "IDP_SECRET",
		"VCA_ISSUER_AUTH_ADMIN_TOKEN":       "t",
		"VCA_ISSUER_AUTH_ADMIN_JWKS_URL":    "http://admin-waltid-admin:8080/.well-known/jwks.json ",
		"VCA_ISSUER_AUTH_STATE_DIR":         "/tmp/x",
		"VCA_ISSUER_AUTH_TENANT_ID":         "acme",
		"VCA_ISSUER_AUTH_COOKIE_NAME":       "s",
		"VCA_SECRETS_SIGNING_KEY":           "/run/key.pem",
		"VCA_SECRETS_SESSION_KEY":           "0123456789abcdef0123456789abcdef",
		"VCA_OIDC_INTERNAL_AUTHORITY":       "http://idp:8080",
		"VCA_THEME_FILE":                    "/etc/vca/theme.yaml",
		"VCA_ISSUER_AUTH_LANDING_URL":       "https://vca.example/",
		"VCA_OIDC_PUBLIC_URL":               "http://localhost:17010",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Seed.PublicURL != "http://localhost:17010" {
		t.Errorf("the seed lost the public URL: %+v", c.Seed)
	}
	if c.ThemeFile != "/etc/vca/theme.yaml" || c.LandingURL != "https://vca.example" {
		t.Errorf("theme file and landing URL: %+v", c)
	}
	if c.Listen != ":9000" || c.RedirectURI != "http://localhost:8081/callback" || c.SessionTTL != 5*time.Minute || c.MachineTokenTTL != 30*time.Minute || !c.InsecureCookie || c.LogoutRedirect != "/bye" {
		t.Fatalf("%+v", c)
	}
	if !c.Seed.HasSeed() || c.Seed.ClientSecret != "IDP_SECRET" || c.AdminToken != "t" || c.AdminJWKSURL != "http://admin-waltid-admin:8080/.well-known/jwks.json" || c.StateDir != "/tmp/x" || c.TenantID != "acme" || c.CookieName != "s" || c.SigningKeyPath != "/run/key.pem" || c.SessionKey == "" || c.ProviderInternalAuthority != "http://idp:8080" {
		t.Fatalf("%+v", c)
	}
}

func TestFromEnvErrors(t *testing.T) {
	cases := []map[string]string{
		{},
		{"VCA_PUBLIC_URL": "issuer.example"},
		{"VCA_PUBLIC_URL": "ftp://x"},
		{"VCA_PUBLIC_URL": "https://x", "VCA_ISSUER_AUTH_SESSION_TTL": "soon"},
		{"VCA_PUBLIC_URL": "https://x", "VCA_ISSUER_AUTH_SESSION_TTL": "-1m"},
		{"VCA_PUBLIC_URL": "https://x", "VCA_ISSUER_AUTH_MACHINE_TOKEN_TTL": "x"},
		{"VCA_PUBLIC_URL": "https://x", "VCA_ISSUER_AUTH_INSECURE_COOKIE": "maybe"},
		{"VCA_PUBLIC_URL": "https://x", "VCA_ISSUER_AUTH_LOGOUT_REDIRECT": "https://evil"},
	}
	for i, m := range cases {
		if _, err := config.FromEnv(env(m)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
