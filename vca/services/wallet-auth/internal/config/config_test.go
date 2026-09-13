// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/config"
)

func env(m map[string]string) config.Lookup {
	return func(k string) string { return m[k] }
}

func TestFromEnvDefaults(t *testing.T) {
	c, err := config.FromEnv(env(map[string]string{"VCA_PUBLIC_URL": "https://wallet.example/"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8083" || c.RedirectURI != "https://wallet.example/wallet/auth/callback" || c.SessionTTL != 15*time.Minute || c.LoginRate != 30 {
		t.Fatalf("%+v", c)
	}
	if c.GrantType != config.DefaultGrantType || c.CookieName != "vca_wallet_session" || c.Salt != nil || c.GrantKey != nil || c.Seed.HasSeed() {
		t.Fatalf("%+v", c)
	}
}

func TestFromEnvValues(t *testing.T) {
	key := strings.Repeat("k", 32)
	c, err := config.FromEnv(env(map[string]string{
		"VCA_PUBLIC_URL":                     "http://localhost:8083",
		"VCA_WALLET_AUTH_LISTEN":             ":9",
		"VCA_OIDC_REDIRECT_URI":              "http://localhost:8083/cb",
		"VCA_WALLET_AUTH_SESSION_TTL":        "5m",
		"VCA_WALLET_AUTH_INSECURE_COOKIE":    "1",
		"VCA_WALLET_AUTH_LOGIN_RATE":         "5",
		"VCA_WALLET_AUTH_SALT":               hex.EncodeToString([]byte("0123456789abcdef")),
		"VCA_WALLET_AUTH_GRANT_KEY":          base64.StdEncoding.EncodeToString([]byte(key)),
		"VCA_WALLET_AUTH_GRANT_TYPE":         "custom",
		"VCA_WALLET_AUTH_HOLDER_BACKEND_URL": "http://adapter:8090",
		"VCA_REDIS_URL":                      "redis://r",
		"VCA_WALLET_AUTH_ADMIN_TOKEN":        "t",
		"VCA_WALLET_AUTH_STATE_DIR":          "/s",
		"VCA_WALLET_AUTH_COOKIE_NAME":        "c",
		"VCA_WALLET_AUTH_LOGOUT_REDIRECT":    "/bye",
		"VCA_OIDC_INTERNAL_AUTHORITY":        "http://idp:8080",
		"VCA_OIDC_DISCOVERY_URL":             "http://idp/.well-known/openid-configuration",
		"VCA_OIDC_CLIENT_ID":                 "c",
		"VCA_OIDC_CLIENT_SECRET":             "S",
		"VCA_SECRETS_SIGNING_KEY":            "/k.pem",
		"VCA_SECRETS_SESSION_KEY":            "0123456789abcdef0123456789abcdef",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9" || c.RedirectURI != "http://localhost:8083/cb" || c.SessionTTL != 5*time.Minute || !c.InsecureCookie || c.LoginRate != 5 {
		t.Fatalf("%+v", c)
	}
	if string(c.Salt) != "0123456789abcdef" || string(c.GrantKey) != key || c.GrantType != "custom" || c.HolderBackendURL != "http://adapter:8090" || c.RedisURL != "redis://r" {
		t.Fatalf("%+v", c)
	}
	if c.AdminToken != "t" || c.StateDir != "/s" || c.CookieName != "c" || c.LogoutRedirect != "/bye" || c.ProviderInternalAuthority != "http://idp:8080" || !c.Seed.HasSeed() || c.Seed.ClientSecretEnv != "S" {
		t.Fatalf("%+v", c)
	}
	// A raw url safe base64 key and a plain key work too.
	c, err = config.FromEnv(env(map[string]string{"VCA_PUBLIC_URL": "https://w", "VCA_WALLET_AUTH_GRANT_KEY": base64.RawURLEncoding.EncodeToString([]byte(key)), "VCA_WALLET_AUTH_SALT": "plain-salt-value-that-is-long"}))
	if err != nil || string(c.GrantKey) != key || string(c.Salt) != "plain-salt-value-that-is-long" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestFromEnvErrors(t *testing.T) {
	cases := []map[string]string{
		{},
		{"VCA_PUBLIC_URL": "wallet"},
		{"VCA_PUBLIC_URL": "https://w", "VCA_WALLET_AUTH_SESSION_TTL": "x"},
		{"VCA_PUBLIC_URL": "https://w", "VCA_WALLET_AUTH_INSECURE_COOKIE": "x"},
		{"VCA_PUBLIC_URL": "https://w", "VCA_WALLET_AUTH_LOGIN_RATE": "0"},
		{"VCA_PUBLIC_URL": "https://w", "VCA_WALLET_AUTH_SALT": "short"},
		{"VCA_PUBLIC_URL": "https://w", "VCA_WALLET_AUTH_GRANT_KEY": "tooshort"},
		{"VCA_PUBLIC_URL": "https://w", "VCA_WALLET_AUTH_LOGOUT_REDIRECT": "https://evil"},
		{"VCA_PUBLIC_URL": "https://w", "VCA_WALLET_AUTH_HOLDER_BACKEND_URL": "adapter"},
	}
	for i, m := range cases {
		if _, err := config.FromEnv(env(m)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}
