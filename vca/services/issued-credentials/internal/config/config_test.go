// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/retention"
)

// env returns a getenv over a map.
func env(m map[string]string) func(string) string {
	return func(name string) string { return m[name] }
}

func TestDefaults(t *testing.T) {
	c, err := config.Load(env(nil))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != ":8080" || c.PageSizeMax != 50 {
		t.Errorf("config = %+v", c)
	}
	if c.HeadPeriod != 24*time.Hour || c.PruneInterval != 24*time.Hour {
		t.Errorf("periods = %v %v", c.HeadPeriod, c.PruneInterval)
	}
	if c.StatusTimeout != 10*time.Second {
		t.Errorf("status timeout = %v", c.StatusTimeout)
	}
	if c.Retention.Period("any") != 0 {
		t.Error("the default policy keeps every record")
	}
}

func TestLoadReadsEverySetting(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"VCA_ISSUED_LISTEN":         ":9000",
		"VCA_ISSUED_STORE_FILE":     "/data/log.json",
		"VCA_ISSUED_SALT":           "pepper",
		"VCA_ISSUED_SALT_FILE":      "/run/salt",
		"VCA_ISSUED_HEAD_KEY_FILE":  "/run/key.pem",
		"VCA_ISSUED_HEAD_ISSUER":    "issuer.example",
		"VCA_ISSUED_HEAD_PERIOD":    "12h",
		"VCA_ISSUED_RETENTION":      "default=5y,visitor=30d",
		"VCA_ISSUED_PRUNE_INTERVAL": "0",
		"VCA_ISSUED_STATUS_URL":     "http://status:8080/",
		"VCA_ISSUED_STATUS_TIMEOUT": "3s",
		"VCA_ISSUED_PAGE_SIZE_MAX":  "10",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != ":9000" || c.StoreFile != "/data/log.json" || c.Salt != "pepper" {
		t.Errorf("config = %+v", c)
	}
	if c.SaltFile != "/run/salt" || c.HeadKeyFile != "/run/key.pem" || c.HeadIssuer != "issuer.example" {
		t.Errorf("config = %+v", c)
	}
	if c.StatusURL != "http://status:8080" {
		t.Errorf("status url = %q, the trailing slash must go", c.StatusURL)
	}
	if c.HeadPeriod != 12*time.Hour || c.StatusTimeout != 3*time.Second || c.PruneInterval != 0 {
		t.Errorf("periods = %v %v %v", c.HeadPeriod, c.StatusTimeout, c.PruneInterval)
	}
	if c.PageSizeMax != 10 {
		t.Errorf("page size = %d", c.PageSizeMax)
	}
	if c.Retention.Period("visitor") != 30*retention.Day {
		t.Errorf("retention = %v", c.Retention.Period("visitor"))
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := []map[string]string{
		{"VCA_ISSUED_RETENTION": "broken"},
		{"VCA_ISSUED_HEAD_PERIOD": "0"},
		{"VCA_ISSUED_STATUS_TIMEOUT": "soon"},
		{"VCA_ISSUED_PRUNE_INTERVAL": "-1h"},
		{"VCA_ISSUED_PAGE_SIZE_MAX": "0"},
		{"VCA_ISSUED_TIMEOUT": "0s"},
		{"VCA_ISSUED_AUTH_JWKS_TTL": "0s"},
		{"VCA_PEERS": "not a peer"},
	}
	for _, c := range cases {
		if _, err := config.Load(env(c)); err == nil {
			t.Errorf("%v: want an error", c)
		}
	}
}

// TestLoadReadsThePageSettings reads the settings of the issued
// credentials pages: the public URL, the adapter, the staff guard, the
// theme file, and the peers (P3-10).
func TestLoadReadsThePageSettings(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"VCA_ISSUED_PUBLIC_URL":    "https://issuer.example/",
		"VCA_ISSUED_ADAPTER_URL":   "http://dpg-adapter:8080/",
		"VCA_ISSUED_TIMEOUT":       "4s",
		"VCA_ISSUED_AUTH_JWKS_URL": "http://issuer-auth:8081/.well-known/jwks.json",
		"VCA_ISSUED_LOGIN_URL":     "https://issuer.example/auth/",
		"VCA_THEME_FILE":           " /etc/vca/theme.yaml ",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://issuer.example" || c.AdapterURL != "http://dpg-adapter:8080" || c.Timeout != 4*time.Second {
		t.Errorf("config = %+v", c)
	}
	if c.Auth.JWKSURL != "http://issuer-auth:8081/.well-known/jwks.json" || c.Auth.LoginURL != "https://issuer.example/auth/" {
		t.Errorf("auth = %+v", c.Auth)
	}
	if c.ThemeFile != "/etc/vca/theme.yaml" || len(c.Peers) != 0 {
		t.Errorf("theme %q, peers %v", c.ThemeFile, c.Peers)
	}
	d, err := config.Load(env(nil))
	if err != nil || d.Timeout != 10*time.Second || d.AdapterURL != "" {
		t.Errorf("defaults = %+v, %v", d, err)
	}
}
