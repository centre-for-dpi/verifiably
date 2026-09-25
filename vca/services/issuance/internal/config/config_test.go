// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/issuance/internal/config"
)

// env returns a lookup function for the values.
func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

// base is the smallest configuration the service accepts.
func base(extra map[string]string) map[string]string {
	values := map[string]string{"VCA_ISSUANCE_ADAPTER_URL": "http://dpg-adapter:8080"}
	for name, value := range extra {
		values[name] = value
	}
	return values
}

func TestLoadFillsTheDefaults(t *testing.T) {
	cfg, err := config.Load(env(base(nil)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.AdapterName != "dpg" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.DeliverySender != "log" || cfg.EmailSender != "stub" || cfg.SMSSender != "stub" {
		t.Fatalf("senders = %+v", cfg)
	}
	if cfg.OfferTTL != 24*time.Hour || cfg.Timeout != 30*time.Second {
		t.Fatalf("durations = %+v", cfg)
	}
	if cfg.BatchWorkers != 4 || cfg.PageSizeMax != 50 {
		t.Fatalf("limits = %+v", cfg)
	}
	if cfg.DocumentTitle != "Credential" {
		t.Fatalf("title = %q", cfg.DocumentTitle)
	}
}

func TestLoadReadsEverySetting(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{
		"VCA_ISSUANCE_LISTEN":          ":9000",
		"VCA_ISSUANCE_PUBLIC_URL":      "https://issuance.example.org",
		"VCA_ISSUANCE_ADAPTER_URL":     "http://dpg-adapter:8080",
		"VCA_ISSUANCE_ADAPTER_NAME":    "dpg-adapter-test",
		"VCA_ISSUANCE_SCHEMA_URL":      "http://schema:8080",
		"VCA_ISSUANCE_STATUS_URL":      "http://status:8080",
		"VCA_ISSUANCE_ISSUED_URL":      "http://issued:8080",
		"VCA_ISSUANCE_DATA_SOURCE_URL": "http://data-source:8080",
		"VCA_ISSUANCE_DELIVERY_SENDER": "file",
		"VCA_ISSUANCE_EMAIL_SENDER":    "log",
		"VCA_ISSUANCE_SMS_SENDER":      "file",
		"VCA_ISSUANCE_DELIVERY_DIR":    "/data/out",
		"VCA_ISSUANCE_DOCUMENT_TITLE":  "Farmer Credential",
		"VCA_ISSUANCE_DOCUMENT_ISSUER": "Ministry of Agriculture",
		"VCA_ISSUANCE_DOCUMENT_FOOTER": "Keep this page safe.",
		"VCA_ISSUANCE_STORE_FILE":      "/data/issuance",
		"VCA_ISSUANCE_OFFER_TTL":       "1h",
		"VCA_ISSUANCE_TIMEOUT":         "5s",
		"VCA_ISSUANCE_BATCH_WORKERS":   "2",
		"VCA_ISSUANCE_PAGE_SIZE_MAX":   "10",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":9000" || cfg.DeliveryDir != "/data/out" || cfg.StoreFile != "/data/issuance" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.OfferTTL != time.Hour || cfg.Timeout != 5*time.Second {
		t.Fatalf("durations = %+v", cfg)
	}
	if cfg.BatchWorkers != 2 || cfg.PageSizeMax != 10 {
		t.Fatalf("limits = %+v", cfg)
	}
	if cfg.DocumentIssuer != "Ministry of Agriculture" {
		t.Fatalf("issuer = %q", cfg.DocumentIssuer)
	}
}

func TestLoadNeedsTheAdapterUrl(t *testing.T) {
	_, err := config.Load(env(nil))
	if err == nil || !strings.Contains(err.Error(), "ADAPTER_URL") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRejectsABadValue(t *testing.T) {
	cases := map[string]map[string]string{
		"a bad duration":       {"VCA_ISSUANCE_TIMEOUT": "soon"},
		"a zero timeout":       {"VCA_ISSUANCE_TIMEOUT": "0s"},
		"a zero offer life":    {"VCA_ISSUANCE_OFFER_TTL": "0s"},
		"no batch worker":      {"VCA_ISSUANCE_BATCH_WORKERS": "0"},
		"no page size":         {"VCA_ISSUANCE_PAGE_SIZE_MAX": "0"},
		"an unknown sender":    {"VCA_ISSUANCE_DELIVERY_SENDER": "carrier pigeon"},
		"an unknown mailer":    {"VCA_ISSUANCE_EMAIL_SENDER": "smtp"},
		"an unknown texter":    {"VCA_ISSUANCE_SMS_SENDER": "modem"},
		"a file sender no dir": {"VCA_ISSUANCE_DELIVERY_SENDER": "file"},
		"a file mailer no dir": {"VCA_ISSUANCE_EMAIL_SENDER": "file"},
		"a file texter no dir": {"VCA_ISSUANCE_SMS_SENDER": "file"},
	}
	for name, values := range cases {
		if _, err := config.Load(env(base(values))); err == nil {
			t.Fatalf("the case %q was accepted", name)
		}
	}
}

func TestDescribeListsTheVariables(t *testing.T) {
	vars, err := config.Describe()
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(vars) < 15 {
		t.Fatalf("variables = %d", len(vars))
	}
	for _, v := range vars {
		if !strings.HasPrefix(v.Name, config.Prefix) {
			t.Fatalf("the variable %q has no prefix", v.Name)
		}
	}
}

// TestLoadReadsThePageSettings reads the theme file, the staff guard,
// and the peers of the issuer pages (ADR-044 decision 1).
func TestLoadReadsThePageSettings(t *testing.T) {
	cfg, err := config.Load(env(base(map[string]string{
		"VCA_THEME_FILE":             " /etc/vca/theme.yaml ",
		"VCA_ISSUANCE_AUTH_JWKS_URL": "http://issuer-auth:8081/.well-known/jwks.json",
		"VCA_ISSUANCE_LOGIN_URL":     "https://issuer.example/auth/",
		"VCA_ISSUANCE_PUBLIC_URL":    "https://issuer.example/",
		"VCA_PEERS":                  "issuer-waltid|https://issuer.example|issuance=http://issuance:8080",
	})))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ThemeFile != "/etc/vca/theme.yaml" || cfg.Auth.LoginURL != "https://issuer.example/auth/" ||
		cfg.Auth.JWKSURL == "" || len(cfg.Peers) != 1 || cfg.PublicURL != "https://issuer.example" {
		t.Fatalf("config = %+v", cfg)
	}
	for name, value := range map[string]string{
		"VCA_PEERS":                  "not a peer list",
		"VCA_ISSUANCE_AUTH_JWKS_TTL": "0s",
	} {
		if _, lerr := config.Load(env(base(map[string]string{name: value}))); lerr == nil {
			t.Errorf("%s=%q was accepted", name, value)
		}
	}
	if _, lerr := config.Load(env(base(map[string]string{"VCA_ISSUANCE_AUTH_JWKS_TTL": "soon"}))); lerr == nil {
		t.Error("a bad duration was accepted")
	}
	vars, err := config.Describe()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, v := range vars {
		names = append(names, v.Name)
	}
	if !strings.Contains(strings.Join(names, " "), "VCA_ISSUANCE_AUTH_JWKS_URL") {
		t.Fatalf("Describe lacks the guard: %v", names)
	}
}
