// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/config"
)

// env returns a lookup function for the values.
func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestLoadFillsTheDefaults(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{"VCA_INJI_CERTIFY_URL": "http://certify:8090"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.DpgVersion != "0.14.0" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.MetadataPath != "/v1/certify/issuance/.well-known/openid-credential-issuer" {
		t.Fatalf("metadata path = %q", cfg.MetadataPath)
	}
	if cfg.Timeout != 30*time.Second || cfg.OfferTTL != 15*time.Minute {
		t.Fatalf("times = %v %v", cfg.Timeout, cfg.OfferTTL)
	}
}

func TestLoadReadsEverySetting(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{
		"VCA_INJI_LISTEN":               ":9000",
		"VCA_INJI_CERTIFY_URL":          "http://certify:8090",
		"VCA_INJI_VERIFY_URL":           "http://verify:8080",
		"VCA_INJI_PUBLIC_URL":           "https://adapter.example",
		"VCA_INJI_AUTHORIZATION_SERVER": "https://esignet.example/v1/esignet",
		"VCA_INJI_OFFER_ISSUER":         "https://certify.example",
		"VCA_INJI_METADATA_PATH":        "/v1/certify/.well-known/openid-credential-issuer",
		"VCA_INJI_VERIFY_CLIENT_ID":     "did:web:verify.example:v1:verify",
		"VCA_INJI_DPG_VERSION":          "0.15.0",
		"VCA_INJI_TIMEOUT":              "10s",
		"VCA_INJI_RETRIES":              "1",
		"VCA_INJI_MAX_BYTES":            "2048",
		"VCA_INJI_STORE_FILE":           "/data/inji",
		"VCA_INJI_OFFER_TTL":            "5m",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.VerifyClientID != "did:web:verify.example:v1:verify" || cfg.OfferTTL != 5*time.Minute {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.MaxBytes != 2048 || cfg.Retries != 1 {
		t.Fatalf("call settings = %+v", cfg)
	}
}

func TestLoadNeedsAtLeastOneUrl(t *testing.T) {
	_, err := config.Load(env(nil))
	if err == nil || !strings.Contains(err.Error(), "CERTIFY_URL") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRejectsABadValue(t *testing.T) {
	cases := []map[string]string{
		{"VCA_INJI_CERTIFY_URL": "http://x", "VCA_INJI_TIMEOUT": "0s"},
		{"VCA_INJI_CERTIFY_URL": "http://x", "VCA_INJI_OFFER_TTL": "0s"},
		{"VCA_INJI_CERTIFY_URL": "http://x", "VCA_INJI_MAX_BYTES": "0"},
		{"VCA_INJI_CERTIFY_URL": "http://x", "VCA_INJI_RETRIES": "many"},
	}
	for i, values := range cases {
		if _, err := config.Load(env(values)); err == nil {
			t.Fatalf("case %d was accepted", i)
		}
	}
}

func TestDescribeListsTheVariables(t *testing.T) {
	vars, err := config.Describe()
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if len(vars) < 10 {
		t.Fatalf("variables = %d", len(vars))
	}
	for _, v := range vars {
		if !strings.HasPrefix(v.Name, config.Prefix) {
			t.Fatalf("variable %q has no prefix", v.Name)
		}
	}
}
