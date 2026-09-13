// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/config"
)

// env returns a lookup function for the values.
func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestLoadFillsTheDefaults(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{
		"VCA_WALTID_ISSUER_URL": "http://issuer-api:7002",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.StandardVersion != "draft13" || cfg.DpgVersion != "0.18.2" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.Timeout != 30*time.Second || cfg.Retries != 2 || cfg.MaxBytes != 8388608 {
		t.Fatalf("call settings = %+v", cfg)
	}
}

func TestLoadReadsEverySetting(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{
		"VCA_WALTID_LISTEN":           ":9000",
		"VCA_WALTID_ISSUER_URL":       "http://issuer-api:7002/",
		"VCA_WALTID_VERIFIER_URL":     "http://verifier-api:7003",
		"VCA_WALTID_WALLET_URL":       "http://wallet-api:7001",
		"VCA_WALTID_STANDARD_VERSION": "draft11",
		"VCA_WALTID_DPG_VERSION":      "0.19.0",
		"VCA_WALTID_ISSUER_DID":       "did:web:issuer.example",
		"VCA_WALTID_ISSUER_KEY":       `{"type":"jwk"}`,
		"VCA_WALTID_VCT_BASE":         "https://vca.example",
		"VCA_WALTID_TIMEOUT":          "5s",
		"VCA_WALTID_RETRIES":          "0",
		"VCA_WALTID_MAX_BYTES":        "1024",
		"VCA_WALTID_STORE_FILE":       "/data/waltid",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":9000" || cfg.StandardVersion != "draft11" || cfg.StoreFile != "/data/waltid" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.Timeout != 5*time.Second || cfg.Retries != 0 || cfg.MaxBytes != 1024 {
		t.Fatalf("call settings = %+v", cfg)
	}
}

func TestLoadNeedsAtLeastOneUrl(t *testing.T) {
	_, err := config.Load(env(nil))
	if err == nil || !strings.Contains(err.Error(), "ISSUER_URL") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRejectsABadValue(t *testing.T) {
	cases := []map[string]string{
		{"VCA_WALTID_ISSUER_URL": "http://x", "VCA_WALTID_TIMEOUT": "soon"},
		{"VCA_WALTID_ISSUER_URL": "http://x", "VCA_WALTID_TIMEOUT": "0s"},
		{"VCA_WALTID_ISSUER_URL": "http://x", "VCA_WALTID_MAX_BYTES": "0"},
		{"VCA_WALTID_ISSUER_URL": "http://x", "VCA_WALTID_RETRIES": "many"},
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
		if v.Name == config.Prefix+"ISSUER_KEY" && !v.Secret {
			t.Fatal("the issuer key is a secret")
		}
	}
}
