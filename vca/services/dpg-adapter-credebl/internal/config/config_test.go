// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/config"
)

// env returns a lookup function for the values.
func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

// required is the smallest set of settings that loads.
func required() map[string]string {
	return map[string]string{
		"VCA_CREDEBL_API_URL":    "https://credebl.example.org",
		"VCA_CREDEBL_EMAIL":      "admin@example.org",
		"VCA_CREDEBL_PASSWORD":   "secret",
		"VCA_CREDEBL_CRYPTO_KEY": "key",
		"VCA_CREDEBL_ORG_ID":     "org-1",
	}
}

func TestLoadFillsTheDefaults(t *testing.T) {
	cfg, err := config.Load(env(required()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != ":8080" || cfg.DpgVersion != "2.x" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.VerifierName != "verifiable-credentials-adapters" {
		t.Fatalf("verifier name = %q", cfg.VerifierName)
	}
	if cfg.Timeout != 30*time.Second || cfg.Retries != 2 {
		t.Fatalf("call settings = %+v", cfg)
	}
}

func TestLoadNamesEveryMissingSetting(t *testing.T) {
	_, err := config.Load(env(nil))
	if err == nil {
		t.Fatal("Load accepted an empty environment")
	}
	for _, name := range []string{"API_URL", "EMAIL", "PASSWORD", "CRYPTO_KEY", "ORG_ID"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("the error %q does not name %s", err, name)
		}
	}
}

func TestLoadReadsEverySetting(t *testing.T) {
	values := required()
	values["VCA_CREDEBL_LISTEN"] = ":9000"
	values["VCA_CREDEBL_ISSUER_ID"] = "issuer-1"
	values["VCA_CREDEBL_VERIFIER_ID"] = "verifier-1"
	values["VCA_CREDEBL_VERIFIER_NAME"] = "vca"
	values["VCA_CREDEBL_PUBLIC_URL"] = "https://credebl.example.org"
	values["VCA_CREDEBL_INTERNAL_URL"] = "http://credebl-agent:8001"
	values["VCA_CREDEBL_DEFAULT_PIN"] = "0000"
	values["VCA_CREDEBL_STORE_FILE"] = "/data/credebl"
	values["VCA_CREDEBL_TIMEOUT"] = "10s"
	values["VCA_CREDEBL_MAX_BYTES"] = "4096"
	cfg, err := config.Load(env(values))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.VerifierID != "verifier-1" || cfg.InternalURL != "http://credebl-agent:8001" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.MaxBytes != 4096 || cfg.Timeout != 10*time.Second {
		t.Fatalf("call settings = %+v", cfg)
	}
}

func TestLoadRejectsABadValue(t *testing.T) {
	for _, change := range []map[string]string{
		{"VCA_CREDEBL_TIMEOUT": "0s"},
		{"VCA_CREDEBL_MAX_BYTES": "0"},
		{"VCA_CREDEBL_RETRIES": "many"},
	} {
		values := required()
		for k, v := range change {
			values[k] = v
		}
		if _, err := config.Load(env(values)); err == nil {
			t.Fatalf("the change %v was accepted", change)
		}
	}
}

func TestDescribeMarksTheSecrets(t *testing.T) {
	vars, err := config.Describe()
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	secrets := map[string]bool{}
	for _, v := range vars {
		if !strings.HasPrefix(v.Name, config.Prefix) {
			t.Fatalf("variable %q has no prefix", v.Name)
		}
		if v.Secret {
			secrets[v.Name] = true
		}
	}
	for _, name := range []string{"PASSWORD", "CRYPTO_KEY", "DEFAULT_PIN"} {
		if !secrets[config.Prefix+name] {
			t.Fatalf("%s must be a secret", name)
		}
	}
}
