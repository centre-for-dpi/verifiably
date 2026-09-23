// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
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
	if cfg.Listen != ":8080" || cfg.DpgVersion != "latest" {
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

// TestDefaultVersionsMatchTheStackFile binds the versions the capability
// answer reports to the image tags of the stack file, so a bump of one
// without the other fails here (ADR-034 decision 4). CREDEBL publishes
// no version tag, so the tag is the default of CREDEBL_VERSION until a
// digest pins it.
func TestDefaultVersionsMatchTheStackFile(t *testing.T) {
	cfg, err := config.Load(env(required()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tags := stackImageTags(t, "../../../../../deploy/vca/dpg/credebl.yaml")
	versions := cfg.Versions()
	if len(versions) < 3 {
		t.Fatalf("versions = %v, want the platform services and the identity provider", versions)
	}
	for name, version := range versions {
		tag, ok := tags["credebl-"+name]
		if !ok {
			t.Errorf("the stack file runs no service credebl-%s", name)
			continue
		}
		if tag != version {
			t.Errorf("%s: the answer says %s but the stack file runs %s", name, version, tag)
		}
	}
}

// stackImageTags reads the image tag of every service of a compose file.
// A tag of the form ${NAME:-default} resolves to its default.
func stackImageTags(t *testing.T, path string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the path is a test constant
	if err != nil {
		t.Fatalf("read the stack file: %v", err)
	}
	out := map[string]string{}
	service := ""
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(trimmed, ":"):
			service = strings.TrimSuffix(trimmed, ":")
		case strings.HasPrefix(trimmed, "image:") && service != "":
			image := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
			tag := image[strings.LastIndex(image, ":")+1:]
			if strings.HasPrefix(image[strings.Index(image, ":")+1:], "${") {
				tag = image[strings.Index(image, ":")+1:]
			}
			if strings.HasPrefix(tag, "${") {
				tag = strings.TrimSuffix(tag[strings.Index(tag, ":-")+2:], "}")
			}
			out[service] = tag
		}
	}
	return out
}
