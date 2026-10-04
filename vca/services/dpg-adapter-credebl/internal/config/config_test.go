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
	if cfg.Listen != ":8080" || cfg.DpgVersion != "v2.2.1-alpha.4, sha256:b687cec51f96" {
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
// answer reports to the image references of the stack file, so a bump
// of one without the other fails here (ADR-034 decision 4). CREDEBL
// publishes from main, so each platform image carries the digest of the
// day the stack file pinned it (open question G.5).
func TestDefaultVersionsMatchTheStackFile(t *testing.T) {
	cfg, err := config.Load(env(required()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	refs := stackImageRefs(t, "../../../../../deploy/vca/dpg/credebl.yaml")
	versions := cfg.Versions()
	if len(versions) < 20 {
		t.Fatalf("versions = %v, want every platform service, the agent and the identity provider", versions)
	}
	for name, version := range versions {
		ref, ok := refs["credebl-"+name]
		if !ok {
			t.Errorf("the stack file runs no service credebl-%s", name)
			continue
		}
		if config.ShortRef(ref) != version {
			t.Errorf("%s: the answer says %s but the stack file runs %s", name, version, ref)
		}
	}
	for name, ref := range config.Images {
		if refs["credebl-"+name] != ref {
			t.Errorf("%s: the adapter pins %s but the stack file runs %s", name, ref, refs["credebl-"+name])
		}
	}
	// The release names its tag and the digest of the api gateway.
	tag, digest, _ := strings.Cut(config.Images["api-gateway"], "@")
	if want := tag + ", " + digest[:len("sha256:")+12]; cfg.DpgVersion != want {
		t.Errorf("DpgVersion = %q, want %q", cfg.DpgVersion, want)
	}
	if config.ShortRef("25.0") != "25.0" || config.ShortRef("v1@sha256:abc") != "v1@sha256:abc" {
		t.Error("ShortRef changed a reference with no full digest")
	}
}

// stackImageRefs reads the image reference after the repository of
// every service of a compose file: the tag, and the digest when the file
// pins one.
func stackImageRefs(t *testing.T, path string) map[string]string {
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
			slash := strings.LastIndex(image, "/")
			out[service] = image[slash+1+strings.Index(image[slash+1:], ":")+1:]
		}
	}
	return out
}

// TestLoadReadsTheAgentOfTheHolderRole is ADR-062 decision 7: the
// address and the API key of the shared agent turn the holder role on.
// The key is a secret, and the label has a default.
func TestLoadReadsTheAgentOfTheHolderRole(t *testing.T) {
	values := required()
	cfg, err := config.Load(env(values))
	if err != nil || cfg.AgentURL != "" || cfg.AgentAPIKey != "" || cfg.HolderLabel != "Wallet" || cfg.HolderRole() {
		t.Fatalf("defaults = %+v, %v", cfg, err)
	}
	values["VCA_CREDEBL_AGENT_URL"] = "http://credebl-agent.vca.internal:8001"
	values["VCA_CREDEBL_AGENT_API_KEY"] = "key"
	values["VCA_CREDEBL_HOLDER_LABEL"] = "Citizen wallet"
	if cfg, err = config.Load(env(values)); err != nil || !cfg.HolderRole() || cfg.HolderLabel != "Citizen wallet" {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
	vars, err := config.Describe()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vars {
		if v.Name == "VCA_CREDEBL_AGENT_API_KEY" && !v.Secret {
			t.Error("the agent API key is not a secret")
		}
	}
}

// TestLoadReadsAResolverOnlyAgent: an issuer and a verifier pair reach
// the agent to resolve ledger DIDs only (ADR-062 amendment of
// 2026-10-04). The setting keeps the holder role off.
func TestLoadReadsAResolverOnlyAgent(t *testing.T) {
	values := required()
	values["VCA_CREDEBL_AGENT_URL"] = "http://credebl-agent.vca.internal:8001"
	values["VCA_CREDEBL_AGENT_API_KEY"] = "key"
	values["VCA_CREDEBL_AGENT_RESOLVER_ONLY"] = "true"
	cfg, err := config.Load(env(values))
	if err != nil || cfg.HolderRole() || !cfg.UsesAgent() {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
	delete(values, "VCA_CREDEBL_AGENT_API_KEY")
	if cfg, err = config.Load(env(values)); err != nil || cfg.UsesAgent() {
		t.Fatalf("an agent without a key = %+v, %v", cfg, err)
	}
}

// TestLoadReadsTheStatusList: the status list host of the stack turns
// revocable offers on (P6-C5b). It is off by default, because the
// platform refuses a revocable offer without the host.
func TestLoadReadsTheStatusList(t *testing.T) {
	values := required()
	cfg, err := config.Load(env(values))
	if err != nil || cfg.StatusList {
		t.Fatalf("defaults = %+v, %v", cfg, err)
	}
	values["VCA_CREDEBL_STATUS_LIST"] = "true"
	if cfg, err = config.Load(env(values)); err != nil || !cfg.StatusList {
		t.Fatalf("config = %+v, %v", cfg, err)
	}
}
