// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
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

// TestDefaultVersionsMatchTheStackFile binds the versions the capability
// answer reports to the image tags of the stack file, so a bump of one
// without the other fails here (ADR-034 decision 4).
func TestDefaultVersionsMatchTheStackFile(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{"VCA_INJI_CERTIFY_URL": "http://x"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tags := stackImageTags(t, "../../../../../deploy/vca/dpg/inji.yaml")
	versions := cfg.Versions()
	if len(versions) < 6 {
		t.Fatalf("versions = %v, want every component of the issuer and verifier profiles", versions)
	}
	for name, version := range versions {
		service := name
		if !strings.HasPrefix(name, "inji-") {
			service = "inji-" + name
		}
		tag, ok := tags[service]
		if !ok {
			t.Errorf("the stack file runs no service %s", service)
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

func TestProfilesNameTheStackKeys(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{
		"VCA_INJI_CERTIFY_URL":      "http://certify:8090",
		"VCA_INJI_SIGNING_DID_URL":  "did:web:issuer.example",
		"VCA_INJI_LDP_CRYPTO_SUITE": "EcdsaSecp256k1Signature2019",
	}))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles()
	if p.DidURL != "did:web:issuer.example" || p.Ldp.CryptoSuite != "EcdsaSecp256k1Signature2019" ||
		p.Ldp.AppID != "CERTIFY_VC_SIGN_ED25519" || p.SdJwt.Algorithm != "ES256" || p.Mdoc.CryptoSuite != "ES256" {
		t.Fatalf("profiles %+v", p)
	}
}

func TestPluginsSplitTheList(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{"VCA_INJI_CERTIFY_URL": "http://c", "VCA_INJI_CERTIFY_PLUGINS": " A, ,B "}))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Plugins(); len(got) != 2 || got[0] != "A" || got[1] != "B" || cfg.CADomain != "DEVICE" {
		t.Fatalf("plugins %v, domain %q", got, cfg.CADomain)
	}
}

// TestPresentationDuringIssuanceIsOffByDefault keeps the option off until
// the operator points Certify at Inji Verify.
func TestPresentationDuringIssuanceIsOffByDefault(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{"VCA_INJI_CERTIFY_URL": "http://c"}))
	if err != nil || cfg.PresentationDuringIssuance {
		t.Fatalf("default %v %v", cfg.PresentationDuringIssuance, err)
	}
	cfg, err = config.Load(env(map[string]string{"VCA_INJI_CERTIFY_URL": "http://c", "VCA_INJI_PRESENTATION_DURING_ISSUANCE": "true"}))
	if err != nil || !cfg.PresentationDuringIssuance {
		t.Fatalf("set %v %v", cfg.PresentationDuringIssuance, err)
	}
}

// TestLoadServesTheHolderRoleAlone loads a holder pair: Mimoto alone
// suffices, and the Mimoto settings have the defaults of the stack.
func TestLoadServesTheHolderRoleAlone(t *testing.T) {
	cfg, err := config.Load(env(map[string]string{
		"VCA_INJI_MIMOTO_URL": "http://inji-mimoto:8099", "VCA_INJI_WEB_URL": "http://localhost:17085",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MimotoProvider != "google" || cfg.WebURL != "http://localhost:17085" ||
		cfg.Versions()["mimoto"] != "0.21.0" || cfg.Versions()["inji-web"] != "0.16.0" {
		t.Fatalf("config = %+v", cfg)
	}
}
