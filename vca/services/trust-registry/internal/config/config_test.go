// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/lookup"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.BaseURL != "http://localhost:8080" || c.Issuer.ID != c.BaseURL || len(c.Methods) != 2 {
		t.Fatalf("%+v", c)
	}
	if c.ListTTL != 24*time.Hour || c.HTTPMaxAge != 5*time.Minute || c.LookupMaxAge != time.Hour || c.LookupPolicy != lookup.FailClosed || !c.ResolveDIDs || c.PageSizeMax != 200 || c.SigningAlg != "ES256" {
		t.Fatalf("%+v", c)
	}
	if !c.Enabled("etsi") || !c.Enabled("dedi") || c.Enabled("x") {
		t.Fatal("enabled")
	}
}

func TestOverrides(t *testing.T) {
	c, err := Load(env(map[string]string{
		"VCA_TRUST_LISTEN":           ":9090",
		"VCA_TRUST_BASE_URL":         "https://trust.example/",
		"VCA_TRUST_ISSUER_ID":        "did:web:trust.example",
		"VCA_TRUST_ISSUER_NAME":      "Registry",
		"VCA_TRUST_TERRITORY":        "KE",
		"VCA_TRUST_METHODS":          " DEDI , ",
		"VCA_TRUST_SIGNING_KEY_FILE": "/keys/trust.pem",
		"VCA_TRUST_SIGNING_ALG":      "EdDSA",
		"VCA_TRUST_STORE_FILE":       "/data/trust.json",
		"VCA_TRUST_LIST_TTL":         "1h",
		"VCA_TRUST_HTTP_MAX_AGE":     "30s",
		"VCA_TRUST_LOOKUP_POLICY":    "fail-open",
		"VCA_TRUST_LOOKUP_MAX_AGE":   "10m",
		"VCA_TRUST_RESOLVE_DIDS":     "false",
		"VCA_TRUST_PAGE_SIZE_MAX":    "50",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9090" || c.BaseURL != "https://trust.example" || c.Issuer.ID != "did:web:trust.example" || c.Issuer.Territory != "KE" {
		t.Fatalf("%+v", c)
	}
	if len(c.Methods) != 1 || c.Methods[0] != "dedi" || c.SigningKeyFile != "/keys/trust.pem" || c.SigningAlg != "EdDSA" || c.StoreFile != "/data/trust.json" {
		t.Fatalf("%+v", c)
	}
	if c.ListTTL != time.Hour || c.HTTPMaxAge != 30*time.Second || c.LookupPolicy != lookup.FailOpen || c.LookupMaxAge != 10*time.Minute || c.ResolveDIDs || c.PageSizeMax != 50 {
		t.Fatalf("%+v", c)
	}
}

func TestErrors(t *testing.T) {
	bad := []map[string]string{
		{"VCA_TRUST_METHODS": "openid"},
		{"VCA_TRUST_METHODS": ","},
		{"VCA_TRUST_SIGNING_ALG": "HS256"},
		{"VCA_TRUST_LIST_TTL": "soon"},
		{"VCA_TRUST_LIST_TTL": "-1h"},
		{"VCA_TRUST_HTTP_MAX_AGE": "x"},
		{"VCA_TRUST_LOOKUP_MAX_AGE": "x"},
		{"VCA_TRUST_LOOKUP_POLICY": "maybe"},
		{"VCA_TRUST_RESOLVE_DIDS": "sometimes"},
		{"VCA_TRUST_PAGE_SIZE_MAX": "0"},
		{"VCA_TRUST_PAGE_SIZE_MAX": "many"},
	}
	for i, m := range bad {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
}

// TestFederationSettings keeps the fetch guard strict by default and
// puts the registries file beside the store file.
func TestFederationSettings(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.RegistriesFile != "" || c.FederationAllowPrivate || c.FederationAllowHTTP || len(c.FederationHosts) != 0 || c.FederationTick != time.Minute {
		t.Fatalf("defaults = %+v", c)
	}
	c, err = Load(env(map[string]string{
		"VCA_TRUST_STORE_FILE":               "/data/trust.json",
		"VCA_TRUST_FEDERATION_ALLOW_PRIVATE": "true",
		"VCA_TRUST_FEDERATION_ALLOW_HTTP":    "true",
		"VCA_TRUST_FEDERATION_ALLOWED_HOSTS": "trust.go.ke,.europa.eu",
		"VCA_TRUST_FEDERATION_TICK":          "30s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.RegistriesFile != "/data/registries.json" || !c.FederationAllowPrivate || !c.FederationAllowHTTP || len(c.FederationHosts) != 2 || c.FederationTick != 30*time.Second {
		t.Fatalf("overrides = %+v", c)
	}
	c, err = Load(env(map[string]string{"VCA_TRUST_STORE_FILE": "/data/trust.json", "VCA_TRUST_REGISTRIES_FILE": "/other/r.json"}))
	if err != nil || c.RegistriesFile != "/other/r.json" {
		t.Fatalf("explicit file = %+v, %v", c, err)
	}
	if _, err := Load(env(map[string]string{"VCA_TRUST_FEDERATION_TICK": "0s"})); err == nil {
		t.Fatal("a zero tick passed")
	}
}
