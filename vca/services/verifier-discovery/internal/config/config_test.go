// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/config"
)

// env returns a getenv function over a map.
func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := config.Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8090" || c.PortalPrefix != "/portal" {
		t.Errorf("config = %+v", c)
	}
	if c.CacheTTL.Minutes() != 15 || c.PageSizeMax != 50 {
		t.Errorf("config = %+v", c)
	}
	if c.AllowPrivateNetwork || c.AllowPlainHTTP {
		t.Error("the fetcher guards the private network by default")
	}
}

func TestLoadValues(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"VCA_DISCOVERY_BASE_URL":              "https://verify.example/",
		"VCA_DISCOVERY_TRUST_URL":             "https://trust.example/",
		"VCA_DISCOVERY_ALLOWED_HOSTS":         "issuer.example, .gov.example",
		"VCA_DISCOVERY_ALLOW_PLAIN_HTTP":      "true",
		"VCA_DISCOVERY_ALLOW_PRIVATE_NETWORK": "true",
		"VCA_DISCOVERY_CRAWL_INTERVAL":        "0s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://verify.example" || c.TrustURL != "https://trust.example" {
		t.Errorf("the loader removes a trailing slash, got %+v", c)
	}
	if len(c.AllowedHosts) != 2 || c.AllowedHosts[1] != ".gov.example" {
		t.Errorf("allowed hosts = %v", c.AllowedHosts)
	}
	if c.CrawlInterval != 0 {
		t.Errorf("a zero interval turns the job off, got %v", c.CrawlInterval)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"trust timeout":  {"VCA_DISCOVERY_TRUST_TIMEOUT": "0s"},
		"crawl interval": {"VCA_DISCOVERY_CRAWL_INTERVAL": "-1s"},
		"cache ttl":      {"VCA_DISCOVERY_CACHE_TTL": "0s"},
		"fetch timeout":  {"VCA_DISCOVERY_FETCH_TIMEOUT": "0s"},
		"document bytes": {"VCA_DISCOVERY_MAX_DOCUMENT_BYTES": "0"},
		"page size":      {"VCA_DISCOVERY_PAGE_SIZE_MAX": "0"},
		"catalog max":    {"VCA_DISCOVERY_CATALOG_MAX_AGE": "-1s"},
		"portal prefix":  {"VCA_DISCOVERY_PORTAL_PREFIX": "portal"},
		"bad duration":   {"VCA_DISCOVERY_CACHE_TTL": "soon"},
		"key set ttl":    {"VCA_DISCOVERY_AUTH_JWKS_TTL": "0s"},
		"bad key set":    {"VCA_DISCOVERY_AUTH_JWKS_TTL": "soon"},
	}
	for name, values := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(env(values))
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), "config:") {
				t.Errorf("error = %v", err)
			}
		})
	}
}

// TestAuthSettings proves the guard variables load under the service
// prefix (ADR-036 decision 2).
func TestAuthSettings(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"VCA_DISCOVERY_AUTH_JWKS_URL": "http://verifier-auth:8081/.well-known/jwks.json",
		"VCA_DISCOVERY_LOGIN_URL":     "https://verifier-waltid.example/auth/",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Auth.Configured() || c.Auth.LoginURL != "https://verifier-waltid.example/auth/" || c.Auth.JWKSTTL != 10*time.Minute {
		t.Fatalf("auth %+v", c.Auth)
	}
}

// TestLoadPeers reads the pairs of the verifier shell and refuses a bad
// list (P5-01).
func TestLoadPeers(t *testing.T) {
	c, err := config.Load(env(map[string]string{"VCA_PEERS": "verifier-waltid|https://verifier.example|verifier-auth=http://auth:8081"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 1 || c.Peers[0].Pair != "verifier-waltid" {
		t.Errorf("peers = %+v", c.Peers)
	}
	if _, err := config.Load(env(map[string]string{"VCA_PEERS": "nonsense"})); err == nil {
		t.Error("a bad peer list loaded")
	}
}

// TestLoadPolicy reads the policy service of the query rules.
func TestLoadPolicy(t *testing.T) {
	c, err := config.Load(env(map[string]string{"VCA_DISCOVERY_POLICY_URL": "http://policy:8086/"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PolicyURL != "http://policy:8086" || c.PolicyTimeout != 10*time.Second {
		t.Errorf("policy = %q %s", c.PolicyURL, c.PolicyTimeout)
	}
	if _, err := config.Load(env(map[string]string{"VCA_DISCOVERY_POLICY_TIMEOUT": "0s"})); err == nil {
		t.Error("a zero policy timeout loaded")
	}
}
