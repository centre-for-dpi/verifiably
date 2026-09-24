// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
)

// env returns a lookup over a map.
func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func base(extra map[string]string) map[string]string {
	m := map[string]string{"VCA_ADMIN_PUBLIC_URL": "https://admin.example"}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestLoadFillsTheDefaults(t *testing.T) {
	c, err := config.Load(env(base(nil)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != config.DefaultListen {
		t.Errorf("listen = %q", c.Listen)
	}
	if c.RedirectURI != "https://admin.example/auth/callback" {
		t.Errorf("redirect = %q", c.RedirectURI)
	}
	if c.SessionTTL != 15*time.Minute {
		t.Errorf("ttl = %s", c.SessionTTL)
	}
	if c.CookieName != "vca_admin_session" {
		t.Errorf("cookie = %q", c.CookieName)
	}
	if c.PortalPrefix != "/admin" || c.LogoutRedirect != "/admin/" {
		t.Errorf("portal = %q logout = %q", c.PortalPrefix, c.LogoutRedirect)
	}
	if c.Timeout != 10*time.Second {
		t.Errorf("timeout = %s", c.Timeout)
	}
}

// TestLoadReadsTheSeedProvider reads the VCA_OIDC_* variables that the
// setup CLI writes, so the first admin has a provider to sign in with
// (ADR-035 decision 6).
func TestLoadReadsTheSeedProvider(t *testing.T) {
	c, err := config.Load(env(base(map[string]string{
		"VCA_OIDC_DISCOVERY_URL":      "http://kc:8080/realms/vca-admin-realm/.well-known/openid-configuration",
		"VCA_OIDC_CLIENT_ID":          "vca-admin",
		"VCA_OIDC_CLIENT_SECRET":      "S",
		"VCA_OIDC_PUBLIC_URL":         "http://localhost:17010",
		"VCA_OIDC_INTERNAL_AUTHORITY": "http://kc:8080",
	})))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.Seed.HasSeed() || c.Seed.ClientID != "vca-admin" || c.Seed.ClientSecret != "S" ||
		c.Seed.PublicURL != "http://localhost:17010" || c.Seed.InternalAuthority != "http://kc:8080" ||
		c.Seed.RolesClaimPath != "realm_access.roles" {
		t.Errorf("seed = %+v", c.Seed)
	}
	plain, err := config.Load(env(base(nil)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if plain.Seed.HasSeed() {
		t.Errorf("a configuration with no OIDC variables has a seed: %+v", plain.Seed)
	}
}

func TestLoadTrimsAndParsesTheServices(t *testing.T) {
	c, err := config.Load(env(base(map[string]string{
		"VCA_ADMIN_PUBLIC_URL":    "https://admin.example/",
		"VCA_ADMIN_SERVICES":      " trust-registry=https://trust.example/ , issuer-auth=https://issuer.example ",
		"VCA_ADMIN_TRUST_URL":     "https://trust.example/",
		"VCA_ADMIN_PORTAL_PREFIX": "/admin/",
	})))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.PublicURL != "https://admin.example" || c.TrustURL != "https://trust.example" {
		t.Errorf("urls = %q %q", c.PublicURL, c.TrustURL)
	}
	if c.PortalPrefix != "/admin" {
		t.Errorf("portal prefix = %q", c.PortalPrefix)
	}
	targets := c.Targets()
	if len(targets) != 2 {
		t.Fatalf("targets = %v", targets)
	}
	if targets[0].Name != "trust-registry" || targets[0].BaseURL != "https://trust.example" {
		t.Errorf("first target = %+v", targets[0])
	}
	if targets[0].ReadyzURL() != "https://trust.example/readyz" {
		t.Errorf("readyz = %q", targets[0].ReadyzURL())
	}
}

func TestTargetsSkipsAnItemWithoutAnEqualSign(t *testing.T) {
	c := config.Config{Services: []string{"broken"}}
	if got := c.Targets(); len(got) != 0 {
		t.Fatalf("targets = %v", got)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string]map[string]string{
		"no public url":     {"VCA_ADMIN_PUBLIC_URL": ""},
		"relative":          {"VCA_ADMIN_PUBLIC_URL": "admin.example"},
		"bad redirect":      {"VCA_ADMIN_REDIRECT_URI": "not-a-url"},
		"zero session ttl":  {"VCA_ADMIN_SESSION_TTL": "0s"},
		"zero timeout":      {"VCA_ADMIN_TIMEOUT": "0s"},
		"bad trust url":     {"VCA_ADMIN_TRUST_URL": "trust.example"},
		"bad portal prefix": {"VCA_ADMIN_PORTAL_PREFIX": "admin"},
		"bad logout":        {"VCA_ADMIN_LOGOUT_REDIRECT": "https://evil.example"},
		"bad service":       {"VCA_ADMIN_SERVICES": "trust-registry"},
		"bad service url":   {"VCA_ADMIN_SERVICES": "trust-registry=nowhere"},
		"bad duration":      {"VCA_ADMIN_TIMEOUT": "soon"},
		"bad boolean":       {"VCA_ADMIN_INSECURE_COOKIE": "maybe"},
	}
	for name, extra := range cases {
		m := base(extra)
		if v, ok := extra["VCA_ADMIN_PUBLIC_URL"]; ok {
			m["VCA_ADMIN_PUBLIC_URL"] = v
		}
		if _, err := config.Load(env(m)); err == nil {
			t.Errorf("%s: Load returned no error", name)
		}
	}
}

func TestVariablesNameEverySetting(t *testing.T) {
	vars, err := config.Variables()
	if err != nil {
		t.Fatalf("Variables: %v", err)
	}
	if len(vars) < 15 {
		t.Fatalf("got %d variables", len(vars))
	}
	var secrets, required int
	for _, v := range vars {
		if !strings.HasPrefix(v.Name, config.Prefix) {
			t.Errorf("variable %q has no prefix", v.Name)
		}
		if v.Secret {
			secrets++
		}
		if v.Required {
			required++
		}
	}
	if secrets != 2 || required != 1 {
		t.Errorf("secrets = %d required = %d", secrets, required)
	}
}

// TestLoadReadsThePeers reads VCA_PEERS, so the provider fan out knows
// the candidate pairs (ADR-035 decision 5). A bad value is one error.
func TestLoadReadsThePeers(t *testing.T) {
	c, err := config.Load(env(base(map[string]string{
		topology.Env: "issuer-waltid|https://issuer-waltid.example|issuer-auth=http://issuer-waltid-issuer-auth:8081",
	})))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Peers) != 1 || c.Peers[0].Pair != "issuer-waltid" || c.Peers[0].Auth() != "http://issuer-waltid-issuer-auth:8081" {
		t.Fatalf("peers = %+v", c.Peers)
	}
	if _, bad := config.Load(env(base(map[string]string{topology.Env: "not a peer"}))); bad == nil {
		t.Fatal("a bad peer list loaded")
	}
	none, err := config.Load(env(base(nil)))
	if err != nil || len(none.Peers) != 0 {
		t.Fatalf("no peers: %v %+v", err, none.Peers)
	}
}
