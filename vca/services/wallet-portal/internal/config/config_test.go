// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/config"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := config.Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8092" {
		t.Fatalf("listen = %q", c.Listen)
	}
	if c.PortalPrefix != "/wallet" {
		t.Fatalf("prefix = %q", c.PortalPrefix)
	}
	if c.PendingTTL != 15*time.Minute {
		t.Fatalf("pending = %s", c.PendingTTL)
	}
	if _, ok := c.HolderBackendURL(); ok {
		t.Fatal("want browser storage by default")
	}
}

func TestLoadValues(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"VCA_WALLET_PORTAL_DPG":           "one",
		"VCA_WALLET_PORTAL_DPG_ADAPTERS":  "one=http://one:8080, two=http://two:8080",
		"VCA_WALLET_PORTAL_REQUEST_HOSTS": "verifier.example, other.example",
		"VCA_WALLET_PORTAL_CSRF_KEY":      strings.Repeat("k", 16),
	}))
	if err != nil {
		t.Fatal(err)
	}
	url, ok := c.HolderBackendURL()
	if !ok || url != "http://one:8080" {
		t.Fatalf("holder = %q %v", url, ok)
	}
	if len(c.RequestHosts) != 2 {
		t.Fatalf("hosts = %v", c.RequestHosts)
	}
	red, err := c.Redact()
	if err != nil {
		t.Fatal(err)
	}
	if red["VCA_WALLET_PORTAL_CSRF_KEY"] != "[redacted]" {
		t.Fatalf("csrf key = %q", red["VCA_WALLET_PORTAL_CSRF_KEY"])
	}
	if vars, err := config.Describe(); err != nil || len(vars) == 0 {
		t.Fatalf("describe: %v %d", err, len(vars))
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"PAGE_SIZE_MAX":  {"VCA_WALLET_PORTAL_PAGE_SIZE_MAX": "0"},
		"PENDING_TTL":    {"VCA_WALLET_PORTAL_PENDING_TTL": "0s"},
		"MAX_BLOB_BYTES": {"VCA_WALLET_PORTAL_MAX_BLOB_BYTES": "0"},
		"MAX_PASTE":      {"VCA_WALLET_PORTAL_MAX_PASTE_BYTES": "0"},
		"STATUS_TTL":     {"VCA_WALLET_PORTAL_STATUS_TTL": "0s"},
		"STATUS_CACHE":   {"VCA_WALLET_PORTAL_STATUS_CACHE_MAX": "0"},
		"FETCH_TIMEOUT":  {"VCA_WALLET_PORTAL_FETCH_TIMEOUT": "0s"},
		"FETCH_MAX":      {"VCA_WALLET_PORTAL_FETCH_MAX_BYTES": "0"},
		"DPG_TIMEOUT":    {"VCA_WALLET_PORTAL_DPG_TIMEOUT": "0s"},
		"JWKS_TTL":       {"VCA_WALLET_PORTAL_AUTH_JWKS_TTL": "0s"},
		"CSRF_KEY":       {"VCA_WALLET_PORTAL_CSRF_KEY": "short"},
		"ADAPTERS":       {"VCA_WALLET_PORTAL_DPG_ADAPTERS": "broken"},
		"PARSE":          {"VCA_WALLET_PORTAL_PAGE_SIZE_MAX": "many"},
	}
	for name, e := range cases {
		if _, err := config.Load(env(e)); err == nil {
			t.Fatalf("%s: want an error", name)
		}
	}
}

func TestHolderBackendURLMisses(t *testing.T) {
	c := config.Config{DPG: "one"}
	if _, ok := c.HolderBackendURL(); ok {
		t.Fatal("want no URL for an unknown adapter")
	}
	c.DPGAdapters = []string{"broken"}
	if _, ok := c.HolderBackendURL(); ok {
		t.Fatal("want no URL for a broken list")
	}
}

// TestLoadPeers reads the candidate pairs of the frame from VCA_PEERS
// and names a bad value.
func TestLoadPeers(t *testing.T) {
	c, err := config.Load(func(k string) string {
		if k == "VCA_PEERS" {
			return "holder-waltid|https://holder.example|wallet-auth=http://auth:8083,wallet-portal=http://portal:8092"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 1 || c.Peers[0].Pair != "holder-waltid" || c.Peers[0].Auth() != "http://auth:8083" {
		t.Fatalf("peers = %+v", c.Peers)
	}
	if _, err := config.Load(func(k string) string {
		if k == "VCA_PEERS" {
			return "nonsense"
		}
		return ""
	}); err == nil || !strings.Contains(err.Error(), "VCA_PEERS") {
		t.Fatalf("err = %v", err)
	}
}
