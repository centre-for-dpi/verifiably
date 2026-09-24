// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/internal/topology"
)

func lookup(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

const peers = "issuer-waltid|https://issuer-waltid.labs.example|schema-registry=http://issuer-waltid-schema-registry:8103,dpg-adapter-waltid=http://issuer-waltid-dpg-adapter-waltid:8090"

func TestLoadDefaults(t *testing.T) {
	c, err := Load(lookup(map[string]string{}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != ":8080" || c.PublicURL != "" || c.Version != DefaultVersion || len(c.Peers) != 0 {
		t.Errorf("config = %+v", c)
	}
	if c.ProbeTimeout.String() != "1s" || c.ProbeTTL.String() != "15s" {
		t.Errorf("probe settings = %v %v", c.ProbeTimeout, c.ProbeTTL)
	}
	if !strings.HasPrefix(c.RepositoryURL, "https://github.com/") || !strings.HasPrefix(c.DocsURL, "https://") {
		t.Errorf("links = %q %q", c.RepositoryURL, c.DocsURL)
	}
}

func TestLoadReadsEveryVariable(t *testing.T) {
	c, err := Load(lookup(map[string]string{
		"VCA_LANDING_LISTEN":     ":9000",
		"VCA_LANDING_PUBLIC_URL": "https://vca.labs.example/",
		"VCA_THEME_FILE":         "/etc/vca/theme.yaml",
		"VCA_VERSION":            "1.2.3",
		topology.Env:             peers,
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != ":9000" || c.PublicURL != "https://vca.labs.example" || c.ThemeFile != "/etc/vca/theme.yaml" || c.Version != "1.2.3" {
		t.Errorf("config = %+v", c)
	}
	if len(c.Peers) != 1 || c.Peers[0].Pair != "issuer-waltid" || c.Peers[0].Adapter() == "" {
		t.Errorf("peers = %+v", c.Peers)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	for name, values := range map[string]map[string]string{
		"bad peers":      {topology.Env: "nonsense"},
		"bad timeout":    {"VCA_LANDING_PROBE_TIMEOUT": "0s"},
		"bad ttl":        {"VCA_LANDING_PROBE_TTL": "-1s"},
		"bad public url": {"VCA_LANDING_PUBLIC_URL": "vca.labs.example"},
		"bad docs url":   {"VCA_LANDING_DOCS_URL": "ftp://docs"},
		"not a duration": {"VCA_LANDING_PROBE_TTL": "soon"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(lookup(values)); err == nil {
				t.Error("no error")
			}
		})
	}
}
