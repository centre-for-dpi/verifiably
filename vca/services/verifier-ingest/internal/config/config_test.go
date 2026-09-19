// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"strings"
	"testing"

	"github.com/centre-for-dpi/vc-adapters/services/verifier-ingest/internal/config"
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
	if c.Listen != ":8091" || c.ScannerPrefix != "/scan" {
		t.Errorf("config = %+v", c)
	}
	if c.ClientID != c.BaseURL {
		t.Errorf("the client id takes the base URL, got %q", c.ClientID)
	}
	if len(c.RequestURIHosts) != 0 {
		t.Error("no host is allowed by default, so no request URI is read")
	}
	if c.XMLEncoding != "text" {
		t.Errorf("xml encoding = %q", c.XMLEncoding)
	}
}

func TestLoadValues(t *testing.T) {
	c, err := config.Load(env(map[string]string{
		"VCA_INGEST_BASE_URL":          "https://verify.example/",
		"VCA_INGEST_DISCOVERY_URL":     "https://discovery.example/",
		"VCA_INGEST_CLIENT_ID":         "did:web:verify.example",
		"VCA_INGEST_REQUEST_URI_HOSTS": "wallet.example, .gov.example",
		"VCA_INGEST_XML_ENCODING":      "base64",
		"VCA_INGEST_XML_PATH":          "Envelope.Body.Credential",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL != "https://verify.example" || c.DiscoveryURL != "https://discovery.example" {
		t.Errorf("the loader removes a trailing slash, got %+v", c)
	}
	if c.ClientID != "did:web:verify.example" {
		t.Errorf("client id = %q", c.ClientID)
	}
	if len(c.RequestURIHosts) != 2 {
		t.Errorf("request URI hosts = %v", c.RequestURIHosts)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"discovery timeout": {"VCA_INGEST_DISCOVERY_TIMEOUT": "0s"},
		"request ttl":       {"VCA_INGEST_REQUEST_TTL": "0s"},
		"transaction ttl":   {"VCA_INGEST_TRANSACTION_TTL": "0s"},
		"input bytes":       {"VCA_INGEST_MAX_INPUT_BYTES": "0"},
		"request uri bytes": {"VCA_INGEST_MAX_REQUEST_URI_BYTES": "0"},
		"request uri time":  {"VCA_INGEST_REQUEST_URI_TIMEOUT": "0s"},
		"xml encoding":      {"VCA_INGEST_XML_ENCODING": "hex"},
		"scanner prefix":    {"VCA_INGEST_SCANNER_PREFIX": "scan"},
		"bad number":        {"VCA_INGEST_MAX_INPUT_BYTES": "many"},
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
