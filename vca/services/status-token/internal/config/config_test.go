// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8085" || c.BaseURL != "http://localhost:8085" {
		t.Fatalf("config = %+v", c)
	}
	if c.ListSize != 131072 || c.DefaultBits != 1 || c.ListTTL != 24*time.Hour {
		t.Fatalf("config = %+v", c)
	}
	if c.TokenTTL != 5*time.Minute || c.HTTPMaxAge != 5*time.Minute {
		t.Fatalf("config = %+v", c)
	}
	if c.SigningAlg != "ES256" || c.PageSizeMax != 50 || c.AggregationURI != "" {
		t.Fatalf("config = %+v", c)
	}
	if len(c.IssuerDIDs) != 0 || c.StateDir != "" || c.SigningKeyFile != "" {
		t.Fatalf("config = %+v", c)
	}
}

func TestLoadReadsEveryVariable(t *testing.T) {
	c, err := Load(env(map[string]string{
		Prefix + "LISTEN":           ":9001",
		Prefix + "BASE_URL":         "https://status.example",
		Prefix + "ISSUER_DIDS":      "did:web:a.example, did:web:b.example",
		Prefix + "SIGNING_ALG":      "EdDSA",
		Prefix + "SIGNING_KEY_FILE": "/keys/status.pem",
		Prefix + "STATE_DIR":        "/data",
		Prefix + "LIST_SIZE":        "262144",
		Prefix + "DEFAULT_BITS":     "2",
		Prefix + "LIST_TTL":         "48h",
		Prefix + "TOKEN_TTL":        "0s",
		Prefix + "HTTP_MAX_AGE":     "60s",
		Prefix + "AGGREGATION_URI":  "https://status.example/aggregate",
		Prefix + "PAGE_SIZE_MAX":    "10",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.IssuerDIDs) != 2 || c.IssuerDIDs[1] != "did:web:b.example" {
		t.Fatalf("issuers = %v", c.IssuerDIDs)
	}
	if c.ListSize != 262144 || c.DefaultBits != 2 || c.ListTTL != 48*time.Hour {
		t.Fatalf("config = %+v", c)
	}
	if c.TokenTTL != 0 || c.HTTPMaxAge != time.Minute || c.PageSizeMax != 10 {
		t.Fatalf("config = %+v", c)
	}
	if c.SigningAlg != "EdDSA" || c.StateDir != "/data" {
		t.Fatalf("config = %+v", c)
	}
	if c.AggregationURI != "https://status.example/aggregate" {
		t.Fatalf("config = %+v", c)
	}
}

func TestLoadAcceptsEveryStatusWidth(t *testing.T) {
	for _, bits := range []string{"1", "2", "4", "8"} {
		if _, err := Load(env(map[string]string{Prefix + "DEFAULT_BITS": bits})); err != nil {
			t.Errorf("bits %s: %v", bits, err)
		}
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		want string
	}{
		{"size", map[string]string{Prefix + "LIST_SIZE": "0"}, "LIST_SIZE"},
		{"bits", map[string]string{Prefix + "DEFAULT_BITS": "3"}, "DEFAULT_BITS"},
		{"ttl", map[string]string{Prefix + "LIST_TTL": "0s"}, "LIST_TTL"},
		{"token ttl", map[string]string{Prefix + "TOKEN_TTL": "-1s"}, "TOKEN_TTL"},
		{"max age", map[string]string{Prefix + "HTTP_MAX_AGE": "-1s"}, "HTTP_MAX_AGE"},
		{"page size", map[string]string{Prefix + "PAGE_SIZE_MAX": "0"}, "PAGE_SIZE_MAX"},
		{"alg", map[string]string{Prefix + "SIGNING_ALG": "RS256"}, "SIGNING_ALG"},
		{"not a number", map[string]string{Prefix + "DEFAULT_BITS": "many"}, "DEFAULT_BITS"},
	}
	for _, tc := range cases {
		_, err := Load(env(tc.vars))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}

func TestDescribeAndRedact(t *testing.T) {
	vars, err := Describe()
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 13 || vars[0].Name != Prefix+"LISTEN" {
		t.Fatalf("variables = %d, first %+v", len(vars), vars[0])
	}
	c, verr := Load(env(nil))
	if verr != nil {
		t.Fatalf("unexpected error: %v", verr)
	}
	values, err := c.Redact()
	if err != nil {
		t.Fatal(err)
	}
	if values[Prefix+"LISTEN"] != ":8085" {
		t.Fatalf("values = %v", values)
	}
}
