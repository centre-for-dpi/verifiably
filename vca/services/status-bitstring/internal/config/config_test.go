// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/statuslist/bitstring"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8084" || c.BaseURL != "http://localhost:8084" {
		t.Fatalf("config = %+v", c)
	}
	if c.ListSize != bitstring.MinSize || c.ListTTL != 24*time.Hour || c.HTTPMaxAge != 5*time.Minute {
		t.Fatalf("config = %+v", c)
	}
	if c.SigningAlg != "ES256" || c.SecuringMethod != "jose" || c.PageSizeMax != 50 {
		t.Fatalf("config = %+v", c)
	}
	if len(c.IssuerDIDs) != 0 || c.StateDir != "" || c.SigningKeyFile != "" {
		t.Fatalf("config = %+v", c)
	}
}

func TestLoadReadsEveryVariable(t *testing.T) {
	c, err := Load(env(map[string]string{
		Prefix + "LISTEN":           ":9000",
		Prefix + "BASE_URL":         "https://status.example",
		Prefix + "ISSUER_DIDS":      "did:web:a.example, did:web:b.example",
		Prefix + "SIGNING_ALG":      "EdDSA",
		Prefix + "SIGNING_KEY_FILE": "/keys/status.pem",
		Prefix + "STATE_DIR":        "/data",
		Prefix + "LIST_SIZE":        "262144",
		Prefix + "LIST_TTL":         "48h",
		Prefix + "HTTP_MAX_AGE":     "60s",
		Prefix + "SECURING_METHOD":  "jose",
		Prefix + "PAGE_SIZE_MAX":    "10",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.IssuerDIDs) != 2 || c.IssuerDIDs[1] != "did:web:b.example" {
		t.Fatalf("issuers = %v", c.IssuerDIDs)
	}
	if c.ListSize != 262144 || c.ListTTL != 48*time.Hour || c.HTTPMaxAge != time.Minute {
		t.Fatalf("config = %+v", c)
	}
	if c.SigningAlg != "EdDSA" || c.StateDir != "/data" || c.PageSizeMax != 10 {
		t.Fatalf("config = %+v", c)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		vars map[string]string
		want string
	}{
		{"size", map[string]string{Prefix + "LIST_SIZE": "1000"}, "at least 131072"},
		{"ttl", map[string]string{Prefix + "LIST_TTL": "0s"}, "LIST_TTL"},
		{"max age", map[string]string{Prefix + "HTTP_MAX_AGE": "-1s"}, "HTTP_MAX_AGE"},
		{"page size", map[string]string{Prefix + "PAGE_SIZE_MAX": "0"}, "PAGE_SIZE_MAX"},
		{"alg", map[string]string{Prefix + "SIGNING_ALG": "RS256"}, "SIGNING_ALG"},
		{"method", map[string]string{Prefix + "SECURING_METHOD": "eddsa-rdfc-2022"}, "not implemented"},
		{"unknown method", map[string]string{Prefix + "SECURING_METHOD": "magic"}, "unknown method"},
		{"not a number", map[string]string{Prefix + "LIST_SIZE": "many"}, "LIST_SIZE"},
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
	if len(vars) != 11 || vars[0].Name != Prefix+"LISTEN" {
		t.Fatalf("variables = %d, first %+v", len(vars), vars[0])
	}
	c, _ := Load(env(nil))
	values, err := c.Redact()
	if err != nil {
		t.Fatal(err)
	}
	if values[Prefix+"LISTEN"] != ":8084" {
		t.Fatalf("values = %v", values)
	}
}
