// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the status-token service from
// environment variables. It uses the shared services/internal/config
// loader, so one error names every problem.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/services/internal/config"
)

// Prefix of every variable of this service.
const Prefix = "VCA_STATUS_TOKEN_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8085"`
	// BaseURL is the public root of the service. A list URL is
	// BaseURL + "/status/" + list id. It is the "sub" claim too.
	BaseURL string `env:"BASE_URL" default:"http://localhost:8085"`
	// IssuerDIDs lists the issuers that sign lists. The first is the
	// default. Empty means one issuer identified by the did:jwk of its
	// own key.
	IssuerDIDs []string `env:"ISSUER_DIDS"`
	// SigningAlg is the algorithm of a generated key: ES256 or EdDSA.
	SigningAlg string `env:"SIGNING_ALG" default:"ES256"`
	// SigningKeyFile is a PEM file with PKCS #8 keys for the default
	// issuer. The service reads it only when the store has no ring yet.
	SigningKeyFile string `env:"SIGNING_KEY_FILE"`
	// StateDir holds the store files. Empty keeps the state in memory
	// and loses every list on restart.
	StateDir string `env:"STATE_DIR"`
	// ListSize is the number of entries of a new list.
	ListSize int `env:"LIST_SIZE" default:"131072"`
	// DefaultBits is the status width of a new list when the request
	// gives none. It is 1, 2, 4, or 8 (ADR-019 decision 3).
	DefaultBits int `env:"DEFAULT_BITS" default:"1"`
	// ListTTL is how long one signature stays valid.
	ListTTL time.Duration `env:"LIST_TTL" default:"24h"`
	// TokenTTL is the "ttl" claim, the caching time for a verifier.
	// Zero leaves the claim out.
	TokenTTL time.Duration `env:"TOKEN_TTL" default:"5m"`
	// HTTPMaxAge is the Cache-Control max-age of the served list.
	HTTPMaxAge time.Duration `env:"HTTP_MAX_AGE" default:"5m"`
	// AggregationURI is the optional aggregation_uri claim.
	AggregationURI string `env:"AGGREGATION_URI"`
	// PageSizeMax caps the page size of ListLists.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := config.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	return c, c.Check()
}

// Check reports every setting that is out of range.
func (c Config) Check() error {
	var problems []string
	if c.ListSize <= 0 {
		problems = append(problems, Prefix+"LIST_SIZE must be positive")
	}
	switch c.DefaultBits {
	case 1, 2, 4, 8:
	default:
		problems = append(problems, Prefix+"DEFAULT_BITS must be 1, 2, 4, or 8")
	}
	if c.ListTTL <= 0 {
		problems = append(problems, Prefix+"LIST_TTL must be positive")
	}
	if c.TokenTTL < 0 {
		problems = append(problems, Prefix+"TOKEN_TTL must not be negative")
	}
	if c.HTTPMaxAge < 0 {
		problems = append(problems, Prefix+"HTTP_MAX_AGE must not be negative")
	}
	if c.PageSizeMax <= 0 {
		problems = append(problems, Prefix+"PAGE_SIZE_MAX must be positive")
	}
	if a := jose.Algorithm(c.SigningAlg); a != jose.ES256 && a != jose.EdDSA {
		problems = append(problems, Prefix+"SIGNING_ALG must be ES256 or EdDSA")
	}
	if len(problems) > 0 {
		return fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Describe lists the variables of the service. The README uses it.
func Describe() ([]config.Variable, error) {
	return config.Describe(Prefix, &Config{})
}

// Redact returns the loaded values by variable name, secrets removed.
func (c Config) Redact() (map[string]string, error) {
	return config.Redact(Prefix, &c)
}
