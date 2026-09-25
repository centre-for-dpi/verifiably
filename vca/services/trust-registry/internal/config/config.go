// SPDX-License-Identifier: Apache-2.0

// Package config reads the trust registry settings from the environment
// with the shared config package (ADR-011).
package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/lookup"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// Prefix of every variable.
const Prefix = "VCA_TRUST_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string `env:"LISTEN" default:":8080"`
	// BaseURL is the public root of the service.
	BaseURL string `env:"BASE_URL" default:"http://localhost:8080"`
	// IssuerID identifies the registry operator. Empty means BaseURL.
	IssuerID string `env:"ISSUER_ID"`
	// IssuerName is the display name of the registry operator.
	IssuerName string `env:"ISSUER_NAME" default:"VCA trust registry"`
	// Territory is the country code of the registry operator.
	Territory string `env:"TERRITORY"`
	// Methods lists the enabled methods: etsi, dedi, or both.
	Methods []string `env:"METHODS" default:"etsi,dedi"`
	// SigningKeyFile is a PEM file with PKCS #8 keys. Empty generates one
	// ES256 key at start.
	SigningKeyFile string `env:"SIGNING_KEY_FILE"`
	// SigningAlg is the algorithm of a generated key: ES256 or EdDSA.
	SigningAlg string `env:"SIGNING_ALG" default:"ES256"`
	// StoreFile is the JSON file of the store. Empty keeps entries in memory.
	StoreFile string `env:"STORE_FILE"`
	// ListTTL is the validity of a published list.
	ListTTL time.Duration `env:"LIST_TTL" default:"24h"`
	// HTTPMaxAge is the Cache-Control max-age of the served files.
	HTTPMaxAge time.Duration `env:"HTTP_MAX_AGE" default:"5m"`
	// LookupPolicyName is fail-open or fail-closed.
	LookupPolicyName string `env:"LOOKUP_POLICY"`
	// LookupMaxAge is how long the lookup cache stays fresh.
	LookupMaxAge time.Duration `env:"LOOKUP_MAX_AGE" default:"1h"`
	// ResolveDIDs makes UpsertEntry resolve the DID of the entry.
	ResolveDIDs bool `env:"RESOLVE_DIDS" default:"true"`
	// PageSizeMax caps the page size of ListEntries.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"200"`
	// RegistriesFile keeps the external registries and their cached
	// copies. Empty puts registries.json beside StoreFile, or keeps them
	// in memory without a store file.
	RegistriesFile string `env:"REGISTRIES_FILE"`
	// FederationAllowPrivate lets the federation reach private and
	// loopback addresses. Use it for development only.
	FederationAllowPrivate bool `env:"FEDERATION_ALLOW_PRIVATE" default:"false"`
	// FederationAllowHTTP lets the federation read lists over plain http.
	FederationAllowHTTP bool `env:"FEDERATION_ALLOW_HTTP" default:"false"`
	// FederationHosts limits the hosts of external lists. Empty allows
	// every public host.
	FederationHosts []string `env:"FEDERATION_ALLOWED_HOSTS"`
	// FederationTick is how often the service looks for registries whose
	// refresh interval passed.
	FederationTick time.Duration `env:"FEDERATION_TICK" default:"1m"`

	// Issuer identifies the registry operator in the lists.
	Issuer publish.Issuer
	// LookupPolicy is the parsed form of LookupPolicyName.
	LookupPolicy lookup.Policy
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := sharedconfig.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	return c.normalize()
}

// normalize checks the values and fills the derived fields.
func (c Config) normalize() (Config, error) {
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.IssuerID == "" {
		c.IssuerID = c.BaseURL
	}
	c.Issuer = publish.Issuer{ID: c.IssuerID, Name: c.IssuerName, Territory: c.Territory}
	methods := make([]string, 0, len(c.Methods))
	for _, m := range c.Methods {
		m = strings.ToLower(m)
		switch m {
		case publish.MethodEtsi, publish.MethodDedi:
			methods = append(methods, m)
		default:
			return Config{}, fmt.Errorf("config: unknown method %q in %sMETHODS", m, Prefix)
		}
	}
	if len(methods) == 0 {
		return Config{}, fmt.Errorf("config: %sMETHODS names no method", Prefix)
	}
	c.Methods = methods
	switch c.SigningAlg {
	case "ES256", "EdDSA":
	default:
		return Config{}, fmt.Errorf("config: %sSIGNING_ALG must be ES256 or EdDSA", Prefix)
	}
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"LIST_TTL", c.ListTTL},
		{"HTTP_MAX_AGE", c.HTTPMaxAge},
		{"LOOKUP_MAX_AGE", c.LookupMaxAge},
		{"FEDERATION_TICK", c.FederationTick},
	} {
		if d.value <= 0 {
			return Config{}, fmt.Errorf("config: %s%s must be a positive duration such as 24h", Prefix, d.name)
		}
	}
	var err error
	if c.LookupPolicy, err = lookup.ParsePolicy(c.LookupPolicyName); err != nil {
		return Config{}, fmt.Errorf("config: %sLOOKUP_POLICY: %w", Prefix, err)
	}
	if c.PageSizeMax <= 0 {
		return Config{}, fmt.Errorf("config: %sPAGE_SIZE_MAX must be a positive number", Prefix)
	}
	if c.RegistriesFile == "" && c.StoreFile != "" {
		c.RegistriesFile = filepath.Join(filepath.Dir(c.StoreFile), "registries.json")
	}
	return c, nil
}

// Enabled reports whether method is in Methods.
func (c Config) Enabled(method string) bool {
	for _, m := range c.Methods {
		if m == method {
			return true
		}
	}
	return false
}
