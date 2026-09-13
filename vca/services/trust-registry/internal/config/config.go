// SPDX-License-Identifier: Apache-2.0

// Package config reads the service settings from environment variables.
// It is a minimal local stand-in for the shared services/internal/config
// package. The orchestrator replaces it later.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/lookup"
	"github.com/centre-for-dpi/vc-adapters/services/trust-registry/internal/publish"
)

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string
	// BaseURL is the public root of the service.
	BaseURL string
	// Issuer identifies the registry operator in the lists.
	Issuer publish.Issuer
	// Methods lists the enabled methods: etsi, dedi, or both.
	Methods []string
	// SigningKeyFile is a PEM file with PKCS #8 keys. Empty generates one
	// ES256 key at start.
	SigningKeyFile string
	// SigningAlg is the algorithm of a generated key: ES256 or EdDSA.
	SigningAlg string
	// StoreFile is the JSON file of the store. Empty keeps entries in memory.
	StoreFile string
	// ListTTL is the validity of a published list.
	ListTTL time.Duration
	// HTTPMaxAge is the Cache-Control max-age of the served files.
	HTTPMaxAge time.Duration
	// LookupPolicy is fail-open or fail-closed.
	LookupPolicy lookup.Policy
	// LookupMaxAge is how long the lookup cache stays fresh.
	LookupMaxAge time.Duration
	// ResolveDIDs makes UpsertEntry resolve the DID of the entry.
	ResolveDIDs bool
	// PageSizeMax caps the page size of ListEntries.
	PageSizeMax int
}

// Prefix of every variable.
const Prefix = "VCA_TRUST_"

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	get := func(name, def string) string {
		if v := strings.TrimSpace(getenv(Prefix + name)); v != "" {
			return v
		}
		return def
	}
	c := Config{
		Listen:         get("LISTEN", ":8080"),
		BaseURL:        strings.TrimRight(get("BASE_URL", "http://localhost:8080"), "/"),
		SigningKeyFile: get("SIGNING_KEY_FILE", ""),
		SigningAlg:     get("SIGNING_ALG", "ES256"),
		StoreFile:      get("STORE_FILE", ""),
	}
	c.Issuer = publish.Issuer{
		ID:        get("ISSUER_ID", c.BaseURL),
		Name:      get("ISSUER_NAME", "VCA trust registry"),
		Territory: get("TERRITORY", ""),
	}
	for _, m := range strings.Split(get("METHODS", "etsi,dedi"), ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		switch m {
		case publish.MethodEtsi, publish.MethodDedi:
			c.Methods = append(c.Methods, m)
		case "":
		default:
			return Config{}, fmt.Errorf("config: unknown method %q in %sMETHODS", m, Prefix)
		}
	}
	if len(c.Methods) == 0 {
		return Config{}, fmt.Errorf("config: %sMETHODS names no method", Prefix)
	}
	switch c.SigningAlg {
	case "ES256", "EdDSA":
	default:
		return Config{}, fmt.Errorf("config: %sSIGNING_ALG must be ES256 or EdDSA", Prefix)
	}
	var err error
	if c.ListTTL, err = duration(get("LIST_TTL", "24h"), "LIST_TTL"); err != nil {
		return Config{}, err
	}
	if c.HTTPMaxAge, err = duration(get("HTTP_MAX_AGE", "5m"), "HTTP_MAX_AGE"); err != nil {
		return Config{}, err
	}
	if c.LookupMaxAge, err = duration(get("LOOKUP_MAX_AGE", "1h"), "LOOKUP_MAX_AGE"); err != nil {
		return Config{}, err
	}
	if c.LookupPolicy, err = lookup.ParsePolicy(get("LOOKUP_POLICY", "")); err != nil {
		return Config{}, fmt.Errorf("config: %sLOOKUP_POLICY: %w", Prefix, err)
	}
	if c.ResolveDIDs, err = strconv.ParseBool(get("RESOLVE_DIDS", "true")); err != nil {
		return Config{}, fmt.Errorf("config: %sRESOLVE_DIDS must be true or false", Prefix)
	}
	if c.PageSizeMax, err = strconv.Atoi(get("PAGE_SIZE_MAX", "200")); err != nil || c.PageSizeMax <= 0 {
		return Config{}, fmt.Errorf("config: %sPAGE_SIZE_MAX must be a positive number", Prefix)
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

func duration(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("config: %s%s must be a positive duration such as 24h", Prefix, name)
	}
	return d, nil
}
