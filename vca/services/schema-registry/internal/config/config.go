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

	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
)

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string
	// BaseURL is the public root of the service.
	BaseURL string
	// Metadata carries the OID4VCI values of the public documents.
	Metadata metadata.Options
	// StoreFile is the JSON file of the store. Empty keeps versions in memory.
	StoreFile string
	// BackendURL is the base URL of the DPG adapter that registers a
	// published version. Empty skips the registration.
	BackendURL string
	// BackendTimeout bounds one call to the DPG adapter.
	BackendTimeout time.Duration
	// HTTPMaxAge is the Cache-Control max-age of the public documents.
	HTTPMaxAge time.Duration
	// PortalPrefix is the URL prefix of the staff pages.
	PortalPrefix string
	// BuilderURL links the portal to the schema builder, when there is one.
	BuilderURL string
	// PageSizeMax caps the page size of List and Search.
	PageSizeMax int
}

// Prefix of every variable.
const Prefix = "VCA_SCHEMA_"

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	get := func(name, def string) string {
		if v := strings.TrimSpace(getenv(Prefix + name)); v != "" {
			return v
		}
		return def
	}
	c := Config{
		Listen:       get("LISTEN", ":8080"),
		BaseURL:      strings.TrimRight(get("BASE_URL", "http://localhost:8080"), "/"),
		StoreFile:    get("STORE_FILE", ""),
		BackendURL:   strings.TrimRight(get("BACKEND_URL", ""), "/"),
		PortalPrefix: "/" + strings.Trim(get("PORTAL_PREFIX", "/portal"), "/"),
		BuilderURL:   get("BUILDER_URL", ""),
	}
	c.Metadata = metadata.Options{
		BaseURL:            c.BaseURL,
		CredentialIssuer:   strings.TrimRight(get("CREDENTIAL_ISSUER", c.BaseURL), "/"),
		CredentialEndpoint: get("CREDENTIAL_ENDPOINT", ""),
	}
	for _, s := range split(get("AUTHORIZATION_SERVERS", "")) {
		c.Metadata.AuthorizationServers = append(c.Metadata.AuthorizationServers, s)
	}
	for _, a := range split(get("SIGNING_ALGS", "ES256,EdDSA")) {
		c.Metadata.SigningAlgs = append(c.Metadata.SigningAlgs, a)
	}
	if len(c.Metadata.SigningAlgs) == 0 {
		return Config{}, fmt.Errorf("config: %sSIGNING_ALGS names no algorithm", Prefix)
	}
	var err error
	if c.HTTPMaxAge, err = duration(get("HTTP_MAX_AGE", "5m"), "HTTP_MAX_AGE"); err != nil {
		return Config{}, err
	}
	if c.BackendTimeout, err = duration(get("BACKEND_TIMEOUT", "10s"), "BACKEND_TIMEOUT"); err != nil {
		return Config{}, err
	}
	if c.PageSizeMax, err = strconv.Atoi(get("PAGE_SIZE_MAX", "200")); err != nil || c.PageSizeMax <= 0 {
		return Config{}, fmt.Errorf("config: %sPAGE_SIZE_MAX must be a positive number", Prefix)
	}
	return c, nil
}

// split cuts a comma separated list and drops the empty parts.
func split(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func duration(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("config: %s%s must be a positive duration such as 5m", Prefix, name)
	}
	return d, nil
}
