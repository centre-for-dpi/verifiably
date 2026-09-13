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
)

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8081.
	Listen string
	// RegistryURL is the Connect base URL of the schema registry. The
	// builder saves every draft there.
	RegistryURL string
	// RegistryTimeout bounds one call to the schema registry.
	RegistryTimeout time.Duration
	// CatalogURL is the Connect base URL of the DPG adapter that serves
	// CatalogBackendService. Empty turns the catalogue import off.
	CatalogURL string
	// CatalogTimeout bounds one call to the DPG catalogue.
	CatalogTimeout time.Duration
	// PortalURL links the builder pages to the schema registry portal.
	PortalURL string
	// Prefix is the URL prefix of the builder pages.
	Prefix string
	// Issuer is the issuer identifier the preview credential carries.
	Issuer string
	// PDFCacheSize is the number of preview documents the cache holds.
	PDFCacheSize int
}

// Prefix of every variable.
const Prefix = "VCA_SCHEMABUILDER_"

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	get := func(name, def string) string {
		if v := strings.TrimSpace(getenv(Prefix + name)); v != "" {
			return v
		}
		return def
	}
	c := Config{
		Listen:      get("LISTEN", ":8081"),
		RegistryURL: strings.TrimRight(get("REGISTRY_URL", ""), "/"),
		CatalogURL:  strings.TrimRight(get("CATALOG_URL", ""), "/"),
		PortalURL:   get("PORTAL_URL", ""),
		Prefix:      "/" + strings.Trim(get("PREFIX", "/builder"), "/"),
		Issuer:      strings.TrimRight(get("ISSUER", ""), "/"),
	}
	if c.RegistryURL == "" {
		return Config{}, fmt.Errorf("config: %sREGISTRY_URL is required", Prefix)
	}
	var err error
	if c.RegistryTimeout, err = duration(get("REGISTRY_TIMEOUT", "10s"), "REGISTRY_TIMEOUT"); err != nil {
		return Config{}, err
	}
	if c.CatalogTimeout, err = duration(get("CATALOG_TIMEOUT", "10s"), "CATALOG_TIMEOUT"); err != nil {
		return Config{}, err
	}
	if c.PDFCacheSize, err = strconv.Atoi(get("PDF_CACHE_SIZE", "64")); err != nil || c.PDFCacheSize <= 0 {
		return Config{}, fmt.Errorf("config: %sPDF_CACHE_SIZE must be a positive number", Prefix)
	}
	return c, nil
}

func duration(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("config: %s%s must be a positive duration such as 10s", Prefix, name)
	}
	return d, nil
}
