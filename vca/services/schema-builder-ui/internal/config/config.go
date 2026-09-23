// SPDX-License-Identifier: Apache-2.0

// Package config reads the schema builder settings from the environment
// with the shared config package (ADR-014).
package config

import (
	"fmt"
	"strings"
	"time"

	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
)

// Prefix of every variable.
const Prefix = "VCA_SCHEMABUILDER_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8081.
	Listen string `env:"LISTEN" default:":8081"`
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it carries
	// no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// RegistryURL is the Connect base URL of the schema registry. The
	// builder saves every draft there.
	RegistryURL string `env:"REGISTRY_URL" required:"true"`
	// RegistryTimeout bounds one call to the schema registry.
	RegistryTimeout time.Duration `env:"REGISTRY_TIMEOUT" default:"10s"`
	// CatalogURL is the Connect base URL of the DPG adapter that serves
	// CatalogBackendService. Empty turns the catalogue import off.
	CatalogURL string `env:"CATALOG_URL"`
	// CatalogTimeout bounds one call to the DPG catalogue.
	CatalogTimeout time.Duration `env:"CATALOG_TIMEOUT" default:"10s"`
	// PortalURL links the builder pages to the schema registry portal.
	PortalURL string `env:"PORTAL_URL"`
	// Prefix is the URL prefix of the builder pages.
	Prefix string `env:"PREFIX" default:"/builder"`
	// Issuer is the issuer identifier the preview credential carries.
	Issuer string `env:"ISSUER"`
	// PDFCacheSize is the number of preview documents the cache holds.
	PDFCacheSize int `env:"PDF_CACHE_SIZE" default:"64"`
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := sharedconfig.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	c.ThemeFile = strings.TrimSpace(getenv(uikit.ThemeFileEnv))
	return c.normalize()
}

// normalize checks the values and trims the URLs.
func (c Config) normalize() (Config, error) {
	c.RegistryURL = strings.TrimRight(c.RegistryURL, "/")
	c.CatalogURL = strings.TrimRight(c.CatalogURL, "/")
	c.Issuer = strings.TrimRight(c.Issuer, "/")
	c.Prefix = "/" + strings.Trim(c.Prefix, "/")
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"REGISTRY_TIMEOUT", c.RegistryTimeout},
		{"CATALOG_TIMEOUT", c.CatalogTimeout},
	} {
		if d.value <= 0 {
			return Config{}, fmt.Errorf("config: %s%s must be a positive duration such as 10s", Prefix, d.name)
		}
	}
	if c.PDFCacheSize <= 0 {
		return Config{}, fmt.Errorf("config: %sPDF_CACHE_SIZE must be a positive number", Prefix)
	}
	return c, nil
}
