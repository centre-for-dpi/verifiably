// SPDX-License-Identifier: Apache-2.0

// Package config reads the schema registry settings from the environment
// with the shared config package (ADR-013).
package config

import (
	"fmt"
	"strings"
	"time"

	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/metadata"
)

// Prefix of every variable.
const Prefix = "VCA_SCHEMA_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string `env:"LISTEN" default:":8080"`
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it carries
	// no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// BaseURL is the public root of the service.
	BaseURL string `env:"BASE_URL" default:"http://localhost:8080"`
	// CredentialIssuer is the issuer identifier of the metadata. Empty
	// means BaseURL.
	CredentialIssuer string `env:"CREDENTIAL_ISSUER"`
	// CredentialEndpoint is the credential endpoint of the metadata.
	CredentialEndpoint string `env:"CREDENTIAL_ENDPOINT"`
	// AuthorizationServers lists the authorization servers of the metadata.
	AuthorizationServers []string `env:"AUTHORIZATION_SERVERS"`
	// SigningAlgs lists the proof algorithms of the metadata.
	SigningAlgs []string `env:"SIGNING_ALGS" default:"ES256,EdDSA"`
	// StoreFile is the JSON file of the store. Empty keeps versions in memory.
	StoreFile string `env:"STORE_FILE"`
	// BackendURL is the base URL of the DPG adapter that registers a
	// published version. Empty skips the registration.
	BackendURL string `env:"BACKEND_URL"`
	// BackendTimeout bounds one call to the DPG adapter.
	BackendTimeout time.Duration `env:"BACKEND_TIMEOUT" default:"10s"`
	// HTTPMaxAge is the Cache-Control max-age of the public documents.
	HTTPMaxAge time.Duration `env:"HTTP_MAX_AGE" default:"5m"`
	// PortalPrefix is the URL prefix of the staff pages.
	PortalPrefix string `env:"PORTAL_PREFIX" default:"/portal"`
	// BuilderURL links the portal to the schema builder, when there is one.
	BuilderURL string `env:"BUILDER_URL"`
	// PageSizeMax caps the page size of List and Search.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"200"`

	// Auth guards the staff pages with a session of issuer-auth
	// (ADR-036 decision 3). Its variables carry the same prefix.
	Auth staffsession.Settings

	// Metadata carries the OID4VCI values of the public documents.
	Metadata metadata.Options
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := sharedconfig.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	if err := sharedconfig.Load(Prefix, &c.Auth, getenv); err != nil {
		return Config{}, err
	}
	c.ThemeFile = strings.TrimSpace(getenv(uikit.ThemeFileEnv))
	return c.normalize()
}

// normalize checks the values and fills the derived fields.
func (c Config) normalize() (Config, error) {
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	c.BackendURL = strings.TrimRight(c.BackendURL, "/")
	c.PortalPrefix = "/" + strings.Trim(c.PortalPrefix, "/")
	if c.CredentialIssuer == "" {
		c.CredentialIssuer = c.BaseURL
	}
	c.CredentialIssuer = strings.TrimRight(c.CredentialIssuer, "/")
	if len(c.SigningAlgs) == 0 {
		return Config{}, fmt.Errorf("config: %sSIGNING_ALGS names no algorithm", Prefix)
	}
	c.Metadata = metadata.Options{
		BaseURL:              c.BaseURL,
		CredentialIssuer:     c.CredentialIssuer,
		CredentialEndpoint:   c.CredentialEndpoint,
		AuthorizationServers: c.AuthorizationServers,
		SigningAlgs:          c.SigningAlgs,
	}
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"HTTP_MAX_AGE", c.HTTPMaxAge},
		{"BACKEND_TIMEOUT", c.BackendTimeout},
	} {
		if d.value <= 0 {
			return Config{}, fmt.Errorf("config: %s%s must be a positive duration such as 5m", Prefix, d.name)
		}
	}
	if c.PageSizeMax <= 0 {
		return Config{}, fmt.Errorf("config: %sPAGE_SIZE_MAX must be a positive number", Prefix)
	}
	if err := c.Auth.Check(Prefix); err != nil {
		return Config{}, err
	}
	return c, nil
}
