// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the verifier-discovery service
// from environment variables. It uses the shared services/internal/config
// loader, so one error names every problem.
package config

import (
	"errors"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
)

// Prefix of every variable of this service.
const Prefix = "VCA_DISCOVERY_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8090"`
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it carries
	// no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// BaseURL is the public root of the service.
	BaseURL string `env:"BASE_URL" default:"http://localhost:8090"`
	// StateDir holds the store files. Empty keeps the state in memory
	// and loses the catalogue and the templates on restart.
	StateDir string `env:"STATE_DIR"`
	// TrustURL is the base URL of the trust registry service. Empty
	// turns the crawler off.
	TrustURL string `env:"TRUST_URL"`
	// TrustTimeout bounds one trust registry call.
	TrustTimeout time.Duration `env:"TRUST_TIMEOUT" default:"10s"`
	// CrawlInterval is the time between two scheduled crawls. Zero turns
	// the scheduled crawl off.
	CrawlInterval time.Duration `env:"CRAWL_INTERVAL" default:"1h"`
	// CacheTTL is how long a fetched document stays fresh
	// (ADR-022 decision 1).
	CacheTTL time.Duration `env:"CACHE_TTL" default:"15m"`
	// FetchTimeout bounds one issuer fetch.
	FetchTimeout time.Duration `env:"FETCH_TIMEOUT" default:"10s"`
	// MaxDocumentBytes caps one fetched document.
	MaxDocumentBytes int `env:"MAX_DOCUMENT_BYTES" default:"1048576"`
	// AllowedHosts lists the host names the fetcher may reach. Empty
	// allows every public host.
	AllowedHosts []string `env:"ALLOWED_HOSTS"`
	// AllowPrivateNetwork lets the fetcher reach private and loopback
	// addresses. Turn it on for development only.
	AllowPrivateNetwork bool `env:"ALLOW_PRIVATE_NETWORK" default:"false"`
	// AllowPlainHTTP lets the fetcher use http as well as https. Turn it
	// on for development only.
	AllowPlainHTTP bool `env:"ALLOW_PLAIN_HTTP" default:"false"`
	// PageSizeMax caps the page size of every list RPC.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
	// CatalogMaxAge is the Cache-Control max-age of GET /catalog.
	CatalogMaxAge time.Duration `env:"CATALOG_MAX_AGE" default:"5m"`
	// PortalPrefix is the URL prefix of the staff pages.
	PortalPrefix string `env:"PORTAL_PREFIX" default:"/portal"`
	// Auth guards the staff pages with a session of verifier-auth
	// (ADR-036 decision 2). Its variables carry the same prefix. The
	// catalogue endpoints stay open.
	Auth staffsession.Settings
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := config.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	if err := config.Load(Prefix, &c.Auth, getenv); err != nil {
		return Config{}, err
	}
	c.ThemeFile = strings.TrimSpace(getenv(uikit.ThemeFileEnv))
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	c.TrustURL = strings.TrimRight(c.TrustURL, "/")
	return c, c.Check()
}

// Check reports every setting that is out of range.
func (c Config) Check() error {
	var problems []string
	if c.TrustTimeout <= 0 {
		problems = append(problems, Prefix+"TRUST_TIMEOUT must be positive")
	}
	if c.CrawlInterval < 0 {
		problems = append(problems, Prefix+"CRAWL_INTERVAL must not be negative")
	}
	if c.CacheTTL <= 0 {
		problems = append(problems, Prefix+"CACHE_TTL must be positive")
	}
	if c.FetchTimeout <= 0 {
		problems = append(problems, Prefix+"FETCH_TIMEOUT must be positive")
	}
	if c.MaxDocumentBytes <= 0 {
		problems = append(problems, Prefix+"MAX_DOCUMENT_BYTES must be positive")
	}
	if c.PageSizeMax <= 0 {
		problems = append(problems, Prefix+"PAGE_SIZE_MAX must be positive")
	}
	if c.CatalogMaxAge < 0 {
		problems = append(problems, Prefix+"CATALOG_MAX_AGE must not be negative")
	}
	if !strings.HasPrefix(c.PortalPrefix, "/") {
		problems = append(problems, Prefix+"PORTAL_PREFIX must start with a slash")
	}
	if c.Auth.JWKSTTL <= 0 {
		problems = append(problems, Prefix+"AUTH_JWKS_TTL must be positive")
	}
	if len(problems) > 0 {
		return errors.New("config: " + strings.Join(problems, "; "))
	}
	return nil
}
