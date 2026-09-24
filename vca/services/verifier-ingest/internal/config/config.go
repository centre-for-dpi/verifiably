// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the verifier-ingest service from
// environment variables. It uses the shared services/internal/config
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
const Prefix = "VCA_INGEST_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8091"`
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it carries
	// no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// BaseURL is the public root of the service. The request URI and the
	// response URI of an OID4VP transaction carry it.
	BaseURL string `env:"BASE_URL" default:"http://localhost:8091"`
	// StateDir holds the transaction files. Empty keeps them in memory.
	StateDir string `env:"STATE_DIR"`
	// DiscoveryURL is the base URL of the discovery service. The service
	// reads a presentation template from it.
	DiscoveryURL string `env:"DISCOVERY_URL"`
	// DiscoveryTimeout bounds one discovery service call.
	DiscoveryTimeout time.Duration `env:"DISCOVERY_TIMEOUT" default:"10s"`
	// ClientID is the OID4VP client identifier of the verifier. Empty
	// means the base URL.
	ClientID string `env:"CLIENT_ID"`
	// SigningKeyFile is a PKCS 8 PEM file with the request object key.
	// Empty makes the service generate one ES256 key at start.
	SigningKeyFile string `env:"SIGNING_KEY_FILE"`
	// RequestTTL is how long an OID4VP request works.
	RequestTTL time.Duration `env:"REQUEST_TTL" default:"5m"`
	// TransactionTTL is how long the service keeps a finished
	// transaction.
	TransactionTTL time.Duration `env:"TRANSACTION_TTL" default:"1h"`
	// MaxInputBytes caps one ingestion.
	MaxInputBytes int `env:"MAX_INPUT_BYTES" default:"16777216"`
	// RequestURIHosts lists the hosts the service may read a request
	// object from. Empty refuses every request URI
	// (ADR-023 decision 5).
	RequestURIHosts []string `env:"REQUEST_URI_HOSTS"`
	// MaxRequestURIBytes caps a fetched request object.
	MaxRequestURIBytes int `env:"MAX_REQUEST_URI_BYTES" default:"131072"`
	// RequestURITimeout bounds one request object fetch.
	RequestURITimeout time.Duration `env:"REQUEST_URI_TIMEOUT" default:"10s"`
	// AllowPlainHTTP lets the request URI fetcher use http. Turn it on
	// for development only.
	AllowPlainHTTP bool `env:"ALLOW_PLAIN_HTTP" default:"false"`
	// XMLPath is the default path of a credential in an XML document.
	XMLPath string `env:"XML_PATH"`
	// XMLEncoding is the default encoding of the XML text: text or
	// base64.
	XMLEncoding string `env:"XML_ENCODING" default:"text"`
	// RedirectURI is the URI the wallet opens after a direct post.
	// Empty sends no redirect.
	RedirectURI string `env:"REDIRECT_URI"`
	// ScannerPrefix is the URL prefix of the camera page.
	ScannerPrefix string `env:"SCANNER_PREFIX" default:"/scan"`
	// Auth guards the camera page with a session of verifier-auth
	// (ADR-036 decision 2). Its variables carry the same prefix. The
	// OID4VP endpoints of the wallet stay open.
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
	c.DiscoveryURL = strings.TrimRight(c.DiscoveryURL, "/")
	if c.ClientID == "" {
		c.ClientID = c.BaseURL
	}
	return c, c.Check()
}

// Check reports every setting that is out of range.
func (c Config) Check() error {
	var problems []string
	if c.DiscoveryTimeout <= 0 {
		problems = append(problems, Prefix+"DISCOVERY_TIMEOUT must be positive")
	}
	if c.RequestTTL <= 0 {
		problems = append(problems, Prefix+"REQUEST_TTL must be positive")
	}
	if c.TransactionTTL <= 0 {
		problems = append(problems, Prefix+"TRANSACTION_TTL must be positive")
	}
	if c.MaxInputBytes <= 0 {
		problems = append(problems, Prefix+"MAX_INPUT_BYTES must be positive")
	}
	if c.MaxRequestURIBytes <= 0 {
		problems = append(problems, Prefix+"MAX_REQUEST_URI_BYTES must be positive")
	}
	if c.RequestURITimeout <= 0 {
		problems = append(problems, Prefix+"REQUEST_URI_TIMEOUT must be positive")
	}
	switch c.XMLEncoding {
	case "text", "base64":
	default:
		problems = append(problems, Prefix+"XML_ENCODING must be text or base64")
	}
	if !strings.HasPrefix(c.ScannerPrefix, "/") {
		problems = append(problems, Prefix+"SCANNER_PREFIX must start with a slash")
	}
	if c.Auth.JWKSTTL <= 0 {
		problems = append(problems, Prefix+"AUTH_JWKS_TTL must be positive")
	}
	if len(problems) > 0 {
		return errors.New("config: " + strings.Join(problems, "; "))
	}
	return nil
}
