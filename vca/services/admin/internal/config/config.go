// SPDX-License-Identifier: Apache-2.0

// Package config reads the admin service settings from the environment
// with the shared config package (ADR-009, ADR-010).
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
)

// Prefix is the environment variable prefix of every setting.
const Prefix = "VCA_ADMIN_"

// DefaultListen is the port of the admin service (ADR-002).
const DefaultListen = ":8093"

// Config holds every setting of the admin service.
type Config struct {
	// Listen is the address to bind.
	Listen string `env:"LISTEN" default:":8093"`
	// PublicURL is the URL the browser uses. Redirect URIs derive from it.
	PublicURL string `env:"PUBLIC_URL" required:"true"`
	// RedirectURI is the exact redirect URI registered at the provider.
	// Empty means PublicURL plus /auth/callback (ADR-010 decision 2).
	RedirectURI string `env:"REDIRECT_URI"`
	// StateDir holds the records. Empty keeps them in memory.
	StateDir string `env:"STATE_DIR"`
	// SigningKeyPath is the PEM file of the ES256 session key. Empty
	// makes a new key at start, so sessions end at a restart.
	SigningKeyPath string `env:"SIGNING_KEY"`
	// SessionKey is the HMAC key of the CSRF tokens. Empty makes a
	// random key at start.
	SessionKey string `env:"SESSION_KEY" secret:"true"`
	// SessionTTL is the lifetime of an admin session JWT.
	SessionTTL time.Duration `env:"SESSION_TTL" default:"15m"`
	// CookieName is the name of the session cookie.
	CookieName string `env:"COOKIE_NAME" default:"vca_admin_session"`
	// InsecureCookie drops the Secure attribute, for localhost only.
	InsecureCookie bool `env:"INSECURE_COOKIE"`
	// BootstrapToken binds the first super admin (ADR-010 decision 4).
	// Empty makes the service generate one and log it once.
	BootstrapToken string `env:"BOOTSTRAP_TOKEN" secret:"true"`
	// TrustURL is the base URL of the trust registry service.
	TrustURL string `env:"TRUST_URL"`
	// Timeout bounds every call to another service or to a provider.
	Timeout time.Duration `env:"TIMEOUT" default:"10s"`
	// Services lists the deployment services as name=url pairs. The
	// health RPC probes the readyz endpoint of each one.
	Services []string `env:"SERVICES"`
	// PortalPrefix is the URL prefix of the admin portal pages.
	PortalPrefix string `env:"PORTAL_PREFIX" default:"/admin"`
	// LogoutRedirect is the relative path the browser opens after a
	// logout when the provider has no end session endpoint.
	LogoutRedirect string `env:"LOGOUT_REDIRECT" default:"/admin/"`
}

// Service is one deployment service the health RPC probes.
type Service struct {
	// Name is the service name, for example trust-registry.
	Name string
	// BaseURL is the base URL of the service without a trailing slash.
	BaseURL string
}

// ReadyzURL returns the readiness probe URL of the service.
func (s Service) ReadyzURL() string { return s.BaseURL + "/readyz" }

// Load reads the configuration from getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := sharedconfig.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	return c.normalize()
}

// Variables lists the settings of the service. The README and the start
// log use it.
func Variables() ([]sharedconfig.Variable, error) {
	return sharedconfig.Describe(Prefix, &Config{})
}

// Targets returns the parsed Services entries.
func (c Config) Targets() []Service {
	out := make([]Service, 0, len(c.Services))
	for _, raw := range c.Services {
		name, base, ok := strings.Cut(raw, "=")
		if !ok {
			continue
		}
		out = append(out, Service{Name: strings.TrimSpace(name), BaseURL: strings.TrimRight(strings.TrimSpace(base), "/")})
	}
	return out
}

// normalize checks the values and fills the derived settings.
func (c Config) normalize() (Config, error) {
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")
	if !absoluteHTTP(c.PublicURL) {
		return Config{}, errors.New("config: VCA_ADMIN_PUBLIC_URL must be an absolute http or https URL")
	}
	if c.RedirectURI == "" {
		c.RedirectURI = c.PublicURL + "/auth/callback"
	}
	if !absoluteHTTP(c.RedirectURI) {
		return Config{}, errors.New("config: VCA_ADMIN_REDIRECT_URI must be an absolute http or https URL")
	}
	if c.SessionTTL <= 0 {
		return Config{}, errors.New("config: VCA_ADMIN_SESSION_TTL must be a positive duration")
	}
	if c.Timeout <= 0 {
		return Config{}, errors.New("config: VCA_ADMIN_TIMEOUT must be a positive duration")
	}
	if c.TrustURL != "" && !absoluteHTTP(c.TrustURL) {
		return Config{}, errors.New("config: VCA_ADMIN_TRUST_URL must be an absolute http or https URL")
	}
	c.TrustURL = strings.TrimRight(c.TrustURL, "/")
	if !strings.HasPrefix(c.PortalPrefix, "/") {
		return Config{}, errors.New("config: VCA_ADMIN_PORTAL_PREFIX must start with a slash")
	}
	c.PortalPrefix = "/" + strings.Trim(c.PortalPrefix, "/")
	if !strings.HasPrefix(c.LogoutRedirect, "/") {
		return Config{}, errors.New("config: VCA_ADMIN_LOGOUT_REDIRECT must be a relative path")
	}
	for _, raw := range c.Services {
		name, base, ok := strings.Cut(raw, "=")
		if !ok || strings.TrimSpace(name) == "" || !absoluteHTTP(strings.TrimSpace(base)) {
			return Config{}, fmt.Errorf("config: VCA_ADMIN_SERVICES item %q must be name=https://host", raw)
		}
	}
	return c, nil
}

func absoluteHTTP(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
