// SPDX-License-Identifier: Apache-2.0

// Package config reads the issuer-auth settings from the environment
// with the shared config package (ADR-012).
package config

import (
	"errors"
	"net/url"
	"strings"
	"time"

	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
)

// Prefix of the variables of this service.
const Prefix = "VCA_ISSUER_AUTH_"

// CommonPrefix of the variables the deployment shares between services.
const CommonPrefix = "VCA_"

// settings are the VCA_ISSUER_AUTH_ variables.
type settings struct {
	// Listen is the internal listen address, for example :8081.
	Listen string `env:"LISTEN" default:":8081"`
	// SessionTTL is the lifetime of a session JWT.
	SessionTTL time.Duration `env:"SESSION_TTL" default:"15m"`
	// MachineTokenTTL is the lifetime of a client credentials JWT.
	MachineTokenTTL time.Duration `env:"MACHINE_TOKEN_TTL" default:"1h"`
	// TenantID is the tenant every session belongs to.
	TenantID string `env:"TENANT_ID" default:"default"`
	// AdminToken lets the admin service register providers and clients.
	AdminToken string `env:"ADMIN_TOKEN" secret:"true"`
	// StateDir is where the service persists providers and clients.
	StateDir string `env:"STATE_DIR"`
	// CookieName is the session cookie name.
	CookieName string `env:"COOKIE_NAME" default:"vca_issuer_session"`
	// InsecureCookie drops the Secure cookie flag, for localhost only.
	InsecureCookie bool `env:"INSECURE_COOKIE"`
	// LogoutRedirect is where the browser goes after logout when the
	// provider has no end session endpoint.
	LogoutRedirect string `env:"LOGOUT_REDIRECT"`
	// LandingURL is the public URL of the landing. The sign in chooser
	// links back to its role picker.
	LandingURL string `env:"LANDING_URL"`
}

// common are the VCA_ variables that other services read too.
type common struct {
	// PublicURL is the URL the browser uses.
	PublicURL string `env:"PUBLIC_URL" required:"true"`
	// RedirectURI is the exact redirect URI registered at the provider.
	RedirectURI string `env:"OIDC_REDIRECT_URI"`
	// SigningKeyPath is the PEM file of the ES256 session key.
	SigningKeyPath string `env:"SECRETS_SIGNING_KEY"`
	// SessionKey is the CSRF HMAC key.
	SessionKey string `env:"SECRETS_SESSION_KEY" secret:"true"`
	// InternalAuthority is the scheme://host that reaches the provider.
	InternalAuthority string `env:"OIDC_INTERNAL_AUTHORITY"`
	// DiscoveryURL is the discovery document of the seed provider.
	DiscoveryURL string `env:"OIDC_DISCOVERY_URL"`
	// ClientID is the client id of the seed provider.
	ClientID string `env:"OIDC_CLIENT_ID"`
	// ClientSecret is the client secret. The provider record keeps a
	// reference to the variable, never the value.
	ClientSecret string `env:"OIDC_CLIENT_SECRET" secret:"true"`
	// RolesClaimPath is the path of the roles claim.
	RolesClaimPath string `env:"OIDC_ROLES_CLAIM_PATH" default:"realm_access.roles"`
	// ProviderPublicURL is the base URL a browser uses to reach the
	// provider. The console link of the seed provider derives from it.
	ProviderPublicURL string `env:"OIDC_PUBLIC_URL"`
}

// Config holds every setting of the service.
type Config struct {
	// Listen is the internal listen address, for example :8081.
	Listen string
	// PublicBaseURL is the URL the browser uses. Redirect URIs derive
	// from it (ADR-012 decision 6).
	PublicBaseURL string
	// RedirectURI is the exact redirect URI registered at the provider.
	RedirectURI string
	// SigningKeyPath is the PEM file of the ES256 session key. Empty
	// makes the service generate a key at start.
	SigningKeyPath string
	// SessionKey is the CSRF HMAC key. Empty makes a random key at start.
	SessionKey string
	// SessionTTL is the lifetime of a session JWT.
	SessionTTL time.Duration
	// MachineTokenTTL is the lifetime of a client credentials JWT.
	MachineTokenTTL time.Duration
	// TenantID is the tenant every session belongs to.
	TenantID string
	// AdminToken lets the admin service register providers and clients.
	AdminToken string
	// StateDir is where the service persists providers and clients.
	// Empty keeps them in memory.
	StateDir string
	// CookieName is the session cookie name.
	CookieName string
	// InsecureCookie drops the Secure cookie flag, for localhost only.
	InsecureCookie bool
	// LogoutRedirect is where the browser goes after logout when the
	// provider has no end session endpoint.
	LogoutRedirect string
	// ProviderInternalAuthority, when set, is the scheme://host the
	// service uses to reach every provider (ADR-012 decision 6).
	ProviderInternalAuthority string
	// Seed is an optional provider from VCA_OIDC_* variables.
	Seed SeedProvider
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Empty selects the embedded default (ADR-032 decision 1).
	ThemeFile string
	// LandingURL is the public URL of the landing, without a trailing
	// slash. Empty hides the way back on the sign in chooser.
	LandingURL string
}

// SeedProvider is the provider that the setup CLI writes to the
// environment. It is registered at start with id "default".
type SeedProvider struct {
	DiscoveryURL   string
	ClientID       string
	ClientSecret   string
	RolesClaimPath string
	// PublicURL is the base URL a browser uses to reach the provider.
	PublicURL string
}

// Lookup reads one environment variable. os.Getenv is the usual value.
type Lookup func(string) string

// FromEnv builds the configuration from the environment.
func FromEnv(get Lookup) (Config, error) {
	var s settings
	if err := sharedconfig.Load(Prefix, &s, get); err != nil {
		return Config{}, err
	}
	var k common
	if err := sharedconfig.Load(CommonPrefix, &k, get); err != nil {
		return Config{}, err
	}
	c := Config{
		Listen:                    s.Listen,
		PublicBaseURL:             strings.TrimRight(k.PublicURL, "/"),
		RedirectURI:               k.RedirectURI,
		SigningKeyPath:            k.SigningKeyPath,
		SessionKey:                k.SessionKey,
		SessionTTL:                s.SessionTTL,
		MachineTokenTTL:           s.MachineTokenTTL,
		TenantID:                  s.TenantID,
		AdminToken:                s.AdminToken,
		StateDir:                  s.StateDir,
		CookieName:                s.CookieName,
		InsecureCookie:            s.InsecureCookie,
		LogoutRedirect:            s.LogoutRedirect,
		ProviderInternalAuthority: k.InternalAuthority,
		ThemeFile:                 strings.TrimSpace(get(uikit.ThemeFileEnv)),
		LandingURL:                strings.TrimRight(strings.TrimSpace(s.LandingURL), "/"),
		Seed: SeedProvider{
			DiscoveryURL:   k.DiscoveryURL,
			ClientID:       k.ClientID,
			ClientSecret:   k.ClientSecret,
			RolesClaimPath: k.RolesClaimPath,
			PublicURL:      k.ProviderPublicURL,
		},
	}
	return c.normalize()
}

// normalize checks the values and fills the derived fields.
func (c Config) normalize() (Config, error) {
	if c.SessionTTL <= 0 || c.MachineTokenTTL <= 0 {
		return Config{}, errors.New("config: a token lifetime must be a positive duration")
	}
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return Config{}, errors.New("config: VCA_PUBLIC_URL must be an absolute http or https URL")
	}
	if c.RedirectURI == "" {
		c.RedirectURI = c.PublicBaseURL + "/auth/callback"
	}
	if c.LogoutRedirect != "" && !strings.HasPrefix(c.LogoutRedirect, "/") {
		return Config{}, errors.New("config: VCA_ISSUER_AUTH_LOGOUT_REDIRECT must be a relative path")
	}
	return c, nil
}

// HasSeed reports whether the environment names a provider.
func (s SeedProvider) HasSeed() bool { return s.DiscoveryURL != "" && s.ClientID != "" }
