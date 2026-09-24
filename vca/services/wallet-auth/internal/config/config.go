// SPDX-License-Identifier: Apache-2.0

// Package config reads the wallet-auth settings from the environment
// with the shared config package (ADR-020).
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
)

// Prefix of the variables of this service.
const Prefix = "VCA_WALLET_AUTH_"

// CommonPrefix of the variables the deployment shares between services.
const CommonPrefix = "VCA_"

// settings are the VCA_WALLET_AUTH_ variables.
type settings struct {
	Listen           string        `env:"LISTEN" default:":8083"`
	SessionTTL       time.Duration `env:"SESSION_TTL" default:"15m"`
	SaltValue        string        `env:"SALT" secret:"true"`
	GrantKeyValue    string        `env:"GRANT_KEY" secret:"true"`
	GrantType        string        `env:"GRANT_TYPE" default:"urn:ietf:params:oauth:grant-type:jwt-bearer"`
	HolderBackendURL string        `env:"HOLDER_BACKEND_URL"`
	LoginRate        int           `env:"LOGIN_RATE" default:"30"`
	AdminToken       string        `env:"ADMIN_TOKEN" secret:"true"`
	StateDir         string        `env:"STATE_DIR"`
	CookieName       string        `env:"COOKIE_NAME" default:"vca_wallet_session"`
	InsecureCookie   bool          `env:"INSECURE_COOKIE"`
	LogoutRedirect   string        `env:"LOGOUT_REDIRECT"`
}

// common are the VCA_ variables that other services read too.
type common struct {
	PublicURL         string `env:"PUBLIC_URL" required:"true"`
	RedirectURI       string `env:"OIDC_REDIRECT_URI"`
	SigningKeyPath    string `env:"SECRETS_SIGNING_KEY"`
	SessionKey        string `env:"SECRETS_SESSION_KEY" secret:"true"`
	InternalAuthority string `env:"OIDC_INTERNAL_AUTHORITY"`
	DiscoveryURL      string `env:"OIDC_DISCOVERY_URL"`
	ClientID          string `env:"OIDC_CLIENT_ID"`
	ClientSecret      string `env:"OIDC_CLIENT_SECRET" secret:"true"`
	ProviderPublicURL string `env:"OIDC_PUBLIC_URL"`
	RedisURL          string `env:"REDIS_URL"`
}

// DefaultGrantType is the grant type the portal presents the IdP token
// with at an OID4VCI authorization server (RFC 7523 section 2.1).
const DefaultGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// Config holds every setting of the service.
type Config struct {
	// Listen is the internal listen address, for example :8083.
	Listen string
	// PublicBaseURL is the URL the browser uses. Redirect URIs derive
	// from it (ADR-012 decision 6).
	PublicBaseURL string
	// RedirectURI is the exact redirect URI registered at the provider.
	RedirectURI string
	// SigningKeyPath is the PEM file of the ES256 session key.
	SigningKeyPath string
	// SessionKey is the CSRF HMAC key. Empty makes a random key at start.
	SessionKey string
	// SessionTTL is the lifetime of a session JWT (ADR-020 decision 2).
	SessionTTL time.Duration
	// Salt is the per deployment salt that hashes iss|sub into the wallet
	// key (ADR-020 decision 1). Empty makes a random salt at start.
	Salt []byte
	// GrantKey is the 32 byte AES key that seals IdP tokens at rest
	// (ADR-020 decision 3). Empty makes a random key at start.
	GrantKey []byte
	// GrantType is the grant type GetAuthorizationGrant returns.
	GrantType string
	// HolderBackendURL is the Connect base URL of the holder backend
	// adapter. Empty keeps wallet ids local.
	HolderBackendURL string
	// RedisURL selects the Redis rate limiter (ADR-020 decision 6).
	// Optional. Empty selects the in-memory limiter, which is fine for
	// one replica. Set a Redis URL for more than one replica.
	RedisURL string
	// LoginRate is the number of login starts one client address can
	// make per minute.
	LoginRate int
	// AdminToken lets the admin service register providers.
	AdminToken string
	// StateDir is where the service persists providers and wallets.
	StateDir string
	// CookieName is the session cookie name.
	CookieName string
	// InsecureCookie drops the Secure cookie flag, for localhost only.
	InsecureCookie bool
	// LogoutRedirect is the relative path the browser goes to after logout.
	LogoutRedirect string
	// ProviderInternalAuthority moves provider endpoints to a container
	// network host (ADR-012 decision 6).
	ProviderInternalAuthority string
	// Seed is an optional provider from VCA_OIDC_* variables.
	Seed SeedProvider
}

// SeedProvider is the provider that the setup CLI writes to the
// environment. It is registered at start with id "default".
type SeedProvider struct {
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	// PublicURL is the base URL a browser uses to reach the provider.
	PublicURL string
}

// HasSeed reports whether the environment names a provider.
func (s SeedProvider) HasSeed() bool { return s.DiscoveryURL != "" && s.ClientID != "" }

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
		GrantType:                 s.GrantType,
		HolderBackendURL:          s.HolderBackendURL,
		RedisURL:                  k.RedisURL,
		LoginRate:                 s.LoginRate,
		AdminToken:                s.AdminToken,
		StateDir:                  s.StateDir,
		CookieName:                s.CookieName,
		InsecureCookie:            s.InsecureCookie,
		LogoutRedirect:            s.LogoutRedirect,
		ProviderInternalAuthority: k.InternalAuthority,
		Seed: SeedProvider{
			DiscoveryURL: k.DiscoveryURL,
			ClientID:     k.ClientID,
			ClientSecret: k.ClientSecret,
			PublicURL:    k.ProviderPublicURL,
		},
	}
	var err error
	if c.Salt, err = secretBytes(s.SaltValue, 16, 0); err != nil {
		return Config{}, fmt.Errorf("config: %sSALT: %w", Prefix, err)
	}
	if c.GrantKey, err = secretBytes(s.GrantKeyValue, 32, 32); err != nil {
		return Config{}, fmt.Errorf("config: %sGRANT_KEY: %w", Prefix, err)
	}
	return c.normalize()
}

// normalize checks the values and fills the derived fields.
func (c Config) normalize() (Config, error) {
	if c.SessionTTL <= 0 {
		return Config{}, errors.New("config: VCA_WALLET_AUTH_SESSION_TTL must be a positive duration")
	}
	if c.LoginRate <= 0 {
		return Config{}, errors.New("config: VCA_WALLET_AUTH_LOGIN_RATE must be a positive number")
	}
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return Config{}, errors.New("config: VCA_PUBLIC_URL must be an absolute http or https URL")
	}
	if c.RedirectURI == "" {
		c.RedirectURI = c.PublicBaseURL + "/wallet/auth/callback"
	}
	if c.LogoutRedirect != "" && !strings.HasPrefix(c.LogoutRedirect, "/") {
		return Config{}, errors.New("config: VCA_WALLET_AUTH_LOGOUT_REDIRECT must be a relative path")
	}
	if c.HolderBackendURL != "" {
		hu, err := url.Parse(c.HolderBackendURL)
		if err != nil || hu.Scheme == "" || hu.Host == "" {
			return Config{}, errors.New("config: VCA_WALLET_AUTH_HOLDER_BACKEND_URL must be an absolute URL")
		}
	}
	return c, nil
}

// secretBytes decodes a base64 or hex value. It returns nil for "".
// The result must have at least min bytes and, when exact is not zero,
// exactly exact bytes.
func secretBytes(v string, min, exact int) ([]byte, error) {
	if v == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(v)
	}
	if err != nil {
		b, err = base64.RawURLEncoding.DecodeString(v)
	}
	if err != nil {
		b = []byte(v)
	}
	if len(b) < min || (exact != 0 && len(b) != exact) {
		return nil, fmt.Errorf("value must have %d bytes", max(min, exact))
	}
	return b, nil
}
