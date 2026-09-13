// SPDX-License-Identifier: Apache-2.0

// Package config reads the wallet-auth settings from the environment.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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
	DiscoveryURL    string
	ClientID        string
	ClientSecretEnv string
}

// HasSeed reports whether the environment names a provider.
func (s SeedProvider) HasSeed() bool { return s.DiscoveryURL != "" && s.ClientID != "" }

// Lookup reads one environment variable. os.Getenv is the usual value.
type Lookup func(string) string

// FromEnv builds the configuration from the environment.
func FromEnv(get Lookup) (Config, error) {
	c := Config{
		Listen:                    or(get("VCA_WALLET_AUTH_LISTEN"), ":8083"),
		PublicBaseURL:             strings.TrimRight(get("VCA_PUBLIC_URL"), "/"),
		RedirectURI:               get("VCA_OIDC_REDIRECT_URI"),
		SigningKeyPath:            get("VCA_SECRETS_SIGNING_KEY"),
		SessionKey:                get("VCA_SECRETS_SESSION_KEY"),
		SessionTTL:                15 * time.Minute,
		GrantType:                 or(get("VCA_WALLET_AUTH_GRANT_TYPE"), DefaultGrantType),
		HolderBackendURL:          get("VCA_WALLET_AUTH_HOLDER_BACKEND_URL"),
		RedisURL:                  get("VCA_REDIS_URL"),
		LoginRate:                 30,
		AdminToken:                get("VCA_WALLET_AUTH_ADMIN_TOKEN"),
		StateDir:                  get("VCA_WALLET_AUTH_STATE_DIR"),
		CookieName:                or(get("VCA_WALLET_AUTH_COOKIE_NAME"), "vca_wallet_session"),
		LogoutRedirect:            get("VCA_WALLET_AUTH_LOGOUT_REDIRECT"),
		ProviderInternalAuthority: get("VCA_OIDC_INTERNAL_AUTHORITY"),
		Seed: SeedProvider{
			DiscoveryURL:    get("VCA_OIDC_DISCOVERY_URL"),
			ClientID:        get("VCA_OIDC_CLIENT_ID"),
			ClientSecretEnv: get("VCA_OIDC_CLIENT_SECRET"),
		},
	}
	var err error
	if c.SessionTTL, err = duration(get("VCA_WALLET_AUTH_SESSION_TTL"), c.SessionTTL); err != nil {
		return Config{}, err
	}
	if c.InsecureCookie, err = boolean(get("VCA_WALLET_AUTH_INSECURE_COOKIE")); err != nil {
		return Config{}, err
	}
	if c.LoginRate, err = integer(get("VCA_WALLET_AUTH_LOGIN_RATE"), c.LoginRate); err != nil {
		return Config{}, err
	}
	if c.Salt, err = secretBytes(get("VCA_WALLET_AUTH_SALT"), 16, 0); err != nil {
		return Config{}, fmt.Errorf("config: VCA_WALLET_AUTH_SALT: %w", err)
	}
	if c.GrantKey, err = secretBytes(get("VCA_WALLET_AUTH_GRANT_KEY"), 32, 32); err != nil {
		return Config{}, fmt.Errorf("config: VCA_WALLET_AUTH_GRANT_KEY: %w", err)
	}
	if c.PublicBaseURL == "" {
		return Config{}, errors.New("config: VCA_PUBLIC_URL is required")
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
		if hu, err := url.Parse(c.HolderBackendURL); err != nil || hu.Scheme == "" || hu.Host == "" {
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

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func duration(v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("config: %q is not a positive duration", v)
	}
	return d, nil
}

func integer(v string, def int) (int, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("config: %q is not a positive integer", v)
	}
	return n, nil
}

func boolean(v string) (bool, error) {
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: %q is not a boolean", v)
	}
	return b, nil
}
