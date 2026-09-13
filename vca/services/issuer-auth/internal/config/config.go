// SPDX-License-Identifier: Apache-2.0

// Package config reads the issuer-auth settings from the environment.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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
}

// SeedProvider is the provider that the setup CLI writes to the
// environment. It is registered at start with id "default".
type SeedProvider struct {
	DiscoveryURL    string
	ClientID        string
	ClientSecretEnv string
	RolesClaimPath  string
}

// Lookup reads one environment variable. os.Getenv is the usual value.
type Lookup func(string) string

// FromEnv builds the configuration from the environment.
func FromEnv(get Lookup) (Config, error) {
	c := Config{
		Listen:                    or(get("VCA_ISSUER_AUTH_LISTEN"), ":8081"),
		PublicBaseURL:             strings.TrimRight(get("VCA_PUBLIC_URL"), "/"),
		RedirectURI:               get("VCA_OIDC_REDIRECT_URI"),
		SigningKeyPath:            get("VCA_SECRETS_SIGNING_KEY"),
		SessionKey:                get("VCA_SECRETS_SESSION_KEY"),
		TenantID:                  or(get("VCA_ISSUER_AUTH_TENANT_ID"), "default"),
		AdminToken:                get("VCA_ISSUER_AUTH_ADMIN_TOKEN"),
		StateDir:                  get("VCA_ISSUER_AUTH_STATE_DIR"),
		CookieName:                or(get("VCA_ISSUER_AUTH_COOKIE_NAME"), "vca_issuer_session"),
		LogoutRedirect:            get("VCA_ISSUER_AUTH_LOGOUT_REDIRECT"),
		SessionTTL:                15 * time.Minute,
		MachineTokenTTL:           time.Hour,
		ProviderInternalAuthority: get("VCA_OIDC_INTERNAL_AUTHORITY"),
		Seed: SeedProvider{
			DiscoveryURL:    get("VCA_OIDC_DISCOVERY_URL"),
			ClientID:        get("VCA_OIDC_CLIENT_ID"),
			ClientSecretEnv: get("VCA_OIDC_CLIENT_SECRET"),
			RolesClaimPath:  or(get("VCA_OIDC_ROLES_CLAIM_PATH"), "realm_access.roles"),
		},
	}
	var err error
	if c.SessionTTL, err = duration(get("VCA_ISSUER_AUTH_SESSION_TTL"), c.SessionTTL); err != nil {
		return Config{}, err
	}
	if c.MachineTokenTTL, err = duration(get("VCA_ISSUER_AUTH_MACHINE_TOKEN_TTL"), c.MachineTokenTTL); err != nil {
		return Config{}, err
	}
	if c.InsecureCookie, err = boolean(get("VCA_ISSUER_AUTH_INSECURE_COOKIE")); err != nil {
		return Config{}, err
	}
	if c.PublicBaseURL == "" {
		return Config{}, errors.New("config: VCA_PUBLIC_URL is required")
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
