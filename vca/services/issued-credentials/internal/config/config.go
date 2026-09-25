// SPDX-License-Identifier: Apache-2.0

// Package config reads the issued credentials settings from the
// environment with the shared config package (ADR-017), with the staff
// guard, the theme file, the adapter, and the peers of the pages.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/retention"
)

// Prefix of every variable.
const Prefix = "VCA_ISSUED_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string `env:"LISTEN" default:":8080"`
	// StoreFile is the JSON file of the log. Empty keeps the log in
	// memory, so a restart loses it.
	StoreFile string `env:"STORE_FILE"`
	// Salt keys the one way subject reference (ADR-017 decision 2).
	Salt string `env:"SALT" secret:"true"`
	// SaltFile holds the salt when Salt is empty.
	SaltFile string `env:"SALT_FILE"`
	// HeadKeyFile is the PKCS 8 PEM file of the head signing key. Empty
	// makes the service generate a key at start.
	HeadKeyFile string `env:"HEAD_KEY_FILE"`
	// HeadIssuer names the deployment in the signed head.
	HeadIssuer string `env:"HEAD_ISSUER"`
	// HeadPeriod is the time between two signatures of an unchanged tip.
	HeadPeriod time.Duration `env:"HEAD_PERIOD" default:"24h"`
	// RetentionRules holds the per schema retention rules
	// (ADR-017 decision 5).
	RetentionRules string `env:"RETENTION"`
	// PruneInterval is the time between two prune runs. Zero turns the
	// scheduled job off.
	PruneInterval time.Duration `env:"PRUNE_INTERVAL" default:"24h"`
	// StatusURL is the base URL of the status service. Empty rejects
	// every status change.
	StatusURL string `env:"STATUS_URL"`
	// StatusTimeout bounds one status service call.
	StatusTimeout time.Duration `env:"STATUS_TIMEOUT" default:"10s"`
	// PageSizeMax caps the page size of List and Search.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
	// AuditDir keeps the audit events of the status changes, one file
	// for each event (ADR-039). Empty keeps them in memory.
	AuditDir string `env:"AUDIT_DIR"`
	// AdminJWKSURL is the key set of the admin service. An admin session
	// it signed opens the audit store. Empty accepts no session.
	AdminJWKSURL string `env:"ADMIN_JWKS_URL"`
	// AdminToken is the admin service token. It opens the audit store
	// too. Empty accepts no token.
	AdminToken string `env:"ADMIN_TOKEN" secret:"true"`
	// PublicURL is the public URL of the issuer pair. An https URL makes
	// the cookie that clears a session Secure.
	PublicURL string `env:"PUBLIC_URL"`
	// AdapterURL is the base URL of the DPG adapter of the pair. A revoke
	// goes through the adapter when it lists FEATURE_REVOCATION, and the
	// pages read the claim state of an offer when it lists
	// FEATURE_ISSUANCE_STATUS. Empty keeps every change on the status
	// service.
	AdapterURL string `env:"ADAPTER_URL"`
	// Timeout bounds one call to the adapter or to issuer-auth.
	Timeout time.Duration `env:"TIMEOUT" default:"10s"`

	// Retention is the parsed form of RetentionRules.
	Retention retention.Policy
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it
	// carries no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// Auth checks the session of issuer-auth on the pages (ADR-036
	// decision 3). Its variables carry the same prefix: AUTH_JWKS_URL,
	// AUTH_JWKS_FILE, AUTH_ISSUER, and LOGIN_URL.
	Auth staffsession.Settings
	// Peers are the candidate pairs of the deployment, from VCA_PEERS.
	// The stack switcher of the issuer shell comes from them.
	Peers []topology.Peer
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
	if err := c.Auth.Check(Prefix); err != nil {
		return Config{}, err
	}
	c.ThemeFile = strings.TrimSpace(getenv(uikit.ThemeFileEnv))
	peers, err := topology.Parse(getenv(topology.Env))
	if err != nil {
		return Config{}, err
	}
	c.Peers = peers
	return c.normalize()
}

// normalize checks the values and fills the derived fields.
func (c Config) normalize() (Config, error) {
	c.StatusURL = strings.TrimRight(c.StatusURL, "/")
	c.AdapterURL = strings.TrimRight(c.AdapterURL, "/")
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	var err error
	if c.Retention, err = retention.Parse(c.RetentionRules); err != nil {
		return Config{}, fmt.Errorf("config: %sRETENTION: %w", Prefix, err)
	}
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"HEAD_PERIOD", c.HeadPeriod},
		{"STATUS_TIMEOUT", c.StatusTimeout},
		{"TIMEOUT", c.Timeout},
	} {
		if d.value <= 0 {
			return Config{}, fmt.Errorf("config: %s%s must be a positive duration such as 24h", Prefix, d.name)
		}
	}
	if c.PruneInterval < 0 {
		return Config{}, fmt.Errorf("config: %sPRUNE_INTERVAL must be a duration such as 24h, or 0 to turn the job off", Prefix)
	}
	if c.PageSizeMax <= 0 {
		return Config{}, fmt.Errorf("config: %sPAGE_SIZE_MAX must be a positive number", Prefix)
	}
	return c, nil
}
