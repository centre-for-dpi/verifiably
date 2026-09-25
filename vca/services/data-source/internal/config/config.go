// SPDX-License-Identifier: Apache-2.0

// Package config reads the data source settings from the environment
// with the shared config package (ADR-015), with the staff guard, the
// theme file, and the peers of the pages.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
)

// Prefix of every variable.
const Prefix = "VCA_DATASOURCE_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string `env:"LISTEN" default:":8080"`
	// StoreFile is the JSON file of the store. Empty keeps sources in memory.
	StoreFile string `env:"STORE_FILE"`
	// CSVDir is the directory of uploaded CSV files. Empty allows inline
	// data URLs only.
	CSVDir string `env:"CSV_DIR"`
	// SecretsDir is the directory of file secrets. Empty disables the
	// file store.
	SecretsDir string `env:"SECRETS_DIR"`
	// AllowHosts lists the host names HTTP sources may reach
	// (ADR-015 decision 6). An empty list allows no host.
	AllowHosts []string `env:"ALLOW_HOSTS"`
	// AllowHTTP permits the plain http scheme. It defaults to false.
	AllowHTTP bool `env:"ALLOW_HTTP" default:"false"`
	// AllowPrivate permits private, loopback, and link local addresses.
	// It defaults to false. Set it only for a local test.
	AllowPrivate bool `env:"ALLOW_PRIVATE" default:"false"`
	// HTTPMaxBytes caps one HTTP source response.
	HTTPMaxBytes int64 `env:"HTTP_MAX_BYTES" default:"8388608"`
	// HTTPTimeout bounds one HTTP source read.
	HTTPTimeout time.Duration `env:"HTTP_TIMEOUT" default:"30s"`
	// CSVMaxBytes caps one CSV file.
	CSVMaxBytes int64 `env:"CSV_MAX_BYTES" default:"33554432"`
	// SQLMaxRows caps the rows one SQL query returns.
	SQLMaxRows int `env:"SQL_MAX_ROWS" default:"10000"`
	// PageSizeMax caps the page size of List.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
	// PublicURL is the public URL of the issuer pair. An https URL makes
	// the cookie that clears a session Secure.
	PublicURL string `env:"PUBLIC_URL"`
	// SchemaURL is the base URL of the schema registry of the pair. The
	// field map and the bulk run read the schemas there.
	SchemaURL string `env:"SCHEMA_URL"`
	// IssuanceURL is the base URL of the issuance service of the pair. A
	// bulk run calls IssueBatch and GetBatch there (ADR-043 decision 4).
	IssuanceURL string `env:"ISSUANCE_URL"`
	// Timeout bounds one call to another service.
	Timeout time.Duration `env:"TIMEOUT" default:"30s"`
	// RunTimeout bounds one bulk run.
	RunTimeout time.Duration `env:"RUN_TIMEOUT" default:"2h"`

	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it
	// carries no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// Auth checks the session of issuer-auth on the pages and on every
	// RPC (ADR-036 decision 3). Its variables carry the same prefix:
	// AUTH_JWKS_URL, AUTH_JWKS_FILE, AUTH_ISSUER, and LOGIN_URL.
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
	c.PublicURL = strings.TrimRight(c.PublicURL, "/")
	return c.normalize()
}

// normalize checks the values and lowers the host names.
func (c Config) normalize() (Config, error) {
	hosts := make([]string, 0, len(c.AllowHosts))
	for _, h := range c.AllowHosts {
		hosts = append(hosts, strings.ToLower(h))
	}
	c.AllowHosts = nil
	if len(hosts) > 0 {
		c.AllowHosts = hosts
	}
	for _, v := range []struct {
		name  string
		value int64
	}{
		{"HTTP_MAX_BYTES", c.HTTPMaxBytes},
		{"CSV_MAX_BYTES", c.CSVMaxBytes},
	} {
		if v.value <= 0 {
			return Config{}, fmt.Errorf("config: %s%s must be a positive number of bytes", Prefix, v.name)
		}
	}
	for _, v := range []struct {
		name  string
		value time.Duration
	}{
		{"HTTP_TIMEOUT", c.HTTPTimeout},
		{"TIMEOUT", c.Timeout},
		{"RUN_TIMEOUT", c.RunTimeout},
	} {
		if v.value <= 0 {
			return Config{}, fmt.Errorf("config: %s%s must be a positive duration such as 30s", Prefix, v.name)
		}
	}
	for _, v := range []struct {
		name  string
		value int
	}{
		{"SQL_MAX_ROWS", c.SQLMaxRows},
		{"PAGE_SIZE_MAX", c.PageSizeMax},
	} {
		if v.value <= 0 {
			return Config{}, fmt.Errorf("config: %s%s must be a positive number", Prefix, v.name)
		}
	}
	return c, nil
}
