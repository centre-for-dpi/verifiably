// SPDX-License-Identifier: Apache-2.0

// Package config reads the data source settings from the environment
// with the shared config package (ADR-015).
package config

import (
	"fmt"
	"strings"
	"time"

	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
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
	// AuthJWKSFile is a JWKS file of issuer-auth. Empty selects header
	// mode, where a gateway verified the session already.
	AuthJWKSFile string `env:"AUTH_JWKS_FILE"`
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := sharedconfig.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
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
	if c.HTTPTimeout <= 0 {
		return Config{}, fmt.Errorf("config: %sHTTP_TIMEOUT must be a positive duration such as 30s", Prefix)
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
