// SPDX-License-Identifier: Apache-2.0

// Package config reads the service settings from environment variables.
// It is a minimal local stand-in for the shared services/internal/config
// package. The orchestrator replaces it later.
package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Prefix of every variable.
const Prefix = "VCA_DATASOURCE_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string
	// StoreFile is the JSON file of the store. Empty keeps sources in memory.
	StoreFile string
	// CSVDir is the directory of uploaded CSV files. Empty allows inline
	// data URLs only.
	CSVDir string
	// SecretsDir is the directory of file secrets. Empty disables the
	// file store.
	SecretsDir string
	// AllowHosts lists the host names HTTP sources may reach
	// (ADR-015 decision 6). An empty list allows no host.
	AllowHosts []string
	// AllowHTTP permits the plain http scheme. It defaults to false.
	AllowHTTP bool
	// AllowPrivate permits private, loopback, and link local addresses.
	// It defaults to false. Set it only for a local test.
	AllowPrivate bool
	// HTTPMaxBytes caps one HTTP source response.
	HTTPMaxBytes int64
	// HTTPTimeout bounds one HTTP source read.
	HTTPTimeout time.Duration
	// CSVMaxBytes caps one CSV file.
	CSVMaxBytes int64
	// SQLMaxRows caps the rows one SQL query returns.
	SQLMaxRows int
	// PageSizeMax caps the page size of List.
	PageSizeMax int
	// AuthJWKSFile is a JWKS file of issuer-auth. Empty selects header
	// mode, where a gateway verified the session already.
	AuthJWKSFile string
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	get := func(name, def string) string {
		if v := strings.TrimSpace(getenv(Prefix + name)); v != "" {
			return v
		}
		return def
	}
	c := Config{
		Listen:       get("LISTEN", ":8080"),
		StoreFile:    get("STORE_FILE", ""),
		CSVDir:       get("CSV_DIR", ""),
		SecretsDir:   get("SECRETS_DIR", ""),
		AuthJWKSFile: get("AUTH_JWKS_FILE", ""),
	}
	for _, h := range strings.Split(get("ALLOW_HOSTS", ""), ",") {
		if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
			c.AllowHosts = append(c.AllowHosts, h)
		}
	}
	var err error
	if c.AllowHTTP, err = boolean(get("ALLOW_HTTP", "false"), "ALLOW_HTTP"); err != nil {
		return Config{}, err
	}
	if c.AllowPrivate, err = boolean(get("ALLOW_PRIVATE", "false"), "ALLOW_PRIVATE"); err != nil {
		return Config{}, err
	}
	if c.HTTPMaxBytes, err = size(get("HTTP_MAX_BYTES", "8388608"), "HTTP_MAX_BYTES"); err != nil {
		return Config{}, err
	}
	if c.CSVMaxBytes, err = size(get("CSV_MAX_BYTES", "33554432"), "CSV_MAX_BYTES"); err != nil {
		return Config{}, err
	}
	if c.HTTPTimeout, err = duration(get("HTTP_TIMEOUT", "30s"), "HTTP_TIMEOUT"); err != nil {
		return Config{}, err
	}
	if c.SQLMaxRows, err = count(get("SQL_MAX_ROWS", "10000"), "SQL_MAX_ROWS"); err != nil {
		return Config{}, err
	}
	if c.PageSizeMax, err = count(get("PAGE_SIZE_MAX", "50"), "PAGE_SIZE_MAX"); err != nil {
		return Config{}, err
	}
	return c, nil
}

func boolean(value, name string) (bool, error) {
	v, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("config: %s%s must be true or false", Prefix, name)
	}
	return v, nil
}

func size(value, name string) (int64, error) {
	v, err := strconv.ParseInt(value, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("config: %s%s must be a positive number of bytes", Prefix, name)
	}
	return v, nil
}

func count(value, name string) (int, error) {
	v, err := strconv.Atoi(value)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("config: %s%s must be a positive number", Prefix, name)
	}
	return v, nil
}

func duration(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("config: %s%s must be a positive duration such as 30s", Prefix, name)
	}
	return d, nil
}
