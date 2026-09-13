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

	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/retention"
)

// Prefix of every variable.
const Prefix = "VCA_ISSUED_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string
	// StoreFile is the JSON file of the log. Empty keeps the log in
	// memory, so a restart loses it.
	StoreFile string
	// Salt keys the one way subject reference (ADR-017 decision 2).
	Salt string
	// SaltFile holds the salt when Salt is empty.
	SaltFile string
	// HeadKeyFile is the PKCS 8 PEM file of the head signing key. Empty
	// makes the service generate a key at start.
	HeadKeyFile string
	// HeadIssuer names the deployment in the signed head.
	HeadIssuer string
	// HeadPeriod is the time between two signatures of an unchanged tip.
	HeadPeriod time.Duration
	// Retention holds the per schema retention rules
	// (ADR-017 decision 5).
	Retention retention.Policy
	// PruneInterval is the time between two prune runs. Zero turns the
	// scheduled job off.
	PruneInterval time.Duration
	// StatusURL is the base URL of the status service. Empty rejects
	// every status change.
	StatusURL string
	// StatusTimeout bounds one status service call.
	StatusTimeout time.Duration
	// PageSizeMax caps the page size of List and Search.
	PageSizeMax int
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
		Listen:      get("LISTEN", ":8080"),
		StoreFile:   get("STORE_FILE", ""),
		Salt:        get("SALT", ""),
		SaltFile:    get("SALT_FILE", ""),
		HeadKeyFile: get("HEAD_KEY_FILE", ""),
		HeadIssuer:  get("HEAD_ISSUER", ""),
		StatusURL:   strings.TrimRight(get("STATUS_URL", ""), "/"),
	}
	var err error
	if c.Retention, err = retention.Parse(get("RETENTION", "")); err != nil {
		return Config{}, fmt.Errorf("config: %sRETENTION: %w", Prefix, err)
	}
	if c.HeadPeriod, err = duration(get("HEAD_PERIOD", "24h"), "HEAD_PERIOD"); err != nil {
		return Config{}, err
	}
	if c.StatusTimeout, err = duration(get("STATUS_TIMEOUT", "10s"), "STATUS_TIMEOUT"); err != nil {
		return Config{}, err
	}
	if c.PruneInterval, err = interval(get("PRUNE_INTERVAL", "24h"), "PRUNE_INTERVAL"); err != nil {
		return Config{}, err
	}
	if c.PageSizeMax, err = count(get("PAGE_SIZE_MAX", "50"), "PAGE_SIZE_MAX"); err != nil {
		return Config{}, err
	}
	return c, nil
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
		return 0, fmt.Errorf("config: %s%s must be a positive duration such as 24h", Prefix, name)
	}
	return d, nil
}

// interval reads a duration that may be zero. Zero turns a job off.
func interval(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("config: %s%s must be a duration such as 24h, or 0 to turn the job off", Prefix, name)
	}
	return d, nil
}
