// SPDX-License-Identifier: Apache-2.0

// Package config reads the issued credentials settings from the
// environment with the shared config package (ADR-017).
package config

import (
	"fmt"
	"strings"
	"time"

	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
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

	// Retention is the parsed form of RetentionRules.
	Retention retention.Policy
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := sharedconfig.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	return c.normalize()
}

// normalize checks the values and fills the derived fields.
func (c Config) normalize() (Config, error) {
	c.StatusURL = strings.TrimRight(c.StatusURL, "/")
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
