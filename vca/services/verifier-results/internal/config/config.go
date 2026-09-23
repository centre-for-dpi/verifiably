// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the verifier results service
// from environment variables. It uses the shared services/internal/config
// loader, so one error names every problem.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
)

// Prefix of every variable of this service.
const Prefix = "VCA_VERIFIER_RESULTS_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8087"`
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it carries
	// no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// StateDir holds the result files. Empty keeps the results in
	// memory and loses them on restart.
	StateDir string `env:"STATE_DIR"`
	// Retention is how long a result stays readable
	// (ADR-025 decision 3).
	Retention time.Duration `env:"RETENTION" default:"720h"`
	// RawRetention is how long the raw presentation stays readable. The
	// purge deletes it first, so it must not be longer than Retention.
	RawRetention time.Duration `env:"RAW_RETENTION" default:"24h"`
	// PurgeInterval is the time between two purge runs. Zero turns the
	// scheduled job off.
	PurgeInterval time.Duration `env:"PURGE_INTERVAL" default:"1h"`
	// PortalPrefix is the URL prefix of the staff pages.
	PortalPrefix string `env:"PORTAL_PREFIX" default:"/portal"`
	// PublicPrefix is the URL prefix of the citizen check page
	// (ADR-025 decision 5).
	PublicPrefix string `env:"PUBLIC_PREFIX" default:"/verify"`
	// PolicyURL is the base URL of the verifier policy service. The
	// citizen check page needs it. Empty turns that page off.
	PolicyURL string `env:"POLICY_URL"`
	// PolicyTimeout bounds one policy service call.
	PolicyTimeout time.Duration `env:"POLICY_TIMEOUT" default:"10s"`
	// MaxPasteBytes caps the size of a pasted presentation.
	MaxPasteBytes int64 `env:"MAX_PASTE_BYTES" default:"1048576"`
	// PageSizeMax caps the page size of Query.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := config.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	c.ThemeFile = strings.TrimSpace(getenv(uikit.ThemeFileEnv))
	return c, c.Check()
}

// Check reports every setting that is out of range.
func (c Config) Check() error {
	var problems []string
	if c.Retention <= 0 {
		problems = append(problems, Prefix+"RETENTION must be positive")
	}
	if c.RawRetention <= 0 {
		problems = append(problems, Prefix+"RAW_RETENTION must be positive")
	}
	if c.RawRetention > c.Retention {
		problems = append(problems, Prefix+"RAW_RETENTION must not be longer than "+Prefix+"RETENTION")
	}
	if c.PurgeInterval < 0 {
		problems = append(problems, Prefix+"PURGE_INTERVAL must not be negative")
	}
	if c.PolicyTimeout <= 0 {
		problems = append(problems, Prefix+"POLICY_TIMEOUT must be positive")
	}
	if c.MaxPasteBytes <= 0 {
		problems = append(problems, Prefix+"MAX_PASTE_BYTES must be positive")
	}
	if c.PageSizeMax <= 0 {
		problems = append(problems, Prefix+"PAGE_SIZE_MAX must be positive")
	}
	if len(problems) > 0 {
		return fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Describe lists the variables of the service. The README uses it.
func Describe() ([]config.Variable, error) {
	return config.Describe(Prefix, &Config{})
}

// Redact returns the loaded values by variable name, secrets removed.
func (c Config) Redact() (map[string]string, error) {
	return config.Redact(Prefix, &c)
}
