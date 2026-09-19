// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the verifier combined service
// from environment variables. It uses the shared services/internal/config
// loader, so one error names every problem.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/config"
)

// Prefix of every variable of this service.
const Prefix = "VCA_VERIFIER_COMBINED_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8088"`
	// StateDir holds the combined template files. Empty keeps the
	// templates in memory and loses them on restart.
	StateDir string `env:"STATE_DIR"`
	// PolicyURL is the base URL of the verifier policy service. The
	// service needs it to check each credential.
	PolicyURL string `env:"POLICY_URL"`
	// ResultsURL is the base URL of the verifier results service. Empty
	// turns the result storage off.
	ResultsURL string `env:"RESULTS_URL"`
	// DiscoveryURL is the base URL of the discovery service. The service
	// needs it to read the member templates for the DCQL query.
	DiscoveryURL string `env:"DISCOVERY_URL"`
	// CallTimeout bounds one call to another service.
	CallTimeout time.Duration `env:"CALL_TIMEOUT" default:"10s"`
	// DefaultPolicySet is the policy set that a template without a set
	// id uses. Empty uses the default set of the policy service.
	DefaultPolicySet string `env:"DEFAULT_POLICY_SET"`
	// PageSizeMax caps the page size of List.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := config.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	return c, c.Check()
}

// Check reports every setting that is out of range.
func (c Config) Check() error {
	var problems []string
	if c.CallTimeout <= 0 {
		problems = append(problems, Prefix+"CALL_TIMEOUT must be positive")
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
