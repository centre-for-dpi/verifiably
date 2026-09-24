// SPDX-License-Identifier: Apache-2.0

// Package config reads the landing settings from the environment with
// the shared config package (ADR-033).
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
)

// Prefix of every variable of the landing.
const Prefix = "VCA_LANDING_"

// VersionEnv carries the image version of the deployment. The deploy
// files set it for compose, so it has no service prefix.
const VersionEnv = "VCA_VERSION"

// DefaultVersion is the version the landing shows when none is set.
const DefaultVersion = "latest"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds, for example :8080.
	Listen string `env:"LISTEN" default:":8080"`
	// PublicURL is the address a browser opens for the landing. The
	// descriptor and the absolute links carry it. Empty means relative
	// links only.
	PublicURL string `env:"PUBLIC_URL"`
	// ProbeTimeout bounds the probe of one peer (ADR-034 decision 2).
	ProbeTimeout time.Duration `env:"PROBE_TIMEOUT" default:"1s"`
	// ProbeTTL is the life of one probe snapshot (ADR-034 decision 2).
	ProbeTTL time.Duration `env:"PROBE_TTL" default:"15s"`
	// RepositoryURL is the source repository the header and the footer
	// link to.
	RepositoryURL string `env:"REPOSITORY_URL" default:"https://github.com/centre-for-dpi/verifiably"`
	// DocsURL is the documentation the header links to.
	DocsURL string `env:"DOCS_URL" default:"https://github.com/centre-for-dpi/verifiably/tree/main/vca/docs"`
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it carries
	// no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// Peers lists every candidate pair of the deployment, from VCA_PEERS
	// (ADR-034 decision 1). Empty means no pair at all.
	Peers []topology.Peer
	// Version is the image version of the deployment, from VCA_VERSION.
	Version string
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := sharedconfig.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	c.ThemeFile = strings.TrimSpace(getenv(uikit.ThemeFileEnv))
	c.Version = strings.TrimSpace(getenv(VersionEnv))
	if c.Version == "" {
		c.Version = DefaultVersion
	}
	peers, err := topology.Parse(getenv(topology.Env))
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	c.Peers = peers
	return c.normalize()
}

// normalize checks the values and trims the URLs.
func (c Config) normalize() (Config, error) {
	c.PublicURL = strings.TrimRight(strings.TrimSpace(c.PublicURL), "/")
	c.RepositoryURL = strings.TrimRight(c.RepositoryURL, "/")
	c.DocsURL = strings.TrimRight(c.DocsURL, "/")
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"PROBE_TIMEOUT", c.ProbeTimeout},
		{"PROBE_TTL", c.ProbeTTL},
	} {
		if d.value <= 0 {
			return Config{}, fmt.Errorf("config: %s%s must be a positive duration such as 1s", Prefix, d.name)
		}
	}
	for _, u := range []struct{ name, value string }{
		{"PUBLIC_URL", c.PublicURL}, {"REPOSITORY_URL", c.RepositoryURL}, {"DOCS_URL", c.DocsURL},
	} {
		if u.value == "" && u.name == "PUBLIC_URL" {
			continue
		}
		if !strings.HasPrefix(u.value, "http://") && !strings.HasPrefix(u.value, "https://") {
			return Config{}, fmt.Errorf("config: %s%s must be an http or https URL", Prefix, u.name)
		}
	}
	return c, nil
}
