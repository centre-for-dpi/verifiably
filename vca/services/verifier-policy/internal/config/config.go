// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the verifier policy service from
// environment variables. It uses the shared services/internal/config
// loader, so one error names every problem.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/cache"
)

// Prefix of every variable of this service.
const Prefix = "VCA_VERIFIER_POLICY_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8086"`
	// StateDir holds the policy set files. Empty keeps the sets in
	// memory and loses them on restart.
	StateDir string `env:"STATE_DIR"`
	// DefaultPolicySet is the set id that an Evaluate request without a
	// set id uses. Empty uses the built in set.
	DefaultPolicySet string `env:"DEFAULT_POLICY_SET"`
	// Audience is the client id of this verifier. The audience check
	// uses it when the request names no audience.
	Audience string `env:"AUDIENCE"`
	// TrustURL is the base URL of the trust registry service. Empty
	// makes the trust chain check report ERROR.
	TrustURL string `env:"TRUST_URL"`
	// TrustTimeout bounds one trust registry call.
	TrustTimeout time.Duration `env:"TRUST_TIMEOUT" default:"5s"`
	// FetchTimeout bounds one status list, DID, or schema fetch.
	FetchTimeout time.Duration `env:"FETCH_TIMEOUT" default:"5s"`
	// CacheTTL is how long a fetched document stays in the cache
	// (ADR-024 decision 3).
	CacheTTL time.Duration `env:"CACHE_TTL" default:"5m"`
	// CacheEntries caps the number of documents in the cache.
	CacheEntries int `env:"CACHE_ENTRIES" default:"256"`
	// FetchMaxBytes caps the size of one fetched document.
	FetchMaxBytes int64 `env:"FETCH_MAX_BYTES" default:"4194304"`
	// StatusFailMode is open or closed. It is the default of the status
	// check when a policy set names no fail mode.
	StatusFailMode string `env:"STATUS_FAIL_MODE" default:"closed"`
	// Leeway is the clock skew the temporal checks accept.
	Leeway time.Duration `env:"LEEWAY" default:"60s"`
	// PageSizeMax caps the page size of ListPolicySets.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
	// CacheTrustRefresh is how often the trust cache reads the trust
	// list (ADR-041 decision 2). SetCachePolicy overrides it.
	CacheTrustRefresh time.Duration `env:"CACHE_TRUST_REFRESH" default:"6h"`
	// CacheKeysRefresh is how often the trust cache reads the registry keys.
	CacheKeysRefresh time.Duration `env:"CACHE_KEYS_REFRESH" default:"24h"`
	// CacheStatusRefresh is how often the trust cache reads the status lists.
	CacheStatusRefresh time.Duration `env:"CACHE_STATUS_REFRESH" default:"1h"`
	// CacheAllowOffline lets a check read the trust cache when a source
	// does not answer (ADR-041 decision 3).
	CacheAllowOffline bool `env:"CACHE_ALLOW_OFFLINE" default:"false"`
	// CacheOfflineWindow is how long after the last good read a copy
	// stays usable with no network. At most 168h.
	CacheOfflineWindow time.Duration `env:"CACHE_OFFLINE_WINDOW" default:"24h"`
	// CacheMarkStale marks a result that read a copy older than its
	// refresh interval.
	CacheMarkStale bool `env:"CACHE_MARK_STALE" default:"true"`
	// CacheRefuseStaleStatus fails the status check on a status list
	// copy older than the window (ADR-041 decision 4).
	CacheRefuseStaleStatus bool `env:"CACHE_REFUSE_STALE_STATUS" default:"true"`
	// CacheTick is how often the schedule looks for a due read. Zero
	// turns the schedule off.
	CacheTick time.Duration `env:"CACHE_TICK" default:"1m"`
}

// CachePolicy returns the trust cache policy of the settings.
func (c Config) CachePolicy() cache.Policy {
	return cache.Policy{
		TrustRefresh: c.CacheTrustRefresh, KeysRefresh: c.CacheKeysRefresh, StatusRefresh: c.CacheStatusRefresh,
		AllowOffline: c.CacheAllowOffline, Window: c.CacheOfflineWindow,
		MarkStale: c.CacheMarkStale, RefuseStaleStatus: c.CacheRefuseStaleStatus,
	}
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
	if c.FetchTimeout <= 0 {
		problems = append(problems, Prefix+"FETCH_TIMEOUT must be positive")
	}
	if c.TrustTimeout <= 0 {
		problems = append(problems, Prefix+"TRUST_TIMEOUT must be positive")
	}
	if c.CacheTTL <= 0 {
		problems = append(problems, Prefix+"CACHE_TTL must be positive")
	}
	if c.CacheEntries <= 0 {
		problems = append(problems, Prefix+"CACHE_ENTRIES must be positive")
	}
	if c.FetchMaxBytes <= 0 {
		problems = append(problems, Prefix+"FETCH_MAX_BYTES must be positive")
	}
	if c.Leeway < 0 {
		problems = append(problems, Prefix+"LEEWAY must not be negative")
	}
	if c.PageSizeMax <= 0 {
		problems = append(problems, Prefix+"PAGE_SIZE_MAX must be positive")
	}
	for _, d := range []struct {
		name  string
		value time.Duration
	}{{"CACHE_TRUST_REFRESH", c.CacheTrustRefresh}, {"CACHE_KEYS_REFRESH", c.CacheKeysRefresh}, {"CACHE_STATUS_REFRESH", c.CacheStatusRefresh}} {
		if d.value < cache.MinRefresh {
			problems = append(problems, Prefix+d.name+" must be at least 1m")
		}
	}
	if c.CacheOfflineWindow <= 0 || c.CacheOfflineWindow > cache.MaxWindow {
		problems = append(problems, Prefix+"CACHE_OFFLINE_WINDOW must be more than zero and at most 168h")
	}
	if c.CacheTick < 0 {
		problems = append(problems, Prefix+"CACHE_TICK must not be negative")
	}
	if m := strings.ToLower(c.StatusFailMode); m != "open" && m != "closed" {
		problems = append(problems, Prefix+"STATUS_FAIL_MODE must be open or closed")
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
