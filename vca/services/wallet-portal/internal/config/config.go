// SPDX-License-Identifier: Apache-2.0

// Package config reads the settings of the wallet portal service from
// environment variables. It uses the shared services/internal/config
// loader, so one error names every problem.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
)

// Prefix of every variable of this service.
const Prefix = "VCA_WALLET_PORTAL_"

// Config holds every setting of the service.
type Config struct {
	// Listen is the address the HTTP server binds.
	Listen string `env:"LISTEN" default:":8092"`
	// ThemeFile is the theme file of the deployment, from VCA_THEME_FILE.
	// Every service that serves HTML reads the same variable, so it carries
	// no service prefix. Empty selects the embedded default look.
	ThemeFile string
	// StateDir holds the pending offers, the presentations, and the
	// ciphertext blobs. Empty keeps them in memory.
	StateDir string `env:"STATE_DIR"`
	// PortalPrefix is the URL prefix of the citizen pages.
	PortalPrefix string `env:"PORTAL_PREFIX" default:"/wallet"`
	// LoginURL is the login page of the wallet authentication service.
	// A citizen with no session goes there. Empty answers 401 instead.
	LoginURL string `env:"LOGIN_URL"`
	// AuthJWKSURL is the JWKS URL of the wallet authentication service.
	// The middleware reads it to check a session JWT (ADR-020 decision 2).
	AuthJWKSURL string `env:"AUTH_JWKS_URL"`
	// AuthJWKSFile is a JWKS file. It replaces AuthJWKSURL in a
	// deployment with no network path to the authentication service.
	AuthJWKSFile string `env:"AUTH_JWKS_FILE"`
	// AuthJWKSTTL is how long the middleware keeps a fetched key set.
	AuthJWKSTTL time.Duration `env:"AUTH_JWKS_TTL" default:"10m"`
	// AuthIssuer is the issuer the session JWT must name. Empty accepts
	// every issuer.
	AuthIssuer string `env:"AUTH_ISSUER"`
	// CSRFKey signs the synchronizer tokens of the POST pages. It needs
	// 16 bytes or more. Empty makes a random key at start.
	CSRFKey string `env:"CSRF_KEY" secret:"true"`
	// DPG names the adapter of DPGAdapters that holds the credentials.
	// Empty turns the browser storage of ADR-021 decision 4 on.
	DPG string `env:"DPG"`
	// DPGAdapters maps an adapter name to its base URL, as
	// "name=http://host:port" items.
	DPGAdapters []string `env:"DPG_ADAPTERS"`
	// DPGTimeout bounds one call to the adapter.
	DPGTimeout time.Duration `env:"DPG_TIMEOUT" default:"30s"`
	// DiscoveryURL is the base URL of the verifier discovery service.
	// Empty turns the discovery page and the claimable page off.
	DiscoveryURL string `env:"DISCOVERY_URL"`
	// TrustURL is the base URL of the trust registry service. Empty
	// makes every trust outcome unavailable.
	TrustURL string `env:"TRUST_URL"`
	// EligibilityURL is the URL of the eligibility hook. The hook
	// answers yes or no per schema and nothing more
	// (ADR-021 decision 2). Empty uses EligibilityDefault.
	EligibilityURL string `env:"ELIGIBILITY_URL"`
	// EligibilityDefault is the answer when no hook is configured.
	EligibilityDefault bool `env:"ELIGIBILITY_DEFAULT"`
	// EligibilitySalt hides the citizen subject from the hook. The
	// service sends a salted, one way reference.
	EligibilitySalt string `env:"ELIGIBILITY_SALT" secret:"true"`
	// RequestHosts is the host allowlist of an OID4VP request_uri
	// (ADR-021 decision 5). Empty blocks every request URI.
	RequestHosts []string `env:"REQUEST_HOSTS"`
	// FetchTimeout bounds one outbound fetch of a request object or a
	// status list.
	FetchTimeout time.Duration `env:"FETCH_TIMEOUT" default:"10s"`
	// FetchMaxBytes caps one outbound fetch.
	FetchMaxBytes int64 `env:"FETCH_MAX_BYTES" default:"1048576"`
	// StatusTTL is how long the service keeps a fetched status list.
	StatusTTL time.Duration `env:"STATUS_TTL" default:"5m"`
	// StatusCacheMax is the number of status lists the cache holds.
	StatusCacheMax int `env:"STATUS_CACHE_MAX" default:"64"`
	// MaxPasteBytes caps a pasted or scanned text.
	MaxPasteBytes int64 `env:"MAX_PASTE_BYTES" default:"65536"`
	// MaxBlobBytes caps one ciphertext blob of browser storage.
	MaxBlobBytes int64 `env:"MAX_BLOB_BYTES" default:"262144"`
	// PendingTTL is how long a pending offer or presentation stays
	// readable.
	PendingTTL time.Duration `env:"PENDING_TTL" default:"15m"`
	// PageSizeMax caps the page size of a list RPC.
	PageSizeMax int `env:"PAGE_SIZE_MAX" default:"50"`
	// ClientID is the client id of the wallet at the authorization server
	// of an issuer, for the sign in at the issuer (spec HO3).
	ClientID string `env:"CLIENT_ID" default:"vca-wallet"`
	// CrawlTTL is how long the wallet keeps the issuer metadata it reads
	// when the deployment runs no discovery service (spec HO1).
	CrawlTTL time.Duration `env:"CRAWL_TTL" default:"5m"`
	// CrawlAllowedHosts limits the trusted issuers the wallet reads.
	// Empty allows every host the address rules accept.
	CrawlAllowedHosts []string `env:"CRAWL_ALLOWED_HOSTS"`
	// CrawlAllowPrivateNetwork lets the wallet read a trusted issuer at a
	// private or loopback address. Turn it on for development only.
	CrawlAllowPrivateNetwork bool `env:"CRAWL_ALLOW_PRIVATE_NETWORK" default:"false"`
	// CrawlAllowPlainHTTP lets the wallet read a trusted issuer over
	// http. Turn it on for development only.
	CrawlAllowPlainHTTP bool `env:"CRAWL_ALLOW_PLAIN_HTTP" default:"false"`
	// Peers are the candidate pairs of the deployment, from VCA_PEERS.
	// The frame of the pages lists the holder pairs that run, and the
	// wallet finds its own pair by the key set of its auth service.
	Peers []topology.Peer
}

// Load reads the settings with getenv, for example os.Getenv.
func Load(getenv func(string) string) (Config, error) {
	var c Config
	if err := config.Load(Prefix, &c, getenv); err != nil {
		return Config{}, err
	}
	c.ThemeFile = strings.TrimSpace(getenv(uikit.ThemeFileEnv))
	peers, err := topology.Parse(getenv(topology.Env))
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	c.Peers = peers
	return c, c.Check()
}

// Check reports every setting that is out of range.
func (c Config) Check() error {
	var problems []string
	for _, p := range []struct {
		ok   bool
		name string
	}{
		{c.AuthJWKSTTL > 0, "AUTH_JWKS_TTL must be positive"},
		{c.DPGTimeout > 0, "DPG_TIMEOUT must be positive"},
		{c.FetchTimeout > 0, "FETCH_TIMEOUT must be positive"},
		{c.FetchMaxBytes > 0, "FETCH_MAX_BYTES must be positive"},
		{c.StatusTTL > 0, "STATUS_TTL must be positive"},
		{c.StatusCacheMax > 0, "STATUS_CACHE_MAX must be positive"},
		{c.MaxPasteBytes > 0, "MAX_PASTE_BYTES must be positive"},
		{c.MaxBlobBytes > 0, "MAX_BLOB_BYTES must be positive"},
		{c.PendingTTL > 0, "PENDING_TTL must be positive"},
		{c.PageSizeMax > 0, "PAGE_SIZE_MAX must be positive"},
		{c.CrawlTTL > 0, "CRAWL_TTL must be positive"},
		{c.CSRFKey == "" || len(c.CSRFKey) >= 16, "CSRF_KEY must have 16 bytes or more"},
	} {
		if !p.ok {
			problems = append(problems, Prefix+p.name)
		}
	}
	if _, err := c.Adapters(); err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		return fmt.Errorf("config: %s", strings.Join(problems, "; "))
	}
	return nil
}

// Adapters returns the adapter base URL per adapter name.
func (c Config) Adapters() (map[string]string, error) {
	out := map[string]string{}
	for _, item := range c.DPGAdapters {
		name, url, ok := strings.Cut(item, "=")
		name, url = strings.TrimSpace(name), strings.TrimSpace(url)
		if !ok || name == "" || url == "" {
			return nil, fmt.Errorf("%sDPG_ADAPTERS needs name=url items, got %q", Prefix, item)
		}
		out[name] = url
	}
	return out, nil
}

// HolderBackendURL returns the base URL of the selected adapter. The
// second value is false when the deployment uses browser storage.
func (c Config) HolderBackendURL() (string, bool) {
	if c.DPG == "" {
		return "", false
	}
	adapters, err := c.Adapters()
	if err != nil {
		return "", false
	}
	url, ok := adapters[c.DPG]
	return url, ok && url != ""
}

// Describe lists the variables of the service. The README uses it.
func Describe() ([]config.Variable, error) {
	return config.Describe(Prefix, &Config{})
}

// Redact returns the loaded values by variable name, secrets removed.
func (c Config) Redact() (map[string]string, error) {
	return config.Redact(Prefix, &c)
}
