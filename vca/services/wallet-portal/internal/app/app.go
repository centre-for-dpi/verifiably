// SPDX-License-Identifier: Apache-2.0

// Package app wires the wallet portal service from its configuration:
// the session middleware, the holder backend client, the catalogue
// client, the trust lookup, the eligibility hook, the card builder, the
// Connect handler, the citizen pages, and the browser storage
// endpoints.
package app

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	walletauthv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1/walletauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletportal/v1/walletportalv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/blobs"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/cards"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/issuers"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/present"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/session"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-portal/internal/static"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// App is the wired service.
type App struct {
	// Mux serves the RPCs, the pages, and the assets.
	Mux *http.ServeMux
	// Service answers the RPCs.
	Service *service.Service
	// Portal renders the citizen pages.
	Portal *portal.Portal
	// Blobs holds the ciphertext of browser storage. It is nil when the
	// deployment uses a DPG wallet.
	Blobs *blobs.Store
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// HTTP is the outbound client. Nil builds one with the configured
	// timeout.
	HTTP *http.Client
	// ConnectClient calls the other services. Nil builds a client.
	ConnectClient connect.HTTPClient
	// Holder replaces the holder backend client. Tests set it.
	Holder backendv1connect.HolderBackendServiceClient
	// Catalogue replaces the catalogue client. Tests set it.
	Catalogue ports.Catalogue
	// Trust replaces the trust registry client. Tests set it.
	Trust trustv1connect.TrustServiceClient
	// ReadFile reads the JWKS file. Nil means os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Snapshot replaces the probe of the peers. Tests set it. Nil builds a
	// prober when the deployment names peers.
	Snapshot func(ctx context.Context) topology.Snapshot
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	deps = deps.withDefaults(cfg)
	kv, err := keyValue(cfg)
	if err != nil {
		return nil, err
	}
	verify, err := verifier(cfg, deps)
	if err != nil {
		return nil, err
	}
	guard, err := newGuard(cfg)
	if err != nil {
		return nil, err
	}
	catalogue := catalogue(cfg, deps)
	trustLookup := ports.Trust(trustClient(cfg, deps), commonv1.Role_ROLE_ISSUER)
	fetch := ports.NewCache(cfg.StatusTTL, cfg.StatusCacheMax, deps.Now).
		Wrap(ports.HTTPFetcher(deps.HTTP, cfg.FetchMaxBytes))
	eligible, err := eligibility(cfg, deps)
	if err != nil {
		return nil, err
	}
	holder := holderClient(cfg, deps)
	snapshot := probe(cfg, deps)
	crawl, err := issuers.New(issuers.Options{
		Peers: peerSources(snapshot), Trust: trustClient(cfg, deps), Lookup: trustLookup,
		Internal: internalFetcher(cfg, deps), Public: publicFetcher(cfg, deps),
	})
	if err != nil {
		return nil, err
	}
	svc, err := service.New(service.Options{
		Holder:    holder,
		Catalogue: catalogue,
		Fallback:  ports.Cached(crawl, cfg.CrawlTTL, deps.Now),
		Methods:   crawl.Methods,
		Eligible:  eligible,
		Salt:      cfg.EligibilitySalt,
		Cards: cards.New(cards.Options{
			Trust: trustLookup, Status: cards.Fetcher(fetch),
			Display: ports.DisplayOf(catalogue), Now: deps.Now,
		}),
		Trust:         trustLookup,
		Store:         kv,
		Fetch:         present.Fetcher(fetch),
		Post:          ports.FormPoster(deps.HTTP, cfg.FetchMaxBytes),
		RequestHosts:  cfg.RequestHosts,
		PageSizeMax:   cfg.PageSizeMax,
		MaxPasteBytes: cfg.MaxPasteBytes,
		PendingTTL:    cfg.PendingTTL,
		Now:           deps.Now,
	})
	if err != nil {
		return nil, err
	}
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return nil, err
	}
	pages, err := portal.New(portal.Options{
		Service: svc, Guard: guard, Prefix: cfg.PortalPrefix,
		LoginPath: cfg.LoginURL, Now: deps.Now, Kit: kit, Topology: frame(cfg, deps, snapshot),
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(walletportalv1connect.NewWalletPortalServiceHandler(svc,
		connect.WithInterceptors(session.Interceptor(verify))))
	mux.Handle("GET "+ui.Prefix, assets)
	app := &App{Mux: mux, Service: svc, Portal: pages}
	guarded := http.NewServeMux()
	pages.Register(guarded)
	if svc.BrowserStorage() {
		st, berr := blobs.NewStore(kv, cfg.MaxBlobBytes, deps.Now)
		if berr != nil {
			return nil, berr
		}
		api, berr := blobs.NewAPI(st, pages.Prefix(), guard)
		if berr != nil {
			return nil, berr
		}
		api.Register(guarded)
		app.Blobs = st
	}
	mux.Handle("GET "+pages.Prefix()+static.Path, pages.Script())
	mux.Handle(pages.Prefix()+"/", session.Middleware(verify, cfg.LoginURL)(guarded))
	warn(cfg, deps, svc)
	deps.Log.Info("wallet portal ready",
		"portal", pages.Prefix(), "browser_storage", svc.BrowserStorage(),
		"state_dir", cfg.StateDir, "dpg", cfg.DPG)
	return app, nil
}

// frame returns the topology of the holder frame: the peers, their
// probe, the own pair by the key set of wallet-auth, and the logout call
// of the sign out form (ADR-034, ADR-044 decision 5).
func frame(cfg config.Config, deps Deps, snapshot func(context.Context) topology.Snapshot) portal.Topology {
	secure := false
	for _, p := range cfg.Peers {
		if auth := p.Auth(); auth != "" && strings.TrimRight(auth, "/")+"/.well-known/jwks.json" == cfg.AuthJWKSURL {
			secure = strings.HasPrefix(p.PublicURL, "https://")
		}
	}
	client := deps.ConnectClient
	return portal.Topology{
		Peers: cfg.Peers, Snapshot: snapshot, JWKSURL: cfg.AuthJWKSURL, SecureCookie: secure,
		Logout: func(ctx context.Context, authURL, token string) (string, error) {
			c := walletauthv1connect.NewWalletAuthServiceClient(client, authURL)
			res, err := c.Logout(ctx, connect.NewRequest(&walletauthv1.LogoutRequest{SessionToken: token}))
			if err != nil {
				return "", err
			}
			return res.Msg.GetProviderLogoutUrl(), nil
		},
	}
}

// probe returns the snapshot of the peers: the one of the test, a
// prober when the deployment names peers, or nil.
func probe(cfg config.Config, deps Deps) func(context.Context) topology.Snapshot {
	if deps.Snapshot != nil {
		return deps.Snapshot
	}
	if len(cfg.Peers) == 0 {
		return nil
	}
	return (&topology.Prober{Peers: cfg.Peers, Now: deps.Now}).Snapshot
}

// registryService is the service of an issuer pair that serves the
// issuer metadata.
const registryService = "schema-registry"

// peerSources returns the live issuer pairs that serve issuer metadata,
// with the channels their adapters list (spec HO1).
func peerSources(snapshot func(context.Context) topology.Snapshot) func(context.Context) []issuers.Source {
	if snapshot == nil {
		return nil
	}
	return func(ctx context.Context) []issuers.Source {
		var out []issuers.Source
		for _, st := range snapshot(ctx).Live() {
			registry := st.Peer.Services[registryService]
			if st.Peer.Role != commonv1.Role_ROLE_ISSUER || registry == "" {
				continue
			}
			out = append(out, issuers.Source{
				Endpoint: registry, Public: st.Peer.PublicURL, Peer: true, Channels: st.Capabilities.GetChannels(),
			})
		}
		return out
	}
}

// internalFetcher reads the metadata of the live issuer pairs on the
// compose network. It reaches only the registry hosts the operator names
// in VCA_PEERS, so the private address rule can stay off.
func internalFetcher(cfg config.Config, deps Deps) issuers.Getter {
	var hosts []string
	for _, p := range cfg.Peers {
		if u, err := url.Parse(p.Services[registryService]); err == nil && p.Role == commonv1.Role_ROLE_ISSUER && u.Hostname() != "" {
			hosts = append(hosts, u.Hostname())
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	return fetchguard.New(fetchguard.Options{
		Guard:  fetchguard.Guard{AllowedHosts: hosts, AllowPrivateNetwork: true, AllowPlainHTTP: true},
		Client: deps.HTTP, TTL: cfg.CrawlTTL, MaxBytes: int(cfg.FetchMaxBytes), Now: deps.Now,
	})
}

// publicFetcher reads the metadata of a trusted issuer and of an
// authorization server under the address rules of the deployment.
func publicFetcher(cfg config.Config, deps Deps) issuers.Getter {
	return fetchguard.New(fetchguard.Options{
		Guard: fetchguard.Guard{
			AllowedHosts: cfg.CrawlAllowedHosts, AllowPrivateNetwork: cfg.CrawlAllowPrivateNetwork,
			AllowPlainHTTP: cfg.CrawlAllowPlainHTTP,
		},
		Client: deps.HTTP, TTL: cfg.CrawlTTL, MaxBytes: int(cfg.FetchMaxBytes), Now: deps.Now,
	})
}

// withDefaults fills the side effects the caller left empty.
func (d Deps) withDefaults(cfg config.Config) Deps {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.ReadFile == nil {
		d.ReadFile = os.ReadFile
	}
	if d.HTTP == nil {
		d.HTTP = &http.Client{Timeout: cfg.FetchTimeout}
	}
	if d.ConnectClient == nil {
		d.ConnectClient = &http.Client{Timeout: cfg.DPGTimeout}
	}
	return d
}

// keyValue returns the store of the pending records and the blobs.
func keyValue(cfg config.Config) (store.KeyValue, error) {
	if cfg.StateDir == "" {
		return store.Memory(), nil
	}
	return store.File(cfg.StateDir)
}

// verifier returns the session verifier of the wallet authentication
// service (ADR-020 decision 2).
func verifier(cfg config.Config, deps Deps) (session.Verifier, error) {
	var keys session.Keys
	switch {
	case cfg.AuthJWKSFile != "":
		raw, err := deps.ReadFile(cfg.AuthJWKSFile)
		if err != nil {
			return nil, fmt.Errorf("app: read %s: %w", config.Prefix+"AUTH_JWKS_FILE", err)
		}
		set, err := jose.ParseJWKS(raw)
		if err != nil {
			return nil, err
		}
		keys = session.StaticKeys(set)
	case cfg.AuthJWKSURL != "":
		keys = session.CachedKeys(cfg.AuthJWKSURL, cfg.AuthJWKSTTL,
			ports.Fetcher(ports.HTTPFetcher(deps.HTTP, cfg.FetchMaxBytes)), deps.Now)
	default:
		return nil, fmt.Errorf("app: set %sAUTH_JWKS_URL or %sAUTH_JWKS_FILE",
			config.Prefix, config.Prefix)
	}
	return session.NewVerifier(session.Options{Keys: keys, Issuer: cfg.AuthIssuer, Now: deps.Now})
}

// newGuard returns the synchronizer token guard. An empty key makes a
// random key, which is fine for one replica.
func newGuard(cfg config.Config) (session.Guard, error) {
	key := []byte(cfg.CSRFKey)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return session.Guard{}, fmt.Errorf("app: read random bytes: %w", err)
		}
	}
	return session.NewGuard(key)
}

// catalogue returns the catalogue client of the discovery service.
func catalogue(cfg config.Config, deps Deps) ports.Catalogue {
	if deps.Catalogue != nil {
		return deps.Catalogue
	}
	if cfg.DiscoveryURL == "" {
		return nil
	}
	client := discoveryv1connect.NewDiscoveryServiceClient(deps.ConnectClient, cfg.DiscoveryURL)
	cat, err := ports.NewCatalogue(client, cfg.PageSizeMax)
	if err != nil {
		return nil
	}
	return ports.Cached(cat, cfg.StatusTTL, deps.Now)
}

// trustClient returns the trust registry client.
func trustClient(cfg config.Config, deps Deps) trustv1connect.TrustServiceClient {
	if deps.Trust != nil {
		return deps.Trust
	}
	if cfg.TrustURL == "" {
		return nil
	}
	return trustv1connect.NewTrustServiceClient(deps.ConnectClient, cfg.TrustURL)
}

// holderClient returns the holder backend client of the chosen adapter
// (ADR-021 decision 3). A deployment with no adapter keeps the
// credentials in the browser (decision 4).
func holderClient(cfg config.Config, deps Deps) backendv1connect.HolderBackendServiceClient {
	if deps.Holder != nil {
		return deps.Holder
	}
	url, ok := cfg.HolderBackendURL()
	if !ok {
		return nil
	}
	return backendv1connect.NewHolderBackendServiceClient(deps.ConnectClient, url)
}

// eligibility returns the hook that answers yes or no per schema
// (ADR-021 decision 2).
func eligibility(cfg config.Config, deps Deps) (ports.Eligibility, error) {
	if cfg.EligibilityURL == "" {
		return ports.StaticEligibility(cfg.EligibilityDefault), nil
	}
	return ports.HTTPEligibility(cfg.EligibilityURL, ports.HTTPPoster(deps.HTTP, cfg.FetchMaxBytes))
}

// warn writes one log line per setting an operator left empty.
func warn(cfg config.Config, deps Deps, svc *service.Service) {
	if cfg.DiscoveryURL == "" && deps.Catalogue == nil {
		deps.Log.Warn("no discovery service, the wallet reads the metadata of the issuers itself",
			"setting", config.Prefix+"DISCOVERY_URL")
	}
	if cfg.TrustURL == "" && deps.Trust == nil {
		deps.Log.Warn("no trust registry, every trust answer is not checked",
			"setting", config.Prefix+"TRUST_URL")
	}
	if len(cfg.RequestHosts) == 0 {
		deps.Log.Warn("no request host allowlist, the wallet blocks every presentation request",
			"setting", config.Prefix+"REQUEST_HOSTS")
	}
	if svc.BrowserStorage() {
		deps.Log.Warn("no holder backend, the browser keeps the credentials",
			"setting", config.Prefix+"DPG")
	}
	if cfg.EligibilityURL == "" && cfg.EligibilityDefault {
		deps.Log.Warn("no eligibility hook, every citizen sees every credential as claimable",
			"setting", config.Prefix+"ELIGIBILITY_URL")
	}
}

// Ready reports whether the service can take traffic.
func (a *App) Ready() bool { return a != nil && a.Service.Ready() }
