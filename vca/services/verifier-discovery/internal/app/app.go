// SPDX-License-Identifier: Apache-2.0

// Package app wires the discovery service from its configuration: the
// store, the guarded fetcher, the trust registry client, the crawler,
// the Connect handler, the catalogue endpoints, and the portal pages
// behind the session guard.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	backendv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1/combinedv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/crawl"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// App is the wired service.
type App struct {
	// Mux serves every path of the service.
	Mux *http.ServeMux
	// Service is the Connect handler.
	Service *service.Service
	// Crawler reads the issuers.
	Crawler *crawl.Crawler
	// Config is the configuration the wiring used.
	Config config.Config
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// Trust calls the trust registry. Nil builds a Connect client from
	// the configured URL.
	Trust trustv1connect.TrustServiceClient
	// Client performs the issuer fetches. Nil means a client with the
	// configured timeout.
	Client *http.Client
	// SessionKeys replaces the key set of verifier-auth. Tests set it.
	SessionKeys staffsession.Keys
	// Prober replaces the probe of the peers.
	Prober *topology.Prober
	// Policy replaces the policy service client. Tests set it.
	Policy service.PolicySets
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	backend := sharedstore.Memory()
	if cfg.StateDir != "" {
		var err error
		if backend, err = sharedstore.File(cfg.StateDir); err != nil {
			return nil, err
		}
	}
	// The constructors below validate the values this wiring supplies.
	// One check reports the first fault of the whole wiring.
	st, storeErr := store.New(backend)
	fetcher := fetchguard.New(fetchguard.Options{
		Guard: fetchguard.Guard{
			AllowedHosts:        cfg.AllowedHosts,
			AllowPrivateNetwork: cfg.AllowPrivateNetwork,
			AllowPlainHTTP:      cfg.AllowPlainHTTP,
		},
		Client:   deps.Client,
		Timeout:  cfg.FetchTimeout,
		TTL:      cfg.CacheTTL,
		MaxBytes: cfg.MaxDocumentBytes,
		Now:      deps.Now,
	})
	trust := deps.Trust
	if trust == nil && cfg.TrustURL != "" {
		trust = trustv1connect.NewTrustServiceClient(cfg.Peer.Client(&http.Client{Timeout: cfg.TrustTimeout}), cfg.TrustURL)
	}
	crawler, crawlErr := crawl.New(crawl.Options{Trust: trust, Fetch: fetcher, Store: st, Now: deps.Now})
	opts := service.Options{Store: st, Crawler: crawler, PageSizeMax: cfg.PageSizeMax, Now: deps.Now, Policy: deps.Policy}
	if opts.Policy == nil && cfg.PolicyURL != "" {
		// The policy service stays on the compose network (ADR-047).
		opts.Policy = policyv1connect.NewPolicyServiceClient(cfg.Peer.Client(&http.Client{Timeout: cfg.PolicyTimeout}), cfg.PolicyURL)
	}
	svc, serviceErr := service.New(opts)
	assets, kit, _, assetsErr := uikit.LoadFile(cfg.ThemeFile)
	shell, signOut := staffshell.Wire(staffshell.Setup{
		Role: commonv1.Role_ROLE_VERIFIER, Peers: cfg.Peers, Peer: cfg.Peer, Auth: cfg.Auth, PublicURL: cfg.BaseURL,
		SignOut: cfg.PortalPrefix + "/signout", Prober: deps.Prober, Client: &http.Client{Timeout: cfg.TrustTimeout}, Now: deps.Now,
	})
	stackClient := cfg.Peer.Client(&http.Client{Timeout: cfg.TrustTimeout})
	// The combined query pages store the combined templates in the
	// combined service of the pair, on the compose network (ADR-079).
	var combined portal.CombinedTemplates
	if cfg.CombinedURL != "" {
		combined = combinedv1connect.NewCombinedServiceClient(cfg.Peer.Client(&http.Client{Timeout: cfg.PolicyTimeout}), cfg.CombinedURL)
	}
	pages, portalErr := portal.New(portal.Options{Client: svc, Prefix: cfg.PortalPrefix, Kit: kit, Shell: shell, SignOut: signOut, Combined: combined,
		ProofSchemas: ProofSchemasOf(shell, func(adapterURL string) backendv1connect.VerifierBackendServiceClient {
			return backendv1connect.NewVerifierBackendServiceClient(stackClient, adapterURL)
		})})
	guard, guardErr := staffsession.Build(cfg.Auth, staffsession.VerifierRealm(), config.Prefix, staffsession.Deps{
		Keys: deps.SessionKeys, Now: deps.Now, Log: deps.Log, MaxFormBytes: portal.MaxFormBytes,
	})
	if err := errors.Join(storeErr, crawlErr, serviceErr, portalErr, assetsErr, guardErr); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(discoveryv1connect.NewDiscoveryServiceHandler(svc, peerauth.Require(cfg.Peer)))
	httpapi.New(httpapi.Options{Reader: svc, MaxAge: cfg.CatalogMaxAge}).Register(mux)
	// The staff pages sit behind the guard. The catalogue endpoints
	// above stay open (ADR-036 decision 2).
	staff := http.NewServeMux()
	pages.Register(staff)
	mux.Handle(pages.Prefix()+"/", guard.Wrap(staff))
	mux.Handle("GET "+ui.Prefix, assets)
	deps.Log.Info("verifier discovery ready",
		"base_url", cfg.BaseURL, "trust_url", cfg.TrustURL, "portal", pages.Prefix(),
		"crawl_interval", cfg.CrawlInterval.String(), "cache_ttl", cfg.CacheTTL.String())
	return &App{Mux: mux, Service: svc, Crawler: crawler, Config: cfg}, nil
}

// proofSchemaPage is the page size the builder reads the AnonCreds
// schemas of a stack with.
const proofSchemaPage = 100

// ProofSchemasOf returns the AnonCreds schemas of each live verifier
// stack of the probe whose adapter lists FEATURE_ANONCREDS_PROOF
// (ADR-061 decision 4). A stack that does not answer adds none.
func ProofSchemasOf(shell *staffshell.Shell, client func(adapterURL string) backendv1connect.VerifierBackendServiceClient) func(context.Context) []portal.StackSchemas {
	return func(ctx context.Context) []portal.StackSchemas {
		if shell == nil {
			return nil
		}
		f := shell.Frame(ctx)
		var out []portal.StackSchemas
		for _, st := range f.Live(commonv1.Role_ROLE_VERIFIER) {
			adapter := st.Peer.Adapter()
			if adapter == "" || !hasFeature(st.Capabilities.GetFeatures(), backendv1.Feature_FEATURE_ANONCREDS_PROOF) {
				continue
			}
			resp, err := client(adapter).ListProofSchemas(ctx, connect.NewRequest(&backendv1.ListProofSchemasRequest{
				Page: &commonv1.Pagination{PageSize: proofSchemaPage},
			}))
			if err != nil {
				continue
			}
			out = append(out, portal.StackSchemas{Stack: f.Snapshot().StackName(st.Peer.Dpg), Schemas: resp.Msg.GetSchemas()})
		}
		return out
	}
}

// hasFeature reports whether a feature list holds one feature.
func hasFeature(list []backendv1.Feature, want backendv1.Feature) bool {
	for _, f := range list {
		if f == want {
			return true
		}
	}
	return false
}

// Crawl runs a crawl every CrawlInterval until ctx ends. A zero interval
// or a missing trust registry turns the job off.
func (a *App) Crawl(ctx context.Context, log *slog.Logger) {
	if a.Config.CrawlInterval <= 0 || !a.Crawler.Enabled() {
		return
	}
	ticker := time.NewTicker(a.Config.CrawlInterval)
	defer ticker.Stop()
	for {
		a.crawlOnce(ctx, log)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// crawlOnce runs one scheduled crawl and logs the result.
func (a *App) crawlOnce(ctx context.Context, log *slog.Logger) {
	res, err := a.Crawler.Run(ctx, nil)
	if err != nil {
		log.Warn("crawl failed", "error", err.Error())
		return
	}
	log.Info("crawl finished", "crawled", res.Crawled, "failed", len(res.Failed))
}
