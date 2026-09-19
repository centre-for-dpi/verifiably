// SPDX-License-Identifier: Apache-2.0

// Package app wires the discovery service from its configuration: the
// store, the guarded fetcher, the trust registry client, the crawler,
// the Connect handler, the catalogue endpoints, and the portal pages.
package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/crawl"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/fetch"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-discovery/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
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
	fetcher := fetch.New(fetch.Options{
		Guard: fetch.Guard{
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
		trust = trustv1connect.NewTrustServiceClient(&http.Client{Timeout: cfg.TrustTimeout}, cfg.TrustURL)
	}
	crawler, crawlErr := crawl.New(crawl.Options{Trust: trust, Fetch: fetcher, Store: st, Now: deps.Now})
	svc, serviceErr := service.New(service.Options{Store: st, Crawler: crawler, PageSizeMax: cfg.PageSizeMax, Now: deps.Now})
	pages, portalErr := portal.New(portal.Options{Client: svc, Prefix: cfg.PortalPrefix})
	assets, assetsErr := ui.Assets(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err := errors.Join(storeErr, crawlErr, serviceErr, portalErr, assetsErr); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(discoveryv1connect.NewDiscoveryServiceHandler(svc))
	httpapi.New(httpapi.Options{Reader: svc, MaxAge: cfg.CatalogMaxAge}).Register(mux)
	pages.Register(mux)
	mux.Handle("GET "+ui.Prefix, assets)
	deps.Log.Info("verifier discovery ready",
		"base_url", cfg.BaseURL, "trust_url", cfg.TrustURL, "portal", pages.Prefix(),
		"crawl_interval", cfg.CrawlInterval.String(), "cache_ttl", cfg.CacheTTL.String())
	return &App{Mux: mux, Service: svc, Crawler: crawler, Config: cfg}, nil
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
