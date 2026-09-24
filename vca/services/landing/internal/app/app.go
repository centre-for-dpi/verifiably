// SPDX-License-Identifier: Apache-2.0

// Package app wires the landing from its configuration: the peer prober,
// the pages, and the UI assets (ADR-033).
package app

import (
	"log/slog"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/landing/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/landing/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// App is the wired service.
type App struct {
	Mux    *http.ServeMux
	Prober *topology.Prober
	Pages  *pages.Pages
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// Prober checks the peers. Nil builds one from the configured peers
	// with the configured timeout and cache life.
	Prober *topology.Prober
	// Log receives start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Prober == nil {
		deps.Prober = &topology.Prober{Peers: cfg.Peers, TTL: cfg.ProbeTTL, Timeout: cfg.ProbeTimeout}
	}
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return nil, err
	}
	site, err := pages.New(pages.Options{
		Kit: kit, Source: deps.Prober, Version: cfg.Version, PublicURL: cfg.PublicURL,
		RepositoryURL: cfg.RepositoryURL, DocsURL: cfg.DocsURL,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET "+ui.Prefix, assets)
	site.Register(mux)
	deps.Log.Info("wired", "peers", len(cfg.Peers), "public_url", cfg.PublicURL, "version", cfg.Version)
	return &App{Mux: mux, Prober: deps.Prober, Pages: site}, nil
}
