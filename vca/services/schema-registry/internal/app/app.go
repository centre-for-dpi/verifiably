// SPDX-License-Identifier: Apache-2.0

// Package app wires the schema registry from its configuration: the
// store, the SchemaService handler, the public HTTP endpoints, the staff
// portal, and the UI assets.
package app

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Portal  *portal.Portal
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// Backend registers published versions with the DPG. Nil builds a
	// Connect client from the configured backend URL.
	Backend backendv1connect.IssuerBackendServiceClient
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives start messages. Nil means slog.Default.
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
	if deps.Backend == nil && cfg.BackendURL != "" {
		deps.Backend = backendv1connect.NewIssuerBackendServiceClient(
			&http.Client{Timeout: cfg.BackendTimeout}, cfg.BackendURL)
	}
	backend := sharedstore.MemoryDoc()
	if cfg.StoreFile != "" {
		backend = sharedstore.FileDoc(cfg.StoreFile)
	}
	st, err := store.Open(backend, store.Options{})
	if err != nil {
		return nil, err
	}
	svc, err := service.New(service.Options{
		Store: st, Backend: deps.Backend, Metadata: cfg.Metadata,
		PageSizeMax: cfg.PageSizeMax, Now: deps.Now,
	})
	if err != nil {
		return nil, err
	}
	pages, err := portal.New(portal.Options{
		Client: svc, Prefix: cfg.PortalPrefix, BuilderURL: cfg.BuilderURL,
	})
	if err != nil {
		return nil, err
	}
	assets, err := ui.Assets(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(schemav1connect.NewSchemaServiceHandler(svc))
	httpapi.New(st, svc.MetadataOptions, cfg.HTTPMaxAge).Register(mux)
	pages.Register(mux)
	mux.Handle("GET "+ui.Prefix, assets)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, pages.Prefix()+"/", http.StatusSeeOther)
	})
	deps.Log.Info("wired", "portal", pages.Prefix(), "store", storeName(cfg), "backend", cfg.BackendURL != "")
	return &App{Mux: mux, Service: svc, Portal: pages}, nil
}

// storeName says where the versions live, for the start log.
func storeName(cfg config.Config) string {
	if cfg.StoreFile != "" {
		return cfg.StoreFile
	}
	return "memory"
}
