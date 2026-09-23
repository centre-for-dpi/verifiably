// SPDX-License-Identifier: Apache-2.0

// Package app wires the schema builder from its configuration: the
// SchemaBuilderService handler, the builder pages, the PDF preview
// handler, and the UI assets.
package app

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schemabuilder/v1/schemabuilderv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/pdfcache"
	"github.com/centre-for-dpi/vc-adapters/services/schema-builder-ui/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Pages   *pages.Pages
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// Registry saves the drafts. Nil builds a Connect client from the
	// configured registry URL.
	Registry schemav1connect.SchemaServiceClient
	// Catalog reads the DPG credential types. Nil builds a Connect client
	// from the configured catalogue URL, when there is one.
	Catalog backendv1connect.CatalogBackendServiceClient
	// Log receives start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Registry == nil {
		if cfg.RegistryURL == "" {
			return nil, errors.New("app: the configuration names no schema registry")
		}
		deps.Registry = schemav1connect.NewSchemaServiceClient(
			&http.Client{Timeout: cfg.RegistryTimeout}, cfg.RegistryURL)
	}
	if deps.Catalog == nil && cfg.CatalogURL != "" {
		deps.Catalog = backendv1connect.NewCatalogBackendServiceClient(
			&http.Client{Timeout: cfg.CatalogTimeout}, cfg.CatalogURL)
	}
	svc, svcErr := service.New(service.Options{
		Registry: deps.Registry, Catalog: deps.Catalog,
		PDF: pdfcache.New(cfg.PDFCacheSize), Issuer: cfg.Issuer,
	})
	assets, kit, _, assetsErr := uikit.LoadFile(cfg.ThemeFile)
	builder, pagesErr := pages.New(pages.Options{
		Builder: svc, Registry: deps.Registry, Prefix: cfg.Prefix,
		RegistryURL: cfg.PortalURL, Catalog: deps.Catalog != nil, Kit: kit,
	})
	if err := first(svcErr, assetsErr, pagesErr); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(schemabuilderv1connect.NewSchemaBuilderServiceHandler(svc))
	builder.Register(mux)
	svc.Cache().Register(mux)
	mux.Handle("GET "+ui.Prefix, assets)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, builder.Prefix()+"/", http.StatusSeeOther)
	})
	deps.Log.Info("wired", "pages", builder.Prefix(), "registry", cfg.RegistryURL, "catalog", deps.Catalog != nil)
	return &App{Mux: mux, Service: svc, Pages: builder}, nil
}

// first returns the first error of the list, or nil. The wiring builds
// every part, then checks the parts once.
func first(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
