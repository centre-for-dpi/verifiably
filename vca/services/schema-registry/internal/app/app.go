// SPDX-License-Identifier: Apache-2.0

// Package app wires the schema registry from its configuration: the
// store, the SchemaService handler, the public HTTP endpoints, the staff
// portal behind the session guard, and the UI assets.
package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/peerauth"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/schema-registry/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Portal  *portal.Portal
	log     *slog.Logger
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// Backend registers published versions with the DPG. Nil builds a
	// Connect client from the configured backend URL.
	Backend backendv1connect.IssuerBackendServiceClient
	// SessionKeys replaces the key set of issuer-auth. Tests set it.
	SessionKeys staffsession.Keys
	// Issued counts the issued credentials of each schema. Nil builds a
	// Connect client from the configured issued URL, when there is one.
	Issued portal.Issued
	// Sources reads the data sources of the pair. Nil builds a Connect
	// client from the configured data source URL, when there is one.
	Sources portal.Sources
	// Prober replaces the probe of the peers of the issuer shell.
	Prober *topology.Prober
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
			cfg.Peer.Client(&http.Client{Timeout: cfg.BackendTimeout}), cfg.BackendURL)
	}
	if deps.Issued == nil && cfg.IssuedURL != "" {
		deps.Issued = issuedv1connect.NewIssuedServiceClient(
			cfg.Peer.Client(&http.Client{Timeout: cfg.BackendTimeout}), cfg.IssuedURL)
	}
	if deps.Sources == nil && cfg.DataSourceURL != "" {
		deps.Sources = datasourcev1connect.NewDataSourceServiceClient(
			cfg.Peer.Client(&http.Client{Timeout: cfg.BackendTimeout}), cfg.DataSourceURL)
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
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return nil, err
	}
	shell, signOut := staffshell.Wire(staffshell.Setup{
		Role: commonv1.Role_ROLE_ISSUER, Peers: cfg.Peers, Peer: cfg.Peer, Auth: cfg.Auth, PublicURL: cfg.BaseURL,
		SignOut: cfg.PortalPrefix + "/signout", Prober: deps.Prober, Now: deps.Now,
	})
	popts := portal.Options{
		Client: svc, Prefix: cfg.PortalPrefix, BuilderURL: cfg.BuilderURL, Kit: kit,
		Shell: shell, SignOut: signOut, Issued: deps.Issued,
	}
	if deps.Backend != nil {
		// The detail page shows the card templates of the stack, and the
		// tab "Claims by sign in" stores the source of a claim without an
		// offer on the adapter (ADR-052 decision 3).
		popts.Catalog = deps.Backend
		popts.SignIn = deps.Backend
	}
	if deps.Sources != nil {
		popts.Sources = deps.Sources
	}
	pages, err := portal.New(popts)
	if err != nil {
		return nil, err
	}
	guard, err := staffsession.Build(cfg.Auth, staffsession.IssuerRealm(), config.Prefix, staffsession.Deps{
		Keys: deps.SessionKeys, Now: deps.Now, Log: deps.Log,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(schemav1connect.NewSchemaServiceHandler(svc, peerauth.Require(cfg.Peer)))
	httpapi.New(st, svc.MetadataOptions, cfg.HTTPMaxAge).Register(mux)
	// The staff pages sit behind the guard. The public documents above
	// stay open (ADR-036 decision 2).
	staff := http.NewServeMux()
	pages.Register(staff)
	mux.Handle(pages.Prefix()+"/", guard.Wrap(staff))
	mux.Handle("GET "+ui.Prefix, assets)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, pages.Prefix()+"/", http.StatusSeeOther)
	})
	deps.Log.Info("wired", "portal", pages.Prefix(), "store", storeName(cfg), "backend", cfg.BackendURL != "")
	return &App{Mux: mux, Service: svc, Portal: pages, log: deps.Log}, nil
}

// Republish registers every published version with the stack again,
// once at the start of the registry (ADR-077). The adapter can start
// after the registry, so a run that the stack refuses waits every and
// tries again. It returns when every version went, or when ctx ends.
func (a *App) Republish(ctx context.Context, every time.Duration) error {
	for {
		n, err := a.Service.Republish(ctx)
		if err == nil {
			a.log.Info("registered every published version with the stack again", "versions", n)
			return nil
		}
		a.log.Warn("the stack refused a registration, so the registry tries again", "error", err, "wait", every.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}

// storeName says where the versions live, for the start log.
func storeName(cfg config.Config) string {
	if cfg.StoreFile != "" {
		return cfg.StoreFile
	}
	return "memory"
}
