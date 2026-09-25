// SPDX-License-Identifier: Apache-2.0

// Package app wires the walt.id DPG adapter from its configuration.
package app

import (
	"log/slog"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-waltid/internal/waltid"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// App is the wired service.
type App struct {
	// Mux serves every Connect route of the adapter.
	Mux *http.ServeMux
	// Service holds the RPC implementation.
	Service *service.Service
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// HTTP replaces the transport that calls walt.id.
	HTTP *http.Client
	// Store replaces the state store.
	Store store.KeyValue
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the adapter from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	backend := deps.Store
	if backend == nil {
		var err error
		if backend, err = openStore(cfg); err != nil {
			return nil, err
		}
	}
	client := waltid.New(waltid.Options{
		Issuer:          dpgClient(cfg, deps, cfg.IssuerURL),
		Verifier:        dpgClient(cfg, deps, cfg.VerifierURL),
		Wallet:          dpgClient(cfg, deps, cfg.WalletURL),
		StandardVersion: cfg.StandardVersion,
		IssuerKey:       cfg.IssuerKey,
		IssuerDid:       cfg.IssuerDid,
	})
	svc, err := service.New(service.Options{
		Client:          client,
		Store:           backend,
		DpgVersion:      cfg.DpgVersion,
		StandardVersion: cfg.StandardVersion,
		VctBase:         cfg.VctBase,
		Versions:        cfg.Versions(),
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(svc))
	mux.Handle(backendv1connect.NewIssuerBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewHolderBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewVerifierBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewCatalogBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewTenantBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewNotificationBackendServiceHandler(svc))
	deps.Log.Info("walt.id adapter ready",
		"issuer", cfg.IssuerURL != "", "verifier", cfg.VerifierURL != "", "wallet", cfg.WalletURL != "")
	return &App{Mux: mux, Service: svc}, nil
}

// openStore returns the state store of the service.
func openStore(cfg config.Config) (store.KeyValue, error) {
	if cfg.StoreFile == "" {
		return store.Memory(), nil
	}
	return store.File(cfg.StoreFile)
}

// dpgClient returns a client for one walt.id service, or nil when the
// configuration names no URL for it.
func dpgClient(cfg config.Config, deps Deps, baseURL string) *dpgclient.Client {
	if baseURL == "" {
		return nil
	}
	return dpgclient.New(dpgclient.Options{
		BaseURL:  baseURL,
		Timeout:  cfg.Timeout,
		Retries:  cfg.Retries,
		MaxBytes: cfg.MaxBytes,
		HTTP:     deps.HTTP,
	})
}
