// SPDX-License-Identifier: Apache-2.0

// Package app wires the CREDEBL DPG adapter from its configuration.
package app

import (
	"log/slog"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/credebl"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-credebl/internal/service"
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
	// HTTP replaces the transport that calls CREDEBL.
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
	client := credebl.New(credebl.Options{
		HTTP: dpgclient.New(dpgclient.Options{
			BaseURL:  cfg.APIURL,
			Timeout:  cfg.Timeout,
			Retries:  cfg.Retries,
			MaxBytes: cfg.MaxBytes,
			HTTP:     deps.HTTP,
		}),
		Account: credebl.Account{
			Email:     cfg.Email,
			Password:  cfg.Password,
			CryptoKey: cfg.CryptoKey,
		},
		OrgID:    cfg.OrgID,
		IssuerID: cfg.IssuerID,
	})
	svc, err := service.New(service.Options{
		Client:       client,
		Store:        backend,
		DpgVersion:   cfg.DpgVersion,
		VerifierID:   cfg.VerifierID,
		VerifierName: cfg.VerifierName,
		PublicURL:    cfg.PublicURL,
		InternalURL:  cfg.InternalURL,
		DefaultPin:   cfg.DefaultPin,
		Versions:     cfg.Versions(),
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
	if cfg.PublicURL == "" || cfg.InternalURL == "" {
		deps.Log.Warn("no public host rewrite, so a wallet outside the deployment may not reach an offer",
			"settings", config.Prefix+"PUBLIC_URL and "+config.Prefix+"INTERNAL_URL")
	}
	deps.Log.Info("CREDEBL adapter ready", "org", cfg.OrgID, "issuer", cfg.IssuerID)
	return &App{Mux: mux, Service: svc}, nil
}

// openStore returns the state store of the service.
func openStore(cfg config.Config) (store.KeyValue, error) {
	if cfg.StoreFile == "" {
		return store.Memory(), nil
	}
	return store.File(cfg.StoreFile)
}
