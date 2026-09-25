// SPDX-License-Identifier: Apache-2.0

// Package app wires the Inji DPG adapter from its configuration.
package app

import (
	"log/slog"
	"net/http"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// App is the wired service.
type App struct {
	// Mux serves the Connect routes and the offer endpoint.
	Mux *http.ServeMux
	// Service holds the RPC implementation.
	Service *service.Service
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// HTTP replaces the transport that calls Inji.
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
	certify := inji.NewCertify(dpgClient(cfg, deps, cfg.CertifyURL), cfg.MetadataPath)
	verify := inji.NewVerify(dpgClient(cfg, deps, cfg.VerifyURL), cfg.VerifyClientID, cfg.VerifyURL)
	svc, err := service.New(service.Options{
		Certify:             certify,
		Verify:              verify,
		Store:               backend,
		DpgVersion:          cfg.DpgVersion,
		PublicURL:           cfg.PublicURL,
		OfferIssuer:         cfg.OfferIssuer,
		AuthorizationServer: cfg.AuthorizationServer,
		OfferTTL:            cfg.OfferTTL,
		Versions:            cfg.Versions(),
		Profiles:            cfg.Profiles(),
		RenderingTemplateID: cfg.RenderingTemplateID,
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
	// The credential offer endpoint is standards defined, so it stays a
	// plain HTTP handler (ADR-003 decision 7).
	mux.HandleFunc("GET /offers/{id}", offerHandler(svc))
	if cfg.CertifyURL != "" && cfg.PublicURL == "" {
		deps.Log.Warn("no public URL, so the authorization code channel is off",
			"setting", config.Prefix+"PUBLIC_URL")
	}
	deps.Log.Info("Inji adapter ready",
		"certify", cfg.CertifyURL != "", "verify", cfg.VerifyURL != "")
	return &App{Mux: mux, Service: svc}, nil
}

// offerHandler serves one hosted credential offer to a wallet.
func offerHandler(svc *service.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		document, ok := svc.HostedOffer(r.Context(), r.PathValue("id"))
		if !ok {
			http.Error(w, "the offer does not exist or it expired", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := w.Write([]byte(document)); err != nil {
			return
		}
	}
}

// openStore returns the state store of the service.
func openStore(cfg config.Config) (store.KeyValue, error) {
	if cfg.StoreFile == "" {
		return store.Memory(), nil
	}
	return store.File(cfg.StoreFile)
}

// dpgClient returns a client for one Inji service, or nil when the
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
