// SPDX-License-Identifier: Apache-2.0

// Package app wires the Inji DPG adapter from its configuration.
package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
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
	// Claims writes the VCA claims store. Nil when the configuration
	// names no directory.
	Claims *claims.Writer
	// ClaimsSweep is the interval of Sweep.
	ClaimsSweep time.Duration
}

// Sweep deletes the expired rows of the claims store every interval
// until ctx ends. A write sweeps too, so a row never outlives its offer
// by more than one interval.
func (a *App) Sweep(ctx context.Context, log *slog.Logger) {
	if a.Claims == nil {
		return
	}
	ticker := time.NewTicker(a.ClaimsSweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := a.Claims.Sweep(); err != nil {
				log.Warn("the sweep of the claims store failed", "error", err)
			}
		}
	}
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
	var writer *claims.Writer
	if cfg.ClaimsDir != "" {
		writer = &claims.Writer{Dir: cfg.ClaimsDir}
	}
	verify := inji.NewVerify(dpgClient(cfg, deps, cfg.VerifyURL), cfg.VerifyClientID, cfg.VerifyURL)
	svc, err := service.New(service.Options{
		Certify:             certify,
		Verify:              verify,
		Mimoto:              inji.NewMimoto(dpgClient(cfg, deps, cfg.MimotoURL)),
		MimotoProvider:      cfg.MimotoProvider,
		InjiWebURL:          cfg.WebURL,
		Store:               backend,
		DpgVersion:          cfg.DpgVersion,
		PublicURL:           cfg.PublicURL,
		OfferIssuer:         cfg.OfferIssuer,
		AuthorizationServer: cfg.AuthorizationServer,
		OfferTTL:            cfg.OfferTTL,
		Versions:            cfg.Versions(),
		Profiles:            cfg.Profiles(),
		RenderingTemplateID: cfg.RenderingTemplateID,
		Plugins:             cfg.Plugins(),
		CADomain:            cfg.CADomain,

		Claims:            writer,
		IARIdentityClaims: cfg.IdentityClaims(),

		PresentationDuringIssuance: cfg.PresentationDuringIssuance,
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
	// Certify reads the presentation definition of a presentation during
	// issuance over HTTP on the compose network (ADR-051 decision 6).
	// The proxy does not publish it.
	mux.HandleFunc("GET /iar/presentation-definition.json", definitionHandler(svc))
	if cfg.CertifyURL != "" && cfg.PublicURL == "" {
		deps.Log.Warn("no public URL, so the authorization code channel is off",
			"setting", config.Prefix+"PUBLIC_URL")
	}
	if cfg.CertifyURL != "" && cfg.ClaimsDir == "" {
		deps.Log.Warn("no claims store, so Inji Certify has no subject to issue",
			"setting", config.Prefix+"CLAIMS_DIR")
	}
	if cfg.MimotoURL != "" && cfg.StoreFile == "" {
		deps.Log.Warn("no store file, so a restart forgets the Mimoto sessions and every holder signs in again",
			"setting", config.Prefix+"STORE_FILE")
	}
	deps.Log.Info("Inji adapter ready",
		"certify", cfg.CertifyURL != "", "verify", cfg.VerifyURL != "", "mimoto", cfg.MimotoURL != "")
	return &App{Mux: mux, Service: svc, Claims: writer, ClaimsSweep: cfg.ClaimsSweep}, nil
}

// definitionHandler serves the presentation definition that the issuer
// set, or 404 before one exists.
func definitionHandler(svc *service.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		definition, ok := svc.PresentationDefinition(r.Context())
		if !ok {
			http.Error(w, "no credential to present is configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := w.Write(definition); err != nil {
			return
		}
	}
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
