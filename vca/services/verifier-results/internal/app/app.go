// SPDX-License-Identifier: Apache-2.0

// Package app wires the verifier results service from its
// configuration: the result store, the Connect handler, the staff
// portal, the citizen check page, and the purge job.
package app

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	resultsv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/check"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/results"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-results/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Store   *results.Store
	Portal  *portal.Portal
	// PurgeInterval is the time between two purge runs. Zero turns the
	// scheduled job off.
	PurgeInterval time.Duration
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// ConnectClient calls the policy service. Nil builds a client with
	// the configured timeout.
	ConnectClient connect.HTTPClient
	// Policy replaces the policy service client. Tests set it.
	Policy policyv1connect.PolicyServiceClient
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	kv := store.Memory()
	if cfg.StateDir != "" {
		var err error
		if kv, err = store.File(cfg.StateDir); err != nil {
			return nil, err
		}
	}
	st := results.New(kv, nil)
	svc, err := service.New(service.Options{
		Store:        st,
		Retention:    cfg.Retention,
		RawRetention: cfg.RawRetention,
		PageSizeMax:  cfg.PageSizeMax,
		Now:          deps.Now,
	})
	if err != nil {
		return nil, err
	}
	policyClient := deps.Policy
	if policyClient == nil && cfg.PolicyURL != "" {
		policyClient = policyv1connect.NewPolicyServiceClient(connectClient(cfg, deps), cfg.PolicyURL)
	}
	var evaluate portal.Evaluator
	if policyClient != nil {
		evaluate = func(ctx context.Context, payload []byte) (*resultsv1.VerificationResult, error) {
			return check.Evaluate(ctx, check.Options{Client: policyClient, Now: deps.Now}, payload)
		}
	}
	pages, err := portal.New(portal.Options{
		Service:       svc,
		Prefix:        cfg.PortalPrefix,
		PublicPrefix:  cfg.PublicPrefix,
		Evaluate:      evaluate,
		MaxPasteBytes: cfg.MaxPasteBytes,
		Now:           deps.Now,
	})
	if err != nil {
		return nil, err
	}
	assets, err := ui.Assets(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(resultsv1connect.NewResultsServiceHandler(svc))
	mux.Handle("GET "+ui.Prefix, assets)
	pages.Register(mux)
	if policyClient == nil {
		deps.Log.Warn("no policy service, the citizen check page is not available",
			"setting", config.Prefix+"POLICY_URL")
	}
	deps.Log.Info("verifier results ready",
		"state_dir", cfg.StateDir, "retention", cfg.Retention.String(),
		"raw_retention", cfg.RawRetention.String(), "portal", pages.Prefix())
	return &App{
		Mux: mux, Service: svc, Store: st, Portal: pages, PurgeInterval: cfg.PurgeInterval,
	}, nil
}

// connectClient returns the client that calls the policy service.
func connectClient(cfg config.Config, deps Deps) connect.HTTPClient {
	if deps.ConnectClient != nil {
		return deps.ConnectClient
	}
	return &http.Client{Timeout: cfg.PolicyTimeout}
}

// Purge runs the retention job until ctx ends (ADR-025 decision 3). A
// zero interval returns at once.
func (a *App) Purge(ctx context.Context, log *slog.Logger) {
	if a.PurgeInterval <= 0 {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(a.PurgeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			counts, err := a.Service.PurgeNow(ctx)
			if err != nil {
				log.Error("purge failed", "error", err)
				continue
			}
			if counts.GetRawDeleted() > 0 || counts.GetResultsDeleted() > 0 {
				log.Info("purged personal data",
					"raw", counts.GetRawDeleted(), "results", counts.GetResultsDeleted())
			}
		}
	}
}
