// SPDX-License-Identifier: Apache-2.0

// Package app wires the verifier combined service from its
// configuration: the combined template store, the policy client, the
// discovery client, the results client, and the Connect handler.
package app

import (
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/combined/v1/combinedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/discovery/v1/discoveryv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/results/v1/resultsv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/combos"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-combined/internal/service"
)

// App is the wired service.
type App struct {
	Mux       *http.ServeMux
	Service   *service.Service
	Templates *combos.Store
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// ConnectClient calls the other services. Nil builds a client with
	// the configured timeout.
	ConnectClient connect.HTTPClient
	// Policy, Discovery, and Results replace the service clients. Tests
	// set them.
	Policy    policyv1connect.PolicyServiceClient
	Discovery discoveryv1connect.DiscoveryServiceClient
	Results   resultsv1connect.ResultsServiceClient
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
	templates := combos.New(kv, nil)
	client := connectClient(cfg, deps)
	policy := deps.Policy
	if policy == nil && cfg.PolicyURL != "" {
		policy = policyv1connect.NewPolicyServiceClient(client, cfg.PolicyURL)
	}
	discovery := deps.Discovery
	if discovery == nil && cfg.DiscoveryURL != "" {
		discovery = discoveryv1connect.NewDiscoveryServiceClient(client, cfg.DiscoveryURL)
	}
	results := deps.Results
	if results == nil && cfg.ResultsURL != "" {
		results = resultsv1connect.NewResultsServiceClient(client, cfg.ResultsURL)
	}
	svc, err := service.New(service.Options{
		Templates:        templates,
		Policy:           policy,
		Discovery:        discovery,
		Results:          results,
		DefaultPolicySet: cfg.DefaultPolicySet,
		PageSizeMax:      cfg.PageSizeMax,
		Now:              deps.Now,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(combinedv1connect.NewCombinedServiceHandler(svc))
	if policy == nil {
		deps.Log.Warn("no policy service, EvaluateCombined reports a failed precondition",
			"setting", config.Prefix+"POLICY_URL")
	}
	if discovery == nil {
		deps.Log.Warn("no discovery service, BuildDcql reports a failed precondition",
			"setting", config.Prefix+"DISCOVERY_URL")
	}
	if results == nil {
		deps.Log.Warn("no results service, a combined result is not stored",
			"setting", config.Prefix+"RESULTS_URL")
	}
	deps.Log.Info("verifier combined ready", "state_dir", cfg.StateDir)
	return &App{Mux: mux, Service: svc, Templates: templates}, nil
}

// connectClient returns the client that calls the other services.
func connectClient(cfg config.Config, deps Deps) connect.HTTPClient {
	if deps.ConnectClient != nil {
		return deps.ConnectClient
	}
	return &http.Client{Timeout: cfg.CallTimeout}
}
