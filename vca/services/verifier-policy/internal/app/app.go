// SPDX-License-Identifier: Apache-2.0

// Package app wires the verifier policy service from its configuration:
// the policy set store, the cached fetchers, the DID resolver, the trust
// registry client, and the Connect handler.
package app

import (
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/did"
	"github.com/centre-for-dpi/vc-adapters/core/policy"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/policy/v1/policyv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/ports"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-policy/internal/sets"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Sets    *sets.Store
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// HTTPClient fetches DID documents, status lists, and schemas.
	// Nil builds a client with the configured timeout.
	HTTPClient *http.Client
	// ConnectClient calls the trust registry. Nil uses HTTPClient.
	ConnectClient connect.HTTPClient
	// Trust replaces the trust registry client. Tests set it.
	Trust trustv1connect.TrustServiceClient
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
	if deps.HTTPClient == nil {
		deps.HTTPClient = &http.Client{Timeout: cfg.FetchTimeout}
	}
	kv := store.Memory()
	if cfg.StateDir != "" {
		var err error
		if kv, err = store.File(cfg.StateDir); err != nil {
			return nil, err
		}
	}
	setStore := sets.New(kv, nil)

	fetch := ports.NewCache(cfg.CacheTTL, cfg.CacheEntries, deps.Now).
		Wrap(ports.HTTPFetcher(deps.HTTPClient, cfg.FetchMaxBytes))
	resolver := did.NewResolver(did.Fetcher(fetch), ports.NewDIDCache(cfg.CacheTTL, deps.Now))

	trust := deps.Trust
	if trust == nil && cfg.TrustURL != "" {
		trust = trustv1connect.NewTrustServiceClient(connectClient(cfg, deps), cfg.TrustURL)
	}

	svc, err := service.New(service.Options{
		Sets: setStore,
		Ports: policy.Context{
			Leeway:  cfg.Leeway,
			Keys:    ports.Keys(resolver, fetch),
			Status:  fetch,
			Schemas: fetch,
			Trust:   ports.Trust(trust),
		},
		DefaultSetID:   cfg.DefaultPolicySet,
		Audience:       cfg.Audience,
		StatusFailMode: cfg.StatusFailMode,
		PageSizeMax:    cfg.PageSizeMax,
		Now:            deps.Now,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(policyv1connect.NewPolicyServiceHandler(svc))
	if trust == nil {
		deps.Log.Warn("no trust registry, the trust chain check reports an error",
			"setting", config.Prefix+"TRUST_URL")
	}
	if cfg.Audience == "" {
		deps.Log.Warn("no audience, the audience check is skipped unless a request names one",
			"setting", config.Prefix+"AUDIENCE")
	}
	deps.Log.Info("verifier policy ready",
		"state_dir", cfg.StateDir, "default_policy_set", cfg.DefaultPolicySet,
		"status_fail_mode", cfg.StatusFailMode, "checks", len(policy.Checks()))
	return &App{Mux: mux, Service: svc, Sets: setStore}, nil
}

// connectClient returns the client that calls the trust registry.
func connectClient(cfg config.Config, deps Deps) connect.HTTPClient {
	if deps.ConnectClient != nil {
		return deps.ConnectClient
	}
	return &http.Client{Timeout: cfg.TrustTimeout}
}
