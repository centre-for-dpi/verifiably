// SPDX-License-Identifier: Apache-2.0

// Package app wires the status-token service from its configuration:
// the store, the per issuer key rings, the securer, the list manager,
// the Connect handler, and the public HTTP endpoints.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/keys"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/lists"
	"github.com/centre-for-dpi/vc-adapters/services/internal/status/rpc"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/status-token/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/status-token/internal/securer"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *rpc.Service
	Manager *lists.Manager
	Issuers *keys.Issuers
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// ReadFile reads the signing key file. Nil means os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(ctx context.Context, cfg config.Config, deps Deps) (*App, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	if deps.ReadFile == nil {
		deps.ReadFile = os.ReadFile
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	sec := securer.New(cfg.TokenTTL, cfg.AggregationURI)
	kv, err := openStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	pem, err := readKeyFile(cfg.SigningKeyFile, deps.ReadFile)
	if err != nil {
		return nil, err
	}
	issuers, err := keys.Open(ctx, kv, keys.Options{
		Configured: cfg.IssuerDIDs, Alg: jose.Algorithm(cfg.SigningAlg), ImportPEM: pem, Now: deps.Now,
	})
	if err != nil {
		return nil, err
	}
	if issuers.Generated && cfg.SigningKeyFile == "" {
		deps.Log.Warn("no signing key file, the service generated a key",
			"setting", config.Prefix+"SIGNING_KEY_FILE", "alg", cfg.SigningAlg)
	}
	manager, err := lists.Open(ctx, lists.Options{
		Store: kv, Issuers: issuers, Securer: sec, BaseURL: cfg.BaseURL,
		Size: cfg.ListSize, TTL: cfg.ListTTL, Now: deps.Now, DefaultBits: cfg.DefaultBits,
	})
	if err != nil {
		return nil, err
	}
	svc, err := rpc.New(manager, cfg.PageSizeMax)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(statusv1connect.NewStatusServiceHandler(svc))
	httpapi.New(manager, cfg.HTTPMaxAge).Register(mux)
	deps.Log.Info("status-token ready",
		"base_url", cfg.BaseURL, "bits", cfg.DefaultBits,
		"issuer", issuers.Default().DID(), "list_size", cfg.ListSize)
	return &App{Mux: mux, Service: svc, Manager: manager, Issuers: issuers}, nil
}

// openStore returns the file store under dir, or a memory store when
// dir is empty.
func openStore(dir string) (store.KeyValue, error) {
	if dir == "" {
		return store.Memory(), nil
	}
	kv, err := store.File(dir)
	if err != nil {
		return nil, fmt.Errorf("app: open state directory: %w", err)
	}
	return kv, nil
}

// readKeyFile reads the PEM file. An empty path returns no bytes.
func readKeyFile(path string, read func(string) ([]byte, error)) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := read(path)
	if err != nil {
		return nil, fmt.Errorf("app: read signing key file: %w", err)
	}
	return data, nil
}
