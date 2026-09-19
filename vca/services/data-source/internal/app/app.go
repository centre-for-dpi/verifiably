// SPDX-License-Identifier: Apache-2.0

// Package app wires the data source service from its configuration:
// store, secret resolver, source readers, the SSRF guard, the role
// interceptor, and the Connect handler.
package app

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/core/jose"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/httpsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/reader"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/sqlsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/store"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Store   *store.Store
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// Getenv reads secret values of the env store. Nil means os.Getenv.
	Getenv func(string) string
	// ReadFile reads CSV files, file secrets, and the JWKS file.
	// Nil means os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.Getenv == nil {
		deps.Getenv = os.Getenv
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
	backend := sharedstore.MemoryDoc()
	if cfg.StoreFile != "" {
		backend = sharedstore.FileDoc(cfg.StoreFile)
	}
	st, err := store.Open(backend)
	if err != nil {
		return nil, err
	}
	rd := reader.Reader{
		Secrets: secrets.Resolver{Getenv: deps.Getenv, ReadFile: deps.ReadFile, Dir: cfg.SecretsDir},
		HTTP: httpsrc.Fetcher{
			Guard: httpsrc.Guard{
				AllowHosts:   cfg.AllowHosts,
				AllowHTTP:    cfg.AllowHTTP,
				AllowPrivate: cfg.AllowPrivate,
			},
			MaxBytes: cfg.HTTPMaxBytes,
		},
		SQL:         sqlsrc.Reader{MaxRows: cfg.SQLMaxRows},
		CSVDir:      cfg.CSVDir,
		ReadFile:    deps.ReadFile,
		CSVMaxBytes: cfg.CSVMaxBytes,
	}
	svc, err := service.New(service.Options{Store: st, Reader: rd, PageSizeMax: cfg.PageSizeMax, Now: deps.Now})
	if err != nil {
		return nil, err
	}
	verify, err := verifier(cfg, deps)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(datasourcev1connect.NewDataSourceServiceHandler(svc,
		connect.WithInterceptors(authz.Interceptor(verify))))
	if len(cfg.AllowHosts) == 0 {
		deps.Log.Warn("no host allowlist, HTTP sources cannot read anything", "setting", config.Prefix+"ALLOW_HOSTS")
	}
	deps.Log.Info("data source ready", "allow_hosts", cfg.AllowHosts, "header_mode", verify == nil, "drivers", sql.Drivers())
	return &App{Mux: mux, Service: svc, Store: st}, nil
}

// verifier returns the session verifier. A nil verifier selects header
// mode, where a gateway verified the session already.
func verifier(cfg config.Config, deps Deps) (authz.Verifier, error) {
	if cfg.AuthJWKSFile == "" {
		return nil, nil
	}
	raw, err := deps.ReadFile(cfg.AuthJWKSFile)
	if err != nil {
		return nil, fmt.Errorf("app: read %s: %w", config.Prefix+"AUTH_JWKS_FILE", err)
	}
	set, err := jose.ParseJWKS(raw)
	if err != nil {
		return nil, err
	}
	return authz.JWKSVerifier(set, deps.Now), nil
}
