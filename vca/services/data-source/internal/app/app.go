// SPDX-License-Identifier: Apache-2.0

// Package app wires the data source service from its configuration:
// store, secret resolver, source readers, the SSRF guard, the staff
// guard of the pages and the RPCs, the Connect handler, and the pages.
package app

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuance/v1/issuancev1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/schema/v1/schemav1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/httpsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/reader"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/secrets"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/sqlsrc"
	"github.com/centre-for-dpi/vc-adapters/services/data-source/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/ui"
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
	// SessionKeys replaces the key set of issuer-auth. Tests set it.
	SessionKeys staffsession.Keys
	// Prober replaces the probe of the peers.
	Prober *topology.Prober
	// Schemas replaces the schema registry client of the pages.
	Schemas pages.Schemas
	// Issuance replaces the issuance client of the pages.
	Issuance pages.Issuance
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
	// One guard checks the sessions of issuer-auth on the pages and on
	// every RPC, so no header can stand in for a session (ADR-036
	// decision 3). A CSV upload is the largest form it reads.
	guard, err := staffsession.Build(cfg.Auth, staffsession.IssuerRealm(), config.Prefix, staffsession.Deps{
		Keys: deps.SessionKeys, ReadFile: deps.ReadFile, MaxFormBytes: cfg.CSVMaxBytes + uploadSlack, Now: deps.Now, Log: deps.Log,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(datasourcev1connect.NewDataSourceServiceHandler(svc,
		connect.WithInterceptors(authz.Interceptor(authz.SessionVerifier(guard.Verify)))))
	if err := mountPages(mux, cfg, deps, svc, guard); err != nil {
		return nil, err
	}
	if len(cfg.AllowHosts) == 0 {
		deps.Log.Warn("no host allowlist, HTTP sources cannot read anything", "setting", config.Prefix+"ALLOW_HOSTS")
	}
	deps.Log.Info("data source ready", "allow_hosts", cfg.AllowHosts, "drivers", sql.Drivers(), "issuance", cfg.IssuanceURL != "")
	return &App{Mux: mux, Service: svc, Store: st}, nil
}

// uploadSlack is the room the form of a CSV upload needs beyond the file.
const uploadSlack = 1 << 20

// mountPages adds the data source pages behind the staff guard and the
// shared assets (P3-08, ADR-044 decision 1).
func mountPages(mux *http.ServeMux, cfg config.Config, deps Deps, svc *service.Service, guard *staffsession.Guard) error {
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: cfg.Timeout}
	shell, signOut := staffshell.Wire(staffshell.Setup{
		Role: commonv1.Role_ROLE_ISSUER, Peers: cfg.Peers, Auth: cfg.Auth, PublicURL: cfg.PublicURL,
		SignOut: pages.SignOutPath, Prober: deps.Prober, Client: client, Now: deps.Now,
	})
	opts := pages.Options{
		Kit: kit, Shell: shell, Sources: svc, Schemas: deps.Schemas, Issuance: deps.Issuance,
		AllowHosts: cfg.AllowHosts, AllowHTTP: cfg.AllowHTTP, Drivers: sql.Drivers(),
		UploadMaxBytes: cfg.CSVMaxBytes, RunTimeout: cfg.RunTimeout, SignOut: signOut, Log: deps.Log,
	}
	if opts.Schemas == nil && cfg.SchemaURL != "" {
		opts.Schemas = schemav1connect.NewSchemaServiceClient(client, cfg.SchemaURL)
	}
	if opts.Issuance == nil && cfg.IssuanceURL != "" {
		// The stream of a run lasts longer than one call, so the client
		// has no timeout; the run timeout of the pages bounds it.
		opts.Issuance = issuancev1connect.NewIssuanceServiceClient(&http.Client{}, cfg.IssuanceURL)
	}
	if cfg.CSVDir != "" {
		opts.SaveCSV = csvSaver(cfg.CSVDir)
	}
	p, err := pages.New(opts)
	if err != nil {
		return err
	}
	staff := http.NewServeMux()
	p.Register(staff)
	mux.Handle(pages.Prefix, guard.Wrap(staff))
	mux.Handle("GET "+ui.Prefix, assets)
	return nil
}

// csvSaver keeps an upload as a new file in dir and returns its name,
// which the reader of a CSV source opens in the same directory.
func csvSaver(dir string) func([]byte) (string, error) {
	return func(data []byte) (string, error) {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		name := hex.EncodeToString(raw) + ".csv"
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("app: make the CSV directory: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return "", fmt.Errorf("app: keep the upload: %w", err)
		}
		return name, nil
	}
}
