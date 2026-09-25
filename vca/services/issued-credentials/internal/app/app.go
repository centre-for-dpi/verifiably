// SPDX-License-Identifier: Apache-2.0

// Package app wires the issued credentials service from its
// configuration: the hash chain store, the head signer, the status
// service client, the adapter of the pair, the Connect handler, the
// chain head endpoints, and the issued credentials pages behind the
// staff guard (P3-10).
package app

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issued/v1/issuedv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/status/v1/statusv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffsession"
	"github.com/centre-for-dpi/vc-adapters/services/internal/staffshell"
	sharedstore "github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/head"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/httpapi"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/pages"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/stack"
	"github.com/centre-for-dpi/vc-adapters/services/issued-credentials/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// App is the wired service.
type App struct {
	Mux     *http.ServeMux
	Service *service.Service
	Store   *store.Store
	Signer  *head.Signer
	// PruneInterval is the time between two prune runs. Zero turns the
	// scheduled job off.
	PruneInterval time.Duration
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// ReadFile reads the salt file and the head key file. Nil means
	// os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// HTTPClient calls the status service. Nil means http.DefaultClient.
	HTTPClient connect.HTTPClient
	// Status replaces the status service client. Tests set it. When it
	// is nil the wiring builds a Connect client from the configuration.
	Status statusv1connect.StatusServiceClient
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives start messages. Nil means slog.Default.
	Log *slog.Logger
	// SessionKeys replaces the key set of issuer-auth. Tests set it.
	SessionKeys staffsession.Keys
	// Prober replaces the probe of the peers.
	Prober *topology.Prober
}

// Build wires the service from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
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
	salt, err := salt(cfg, deps)
	if err != nil {
		return nil, err
	}
	signer, err := signer(cfg, deps)
	if err != nil {
		return nil, err
	}
	events, err := auditlog.Open(cfg.AuditDir, deps.Now)
	if err != nil {
		return nil, err
	}
	status := deps.Status
	if status == nil && cfg.StatusURL != "" {
		status = statusv1connect.NewStatusServiceClient(httpClient(cfg, deps), cfg.StatusURL)
	}
	var adapter *stack.Adapter
	if cfg.AdapterURL != "" {
		client := &http.Client{Timeout: cfg.Timeout}
		adapter = stack.New(backendv1connect.NewCapabilityServiceClient(client, cfg.AdapterURL),
			backendv1connect.NewIssuerBackendServiceClient(client, cfg.AdapterURL), stack.DefaultTTL, deps.Now)
	}
	opts := service.Options{
		Store:       st,
		Status:      status,
		Head:        signer,
		Retention:   cfg.Retention,
		Salt:        salt,
		PageSizeMax: cfg.PageSizeMax,
		Now:         deps.Now,
		Audit:       events,
	}
	if adapter != nil {
		opts.Stack = adapter
	}
	svc, err := service.New(opts)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(issuedv1connect.NewIssuedServiceHandler(svc))
	auditPath, auditHandler := auditlog.NewHandler(auditlog.Handler{
		Log: events, Service: service.Name, Authorize: oidcflow.AuditAuthorizer(cfg.AdminToken, cfg.AdminJWKSURL, nil),
	})
	mux.Handle(auditPath, oidcflow.RejectQueryTokens(auditHandler))
	httpapi.Register(mux, svc, signer)
	if err := mountPages(mux, cfg, deps, svc, adapter); err != nil {
		return nil, err
	}
	if status == nil {
		deps.Log.Warn("no status service, revoke and reinstate report a failed precondition",
			"setting", config.Prefix+"STATUS_URL")
	}
	if salt == "" {
		deps.Log.Warn("no subject salt, the subject reference is not hard to guess",
			"setting", config.Prefix+"SALT_FILE")
	}
	deps.Log.Info("issued credentials ready",
		"store_file", cfg.StoreFile, "key_id", signer.KeyID(), "schemas", cfg.Retention.Schemas())
	return &App{Mux: mux, Service: svc, Store: st, Signer: signer, PruneInterval: cfg.PruneInterval}, nil
}

// mountPages adds the issued credentials pages behind the staff guard
// of issuer-auth and the shared assets (P3-10, ADR-044 decision 2). The
// chain head endpoints keep their own, more specific routes, so they
// stay public.
func mountPages(mux *http.ServeMux, cfg config.Config, deps Deps, svc *service.Service, adapter *stack.Adapter) error {
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return err
	}
	guard, err := staffsession.Build(cfg.Auth, staffsession.IssuerRealm(), config.Prefix, staffsession.Deps{
		Keys: deps.SessionKeys, ReadFile: deps.ReadFile, Now: deps.Now, Log: deps.Log,
	})
	if err != nil {
		return err
	}
	shell, signOut := staffshell.Wire(staffshell.Setup{
		Role: commonv1.Role_ROLE_ISSUER, Peers: cfg.Peers, Auth: cfg.Auth, PublicURL: cfg.PublicURL,
		SignOut: pages.SignOutPath, Prober: deps.Prober, Client: &http.Client{Timeout: cfg.Timeout}, Now: deps.Now,
	})
	opts := pages.Options{Kit: kit, Shell: shell, Records: svc, SignOut: signOut}
	if adapter != nil {
		opts.Stack = adapter
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

// httpClient returns the client that calls the status service.
func httpClient(cfg config.Config, deps Deps) connect.HTTPClient {
	if deps.HTTPClient != nil {
		return deps.HTTPClient
	}
	return &http.Client{Timeout: cfg.StatusTimeout}
}

// salt returns the subject salt. The file wins over the variable, so a
// deployment can mount a secret.
func salt(cfg config.Config, deps Deps) (string, error) {
	if cfg.SaltFile == "" {
		return cfg.Salt, nil
	}
	raw, err := deps.ReadFile(cfg.SaltFile)
	if err != nil {
		return "", fmt.Errorf("app: read %s: %w", config.Prefix+"SALT_FILE", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// signer returns the head signer. It generates a key when the
// configuration names no file. A generated key changes on every restart,
// so an auditor must read the key set again.
func signer(cfg config.Config, deps Deps) (*head.Signer, error) {
	var key crypto.PrivateKey
	var err error
	if cfg.HeadKeyFile == "" {
		if key, err = head.GenerateKey(); err != nil {
			return nil, err
		}
	} else {
		raw, rerr := deps.ReadFile(cfg.HeadKeyFile)
		if rerr != nil {
			return nil, fmt.Errorf("app: read %s: %w", config.Prefix+"HEAD_KEY_FILE", rerr)
		}
		if key, err = head.ParsePEM(raw); err != nil {
			return nil, err
		}
	}
	return head.NewSigner(head.Options{Key: key, Issuer: cfg.HeadIssuer, Period: cfg.HeadPeriod})
}

// Prune runs the retention job until ctx ends (ADR-017 decision 5). A
// zero interval returns at once.
func (a *App) Prune(ctx context.Context, log *slog.Logger) {
	if a.PruneInterval <= 0 {
		return
	}
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(a.PruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := a.Service.PruneDue()
			if err != nil {
				log.Error("prune failed", "error", err)
				continue
			}
			if n > 0 {
				log.Info("pruned records whose retention ended", "count", n)
			}
		}
	}
}
