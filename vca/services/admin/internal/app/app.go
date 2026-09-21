// SPDX-License-Identifier: Apache-2.0

// Package app wires the admin service from its configuration: the record
// store, the audit log, the provider registry, the OpenID Connect login,
// the AdminService handler, the CLI login endpoints, and the portal
// pages (ADR-009, ADR-010).
package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/audit"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/health"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/ui"
	"github.com/centre-for-dpi/vc-adapters/ui/fonts"
	"github.com/centre-for-dpi/vc-adapters/ui/theme"
)

// App is the wired service.
type App struct {
	// Mux serves every path of the service.
	Mux *http.ServeMux
	// Service is the AdminService handler.
	Service *service.Service
	// Login runs the admin logins.
	Login *login.Service
	// Portal serves the admin pages.
	Portal *portal.Portal
	// Config is the configuration the wiring used.
	Config config.Config
	// BootstrapToken is the one time token that binds the first super
	// admin. It is empty when an admin already exists (ADR-010
	// decision 4).
	BootstrapToken string
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// Trust calls the trust registry. Nil builds a Connect client from
	// the configured URL.
	Trust trustv1connect.TrustServiceClient
	// Client calls the providers and the other services. Nil means a
	// client with the configured timeout.
	Client *http.Client
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the service from cfg. It prints the bootstrap token once
// when no super admin exists.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Client == nil {
		deps.Client = &http.Client{Timeout: cfg.Timeout}
	}
	backend := store.Memory()
	if cfg.StateDir != "" {
		var err error
		if backend, err = store.File(filepath.Join(cfg.StateDir, "records")); err != nil {
			return nil, err
		}
	}
	recordStore, err := records.New(backend, deps.Now)
	if err != nil {
		return nil, err
	}
	auditLog, err := audit.New(backend, deps.Now)
	if err != nil {
		return nil, err
	}
	providers, err := oidcflow.NewRegistry(Persister{KV: backend}, deps.Now)
	if err != nil {
		return nil, err
	}
	key, err := loadKey(cfg.SigningKeyPath, deps.Log)
	if err != nil {
		return nil, err
	}
	signer, err := oidcflow.NewSigner(key, cfg.PublicURL, login.Audience, cfg.SessionTTL, nil)
	if err != nil {
		return nil, err
	}
	csrf, err := oidcflow.NewCSRF(sessionKey(cfg.SessionKey))
	if err != nil {
		return nil, err
	}
	vault := onboard.NewVault(cfg.StateDir)
	cache := oidcflow.NewCache(deps.Client, 0)
	loginService, err := login.New(login.Deps{
		Cfg: cfg, Flow: &oidcflow.Flow{Cache: cache, Client: deps.Client, Secrets: vault.Resolve, Now: deps.Now},
		Cache: cache, Providers: providers, Signer: signer, CSRF: csrf,
		Records: recordStore, Audit: auditLog, Client: deps.Client, Now: deps.Now,
	})
	if err != nil {
		return nil, err
	}
	trust := deps.Trust
	if trust == nil && cfg.TrustURL != "" {
		trust = trustv1connect.NewTrustServiceClient(deps.Client, cfg.TrustURL)
	}
	svc, err := service.New(service.Deps{
		Cfg: cfg, Records: recordStore, Audit: auditLog, Login: loginService, Providers: providers,
		Vault: vault, Fetch: deps.Client, Trust: trust,
		Health: health.New(deps.Client, cfg.Timeout, deps.Now), Now: deps.Now,
	})
	if err != nil {
		return nil, err
	}
	pages, err := portal.New(portal.Options{Client: svc, Login: loginService, Prefix: cfg.PortalPrefix})
	if err != nil {
		return nil, err
	}
	assets, err := ui.Assets(theme.DefaultLight(), theme.DefaultDark(), fonts.Default())
	if err != nil {
		return nil, err
	}
	app := &App{Mux: http.NewServeMux(), Service: svc, Login: loginService, Portal: pages, Config: cfg}
	if app.BootstrapToken, err = bootstrap(cfg, recordStore, deps.Log); err != nil {
		return nil, err
	}
	app.mount(assets)
	deps.Log.Info("admin ready",
		"public_url", cfg.PublicURL, "portal", pages.Prefix(),
		"trust_url", cfg.TrustURL, "services", len(cfg.Targets()))
	return app, nil
}

// mount registers every route of the service.
func (a *App) mount(assets http.Handler) {
	path, handler := adminv1connect.NewAdminServiceHandler(a.Service)
	a.Mux.Handle(path, oidcflow.RejectQueryTokens(handler))
	a.Mux.Handle("GET /.well-known/jwks.json", a.Login.Signer().JWKSHandler())
	handlers := a.Login.Handlers()
	a.Mux.Handle("GET /auth/login", oidcflow.RejectQueryTokens(http.HandlerFunc(a.Login.Login)))
	a.Mux.Handle("GET /auth/callback", oidcflow.RejectQueryTokens(http.HandlerFunc(a.Login.Callback)))
	a.Mux.Handle("POST /auth/logout", oidcflow.RejectQueryTokens(http.HandlerFunc(handlers.Logout)))
	a.Mux.Handle("GET /auth/session", oidcflow.RejectQueryTokens(http.HandlerFunc(handlers.Session)))
	a.Login.MountCLI(a.Mux)
	a.Portal.Register(a.Mux)
	a.Mux.Handle("GET "+ui.Prefix, assets)
	prefix := a.Portal.Prefix()
	a.Mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, prefix+"/", http.StatusSeeOther)
	})
}

// bootstrap stores the one time token when no super admin exists. It
// returns the token, or "" when an admin is already bound.
func bootstrap(cfg config.Config, recordStore *records.Store, log *slog.Logger) (string, error) {
	ctx := context.Background()
	count, err := recordStore.CountAdmins(ctx)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", nil
	}
	token := cfg.BootstrapToken
	generated := false
	if token == "" {
		token = records.NewBootstrapToken()
		generated = true
	}
	if err := recordStore.SetBootstrap(ctx, token); err != nil {
		return "", err
	}
	if !recordStore.BootstrapPending(ctx) {
		return "", nil
	}
	if generated {
		log.Warn("no super admin exists: use this one time bootstrap token to bind the first admin",
			"bootstrap_token", token, "login_url", cfg.PublicURL+cfg.PortalPrefix+"/login")
	} else {
		log.Info("no super admin exists: use VCA_ADMIN_BOOTSTRAP_TOKEN to bind the first admin",
			"login_url", cfg.PublicURL+cfg.PortalPrefix+"/login")
	}
	return token, nil
}

// loadKey reads the session signing key, or makes one at start.
func loadKey(path string, log *slog.Logger) (*ecdsa.PrivateKey, error) {
	if path == "" {
		log.Warn("VCA_ADMIN_SIGNING_KEY is not set: sessions end when the service restarts")
		return oidcflow.GenerateKey()
	}
	raw, err := sharedconfig.ReadKey(os.ReadFile, path)
	if err != nil {
		return nil, fmt.Errorf("app: signing key: %w", err)
	}
	return oidcflow.ParseKeyPEM(raw)
}

// sessionKey returns the CSRF key, or a random key at start.
func sessionKey(value string) []byte {
	if len(value) >= 16 {
		return []byte(value)
	}
	// rand.Text returns 26 random characters from crypto/rand. The key
	// lives until the service restarts.
	fresh := rand.Text()
	return []byte(fresh)
}

// Persister stores the provider registry document in the shared key
// value store. It satisfies oidcflow.Persister.
type Persister struct {
	// KV is the backend. It is required.
	KV store.KeyValue
}

// Load implements oidcflow.Persister. A missing document leaves v
// unchanged.
func (p Persister) Load(name string, v any) error {
	raw, err := p.KV.Get(context.Background(), "oidc/"+name)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("app: load %s: %w", name, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("app: load %s: %w", name, err)
	}
	return nil
}

// Save implements oidcflow.Persister.
func (p Persister) Save(name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("app: save %s: %w", name, err)
	}
	if err := p.KV.Put(context.Background(), "oidc/"+name, raw); err != nil {
		return fmt.Errorf("app: save %s: %w", name, err)
	}
	return nil
}
