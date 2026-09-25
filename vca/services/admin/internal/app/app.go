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

	"github.com/centre-for-dpi/vc-adapters/core/fetchguard"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/admin/v1/adminv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/trust/v1/trustv1connect"
	"github.com/centre-for-dpi/vc-adapters/internal/topology"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/auditfed"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/fanout"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/health"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/login"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/onboard"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/portal"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/records"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/admin/internal/stacks"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/ui"
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
	// Prober knows which pairs of the deployment run. The provider fan
	// out reads it (ADR-035 decision 5). Nil when the configuration
	// names no peers.
	Prober *topology.Prober
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
	// Prober replaces the prober of the peers. Tests set it. Nil builds
	// one from the configured peers.
	Prober *topology.Prober
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
	auditLog, err := auditlog.New(backend, deps.Now)
	if err != nil {
		return nil, err
	}
	providers, err := oidcflow.NewRegistry(Persister{KV: backend}, deps.Now)
	if err != nil {
		return nil, err
	}
	if serr := seed(providers, cfg.Seed); serr != nil {
		return nil, serr
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
	prober := deps.Prober
	if prober == nil && len(cfg.Peers) > 0 {
		prober = &topology.Prober{Peers: cfg.Peers, Client: deps.Client, Now: deps.Now}
	}
	var push *fanout.FanOut
	var dpgs *stacks.Directory
	if prober != nil {
		dpgs = stacks.New(prober.Snapshot, deps.Client)
		if push, err = fanout.New(fanout.Options{Snapshot: prober.Snapshot, Client: deps.Client, Timeout: cfg.Timeout}); err != nil {
			return nil, err
		}
	} else {
		deps.Log.Warn("no peers: a new provider stays on this service", "setting", topology.Env)
	}
	svc, err := service.New(service.Deps{
		Cfg: cfg, Records: recordStore, Audit: auditLog, Login: loginService, Providers: providers,
		Vault: vault, Fetch: deps.Client, Trust: trust,
		Health: health.New(deps.Client, cfg.Timeout, deps.Now), FanOut: push, Stacks: dpgs, Now: deps.Now,
	})
	if err != nil {
		return nil, err
	}
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return nil, err
	}
	fedOpts := auditfed.Options{Local: svc.Audit(), Self: cfg.PublicURL, Client: deps.Client}
	if prober != nil {
		fedOpts.Snapshot = prober.Snapshot
	}
	federation, err := auditfed.New(fedOpts)
	if err != nil {
		return nil, err
	}
	pagesOpts := portal.Options{
		Client: svc, Login: loginService, Prefix: cfg.PortalPrefix, Kit: kit,
		Audit: federation, Retention: auditLog.Retention,
		LandingURL: cfg.LandingURL, PublicURL: cfg.PublicURL,
		Fetcher: fetchguard.New(fetchguard.Options{
			Guard:  fetchguard.Guard{AllowPrivateNetwork: cfg.AllowPrivateNetwork, AllowPlainHTTP: cfg.AllowPlainHTTP},
			Client: deps.Client, Timeout: cfg.Timeout,
		}),
	}
	if prober != nil {
		pagesOpts.Snapshot = prober.Snapshot
	}
	pages, err := portal.New(pagesOpts)
	if err != nil {
		return nil, err
	}
	app := &App{Mux: http.NewServeMux(), Service: svc, Login: loginService, Portal: pages, Config: cfg, Prober: prober}
	if app.BootstrapToken, err = bootstrap(cfg, recordStore, deps.Log); err != nil {
		return nil, err
	}
	app.mount(assets)
	deps.Log.Info("admin ready",
		"public_url", cfg.PublicURL, "portal", pages.Prefix(),
		"trust_url", cfg.TrustURL, "services", len(cfg.Targets()), "peers", len(cfg.Peers))
	return app, nil
}

// mount registers every route of the service.
func (a *App) mount(assets http.Handler) {
	path, handler := adminv1connect.NewAdminServiceHandler(a.Service)
	a.Mux.Handle(path, oidcflow.RejectQueryTokens(handler))
	auditPath, auditHandler := auditlog.NewHandler(a.Service.Audit())
	a.Mux.Handle(auditPath, oidcflow.RejectQueryTokens(auditHandler))
	a.Mux.Handle("GET /.well-known/jwks.json", a.Login.Signer().JWKSHandler())
	handlers := a.Login.Handlers()
	a.Mux.Handle("GET /auth/login", oidcflow.RejectQueryTokens(http.HandlerFunc(a.Login.Login)))
	a.Mux.Handle("GET /auth/register", oidcflow.RejectQueryTokens(http.HandlerFunc(a.Login.RegisterStart)))
	a.Mux.Handle("GET /auth/callback", oidcflow.RejectQueryTokens(http.HandlerFunc(a.Login.Callback)))
	// The chooser and its listing answer at /auth/ like every auth
	// service, so the landing reaches them the same way (ADR-035).
	chooser := a.Portal.Chooser()
	a.Mux.Handle("GET /auth/{$}", oidcflow.RejectQueryTokens(http.HandlerFunc(chooser.Page)))
	a.Mux.HandleFunc("GET /auth/providers.json", chooser.ProvidersJSON)
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

// seed registers the provider of the stack from the environment under
// the seed id when the environment names one and the registry has no
// such record (ADR-035 decisions 2 and 6). The record is of kind
// keycloak with the admin realm when the discovery URL names a Keycloak
// realm.
func seed(reg *oidcflow.Registry, s config.SeedProvider) error {
	if !s.HasSeed() {
		return nil
	}
	secretEnv := ""
	if s.ClientSecret != "" {
		// The variable holds the secret itself. The reference names the
		// variable, so the registry never stores the value.
		secretEnv = config.CommonPrefix + "OIDC_CLIENT_SECRET"
	}
	return reg.Seed(oidcflow.SeedProvider(oidcflow.Seed{
		DiscoveryURL:      s.DiscoveryURL,
		ClientID:          s.ClientID,
		ClientSecretEnv:   secretEnv,
		PublicURL:         s.PublicURL,
		RolesClaimPath:    s.RolesClaimPath,
		Roles:             []string{"admin"},
		InternalAuthority: s.InternalAuthority,
	}))
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
