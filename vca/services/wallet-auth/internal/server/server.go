// SPDX-License-Identifier: Apache-2.0

// Package server wires the wallet-auth service and runs the HTTP server.
package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1/walletauthv1connect"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/grants"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/limits"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/wallets"
)

// persister returns the document store of the service. An empty dir
// keeps every document in the process.
func persister(dir string) (oidcflow.Persister, error) {
	kv := store.Memory()
	if dir != "" {
		var err error
		if kv, err = store.File(dir); err != nil {
			return nil, err
		}
	}
	return store.NewJSON(kv), nil
}

// Audience is the aud claim of every session JWT.
const Audience = "vca-wallet"

// Build wires the service from the configuration.
func Build(cfg config.Config, log *slog.Logger) (*service.Service, error) {
	persist, err := persister(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	providers, err := oidcflow.NewRegistry(persist, nil)
	if err != nil {
		return nil, err
	}
	if serr := seed(providers, cfg); serr != nil {
		return nil, serr
	}
	walletReg, err := wallets.New(persist, nil)
	if err != nil {
		return nil, err
	}
	key, err := loadKey(cfg.SigningKeyPath, log)
	if err != nil {
		return nil, err
	}
	signer, err := oidcflow.NewSigner(key, cfg.PublicBaseURL, Audience, cfg.SessionTTL, nil)
	if err != nil {
		return nil, err
	}
	csrf, err := oidcflow.NewCSRF(randomIfEmpty(cfg.SessionKey, 32))
	if err != nil {
		return nil, err
	}
	if len(cfg.Salt) == 0 {
		log.Warn("VCA_WALLET_AUTH_SALT is not set: wallet keys change when the service restarts")
		cfg.Salt = randomBytes(32)
	}
	if len(cfg.GrantKey) == 0 {
		log.Warn("VCA_WALLET_AUTH_GRANT_KEY is not set: sealed grants are lost when the service restarts")
		cfg.GrantKey = randomBytes(32)
	}
	vault, err := grants.New(cfg.GrantKey, persist, nil)
	if err != nil {
		return nil, err
	}
	limiter, err := newLimiter(cfg)
	if err != nil {
		return nil, err
	}
	var registrar wallets.Registrar = wallets.LocalRegistrar{}
	if cfg.HolderBackendURL != "" {
		registrar = wallets.NewConnectRegistrar(nil, cfg.HolderBackendURL)
	}
	if cfg.AdminToken == "" {
		log.Warn("VCA_WALLET_AUTH_ADMIN_TOKEN is not set: providers can only come from the environment")
	}
	return service.New(cfg, service.Deps{
		Flow:      &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
		Providers: providers,
		Wallets:   walletReg,
		Registrar: registrar,
		Grants:    vault,
		Limiter:   limiter,
		Signer:    signer,
		CSRF:      csrf,
	}), nil
}

// newLimiter selects Redis when VCA_REDIS_URL is set (ADR-020 decision
// 6). The variable is optional. Empty selects the in-memory limiter,
// which is fine for one replica. This build has no Redis client, so a
// set URL returns limits.ErrNotConfigured and the service refuses to
// start.
func newLimiter(cfg config.Config) (limits.Limiter, error) {
	if cfg.RedisURL != "" {
		return limits.NewRedisLimiter(cfg.RedisURL)
	}
	return limits.NewMemory(cfg.LoginRate, time.Minute, 5*time.Minute, nil), nil
}

// seed registers the provider from the environment under id "default"
// when the environment names one and the registry has no such record.
func seed(reg *oidcflow.Registry, cfg config.Config) error {
	s := cfg.Seed
	if !s.HasSeed() {
		return nil
	}
	if _, err := reg.Get("default"); err == nil {
		return nil
	}
	p := oidcflow.Provider{
		ID:                "default",
		DisplayName:       "Sign in",
		DiscoveryURL:      s.DiscoveryURL,
		ClientID:          s.ClientID,
		Scopes:            []string{"openid"},
		Roles:             []string{"holder"},
		Enabled:           true,
		InternalAuthority: cfg.ProviderInternalAuthority,
	}
	if s.ClientSecret != "" {
		// The variable holds the secret itself. The reference names the
		// variable, so the registry never stores the value.
		p.ClientSecret = oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: config.CommonPrefix + "OIDC_CLIENT_SECRET"}
	}
	_, err := reg.Put(p)
	return err
}

func loadKey(path string, log *slog.Logger) (*ecdsa.PrivateKey, error) {
	if path == "" {
		log.Warn("VCA_SECRETS_SIGNING_KEY is not set: sessions end when the service restarts")
		return oidcflow.GenerateKey()
	}
	raw, err := sharedconfig.ReadKey(os.ReadFile, path)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	return oidcflow.ParseKeyPEM(raw)
}

func randomIfEmpty(v string, n int) []byte {
	if v != "" {
		return []byte(v)
	}
	return randomBytes(n)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// Handler returns the HTTP handler with every route of the service.
func Handler(svc *service.Service) http.Handler {
	mux := http.NewServeMux()
	path, h := walletauthv1connect.NewWalletAuthServiceHandler(svc)
	mux.Handle(path, oidcflow.RejectQueryTokens(h))
	adminPath, adminH := oidcflow.NewAdminHandler(svc.Admin())
	mux.Handle(adminPath, oidcflow.RejectQueryTokens(adminH))
	mux.Handle("/.well-known/jwks.json", svc.Signer().JWKSHandler())
	handlers := svc.Handlers()
	for _, prefix := range []string{"", "/wallet/auth"} {
		// Login starts are rate limited per client address.
		mux.Handle("GET "+prefix+"/login", limits.Middleware(svc.Limiter(), false, oidcflow.RejectQueryTokens(http.HandlerFunc(handlers.Login))))
		mux.Handle("GET "+prefix+"/callback", oidcflow.RejectQueryTokens(http.HandlerFunc(handlers.Callback)))
		mux.Handle("POST "+prefix+"/logout", oidcflow.RejectQueryTokens(http.HandlerFunc(handlers.Logout)))
		mux.Handle("GET "+prefix+"/session", oidcflow.RejectQueryTokens(http.HandlerFunc(handlers.Session)))
	}
	return mux
}

// ReadyMessage returns the body of the readiness response. It reports
// the counts of the service state.
func ReadyMessage(svc *service.Service) func() string {
	return func() string {
		return fmt.Sprintf("ok providers=%d wallets=%d", len(svc.Providers().Enabled()), svc.Wallets().Count())
	}
}
