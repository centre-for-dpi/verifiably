// SPDX-License-Identifier: Apache-2.0

// Package server wires the wallet-auth service and runs the HTTP server.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/walletauth/v1/walletauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/grants"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/limits"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/wallet-auth/internal/wallets"
)

// Audience is the aud claim of every session JWT.
const Audience = "vca-wallet"

// Build wires the service from the configuration.
func Build(cfg config.Config, log *slog.Logger) (*service.Service, error) {
	persist, err := store.New(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	providers, err := oidcflow.NewRegistry(persist, nil)
	if err != nil {
		return nil, err
	}
	if err := seed(providers, cfg); err != nil {
		return nil, err
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
// 6). This build has no Redis client, so that path returns
// limits.ErrNotConfigured and the service refuses to start.
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
	if s.ClientSecretEnv != "" {
		p.ClientSecret = oidcflow.SecretRef{Store: oidcflow.SecretEnv, Name: s.ClientSecretEnv}
	}
	_, err := reg.Put(p)
	return err
}

func loadKey(path string, log *slog.Logger) (*ecdsa.PrivateKey, error) {
	if path == "" {
		log.Warn("VCA_SECRETS_SIGNING_KEY is not set: sessions end when the service restarts")
		return oidcflow.GenerateKey()
	}
	raw, err := os.ReadFile(path)
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
	_, _ = rand.Read(b)
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
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "ok providers=%d wallets=%d", len(svc.Providers().Enabled()), svc.Wallets().Count())
	})
	return mux
}

// Run serves h on addr until ctx ends, then drains for up to 5 seconds.
func Run(ctx context.Context, addr string, h http.Handler, log *slog.Logger) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("wallet-auth listening", "addr", ln.Addr().String())
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Healthcheck calls GET /healthz on addr. It backs the -healthcheck flag
// that the container HEALTHCHECK runs (ADR-005 decision 6).
func Healthcheck(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", res.StatusCode)
	}
	return nil
}
