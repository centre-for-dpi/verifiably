// SPDX-License-Identifier: Apache-2.0

// Package server wires the issuer-auth service and runs the HTTP server.
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

	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/roles"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/store"
)

// Audience is the aud claim of every session JWT.
const Audience = "vca-issuer"

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
	if err := seed(providers, cfg.Seed, cfg.ProviderInternalAuthority); err != nil {
		return nil, err
	}
	mappings, err := roles.NewMappings(persist)
	if err != nil {
		return nil, err
	}
	machine, err := clients.New(persist, nil)
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
	csrf, err := oidcflow.NewCSRF(sessionKey(cfg.SessionKey))
	if err != nil {
		return nil, err
	}
	if cfg.AdminToken == "" {
		log.Warn("VCA_ISSUER_AUTH_ADMIN_TOKEN is not set: only issuer-admin sessions can register providers")
	}
	return service.New(cfg, service.Deps{
		Flow:      &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
		Providers: providers,
		Mappings:  mappings,
		Clients:   machine,
		Signer:    signer,
		CSRF:      csrf,
	}), nil
}

// seed registers the provider from the environment under id "default"
// when the environment names one and the registry has no such record.
func seed(reg *oidcflow.Registry, s config.SeedProvider, internalAuthority string) error {
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
		RolesClaimPath:    s.RolesClaimPath,
		Roles:             []string{"issuer"},
		Enabled:           true,
		InternalAuthority: internalAuthority,
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

func sessionKey(v string) []byte {
	if v != "" {
		return []byte(v)
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}

// Handler returns the HTTP handler with every route of the service.
func Handler(svc *service.Service) http.Handler {
	mux := http.NewServeMux()
	path, h := issuerauthv1connect.NewIssuerAuthServiceHandler(svc)
	mux.Handle(path, oidcflow.RejectQueryTokens(h))
	adminPath, adminH := oidcflow.NewAdminHandler(svc.Admin())
	mux.Handle(adminPath, oidcflow.RejectQueryTokens(adminH))
	mux.Handle("/.well-known/jwks.json", svc.Signer().JWKSHandler())
	mux.Handle("/token", svc.TokenHandler())
	handlers := svc.Handlers()
	handlers.Mount(mux, "")
	handlers.Mount(mux, "/auth")
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "ok providers=%d", len(svc.Providers().Enabled()))
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
	log.Info("issuer-auth listening", "addr", ln.Addr().String())
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
