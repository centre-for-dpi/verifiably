// SPDX-License-Identifier: Apache-2.0

// Package server wires the issuer-auth service and runs the HTTP server.
package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/roles"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/service"
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
const Audience = "vca-issuer"

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
	if serr := seed(providers, cfg.Seed, cfg.ProviderInternalAuthority); serr != nil {
		return nil, serr
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

func sessionKey(v string) []byte {
	if v != "" {
		return []byte(v)
	}
	b := make([]byte, 32)
	// crypto/rand cannot fail on a platform that Go supports.
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
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
	return mux
}

// ReadyMessage returns the body of the readiness response. It reports
// the counts of the service state.
func ReadyMessage(svc *service.Service) func() string {
	return func() string {
		return fmt.Sprintf("ok providers=%d", len(svc.Providers().Enabled()))
	}
}
