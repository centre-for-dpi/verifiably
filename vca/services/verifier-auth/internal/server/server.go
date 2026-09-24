// SPDX-License-Identifier: Apache-2.0

// Package server wires the verifier-auth service and runs the HTTP server
// (ADR-036 decision 1). The service shares the flow code of oidcflow with
// issuer-auth; its audience is vca-verifier.
package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/verifierauth/v1/verifierauthv1connect"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/signin"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/roles"
	"github.com/centre-for-dpi/vc-adapters/services/verifier-auth/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui"
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
const Audience = "vca-verifier"

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
		log.Warn("VCA_VERIFIER_AUTH_ADMIN_TOKEN is not set: only verifier-admin sessions can register providers")
	}
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return nil, err
	}
	return service.New(cfg, service.Deps{
		Flow:      &oidcflow.Flow{Cache: oidcflow.NewCache(nil, 0)},
		Providers: providers,
		Mappings:  mappings,
		Clients:   machine,
		Signer:    signer,
		CSRF:      csrf,
		Kit:       kit,
		Assets:    assets,
	}), nil
}

// seed registers the provider from the environment under the seed id
// when the environment names one and the registry has no such record.
// The record is of kind keycloak with the realm of the role when the
// discovery URL names a Keycloak realm (ADR-035 decision 2).
func seed(reg *oidcflow.Registry, s config.SeedProvider, internalAuthority string) error {
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
		Roles:             []string{"verifier"},
		InternalAuthority: internalAuthority,
	}))
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

// Handler returns the HTTP handler with every route of the service. The
// sign in chooser, its listing, and the register start sit beside the
// login endpoints at / and at /auth (ADR-035). A build with no kit
// leaves the pages out, which a test of the RPCs alone can use.
func Handler(svc *service.Service) http.Handler {
	mux := http.NewServeMux()
	path, h := verifierauthv1connect.NewVerifierAuthServiceHandler(svc)
	mux.Handle(path, oidcflow.RejectQueryTokens(h))
	adminPath, adminH := oidcflow.NewAdminHandler(svc.Admin())
	mux.Handle(adminPath, oidcflow.RejectQueryTokens(adminH))
	mux.Handle("/.well-known/jwks.json", svc.Signer().JWKSHandler())
	mux.Handle("/token", svc.TokenHandler())
	handlers := svc.Handlers()
	handlers.Mount(mux, "")
	handlers.Mount(mux, "/auth")
	if svc.Kit() == nil {
		return mux
	}
	// The options are complete, so New cannot fail here.
	chooser := anyval.Must(signin.New(signin.Options{
		Kit: svc.Kit(), Role: commonv1.Role_ROLE_VERIFIER, Providers: svc.Providers(), Registrar: svc, Metadata: svc.Flow(),
		LandingURL: svc.Config().LandingURL,
	}))
	chooser.Mount(mux, "")
	chooser.Mount(mux, "/auth")
	if svc.Assets() != nil {
		mux.Handle("GET "+ui.Prefix, svc.Assets())
	}
	return mux
}

// ReadyMessage returns the body of the readiness response. It reports
// the counts of the service state.
func ReadyMessage(svc *service.Service) func() string {
	return func() string {
		return fmt.Sprintf("ok providers=%d", len(svc.Providers().Enabled()))
	}
}
