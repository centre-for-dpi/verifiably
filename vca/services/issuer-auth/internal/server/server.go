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

	"github.com/centre-for-dpi/vc-adapters/core/anyval"
	commonv1 "github.com/centre-for-dpi/vc-adapters/gen/vca/common/v1"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/issuerauth/v1/issuerauthv1connect"
	"github.com/centre-for-dpi/vc-adapters/services/internal/auditlog"
	sharedconfig "github.com/centre-for-dpi/vc-adapters/services/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/signin"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
	"github.com/centre-for-dpi/vc-adapters/services/internal/uikit"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/clients"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/roles"
	"github.com/centre-for-dpi/vc-adapters/services/issuer-auth/internal/service"
	"github.com/centre-for-dpi/vc-adapters/ui"
)

// keyValue returns the key value store of the service. An empty dir
// keeps every document in the process.
func keyValue(dir string) (store.KeyValue, error) {
	if dir == "" {
		return store.Memory(), nil
	}
	return store.File(dir)
}

// Audience is the aud claim of every session JWT.
const Audience = "vca-issuer"

// Build wires the service from the configuration.
func Build(cfg config.Config, log *slog.Logger) (*service.Service, error) {
	kv, err := keyValue(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	persist := store.NewJSON(kv)
	events, err := auditlog.New(kv, nil)
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
	if cfg.AdminToken == "" && cfg.AdminJWKSURL == "" {
		log.Warn("VCA_ISSUER_AUTH_ADMIN_TOKEN and VCA_ISSUER_AUTH_ADMIN_JWKS_URL are not set: only issuer-admin sessions can register providers")
	}
	cache := oidcflow.NewCache(nil, 0)
	var adminSession oidcflow.Authorizer
	if cfg.AdminJWKSURL != "" {
		adminSession = oidcflow.JWTAuthorizer{JWKSURL: cfg.AdminJWKSURL, Audience: oidcflow.AdminAudience, Cache: cache}.Authorize()
	}
	assets, kit, _, err := uikit.LoadFile(cfg.ThemeFile)
	if err != nil {
		return nil, err
	}
	return service.New(cfg, service.Deps{
		Flow:         &oidcflow.Flow{Cache: cache},
		Providers:    providers,
		Mappings:     mappings,
		Clients:      machine,
		Signer:       signer,
		CSRF:         csrf,
		AdminSession: adminSession,
		Kit:          kit,
		Assets:       assets,
		Audit:        events,
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
		Roles:             []string{"issuer"},
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
	path, h := issuerauthv1connect.NewIssuerAuthServiceHandler(svc)
	mux.Handle(path, oidcflow.RejectQueryTokens(h))
	adminPath, adminH := oidcflow.NewAdminHandler(svc.Admin())
	mux.Handle(adminPath, oidcflow.RejectQueryTokens(adminH))
	auditPath, auditH := auditlog.NewHandler(svc.Audit())
	mux.Handle(auditPath, oidcflow.RejectQueryTokens(auditH))
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
		Kit: svc.Kit(), Role: commonv1.Role_ROLE_ISSUER, Providers: svc.Providers(), Registrar: svc, Metadata: svc.Flow(),
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
