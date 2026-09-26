// SPDX-License-Identifier: Apache-2.0

// Package app wires the Inji DPG adapter from its configuration.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/centre-for-dpi/vc-adapters/gen/vca/backend/v1/backendv1connect"
	"github.com/centre-for-dpi/vc-adapters/gen/vca/datasource/v1/datasourcev1connect"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/authz"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/claims"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/config"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/inji"
	"github.com/centre-for-dpi/vc-adapters/services/dpg-adapter-inji/internal/service"
	"github.com/centre-for-dpi/vc-adapters/services/internal/dpgclient"
	"github.com/centre-for-dpi/vc-adapters/services/internal/oidcflow"
	"github.com/centre-for-dpi/vc-adapters/services/internal/servicetoken"
	"github.com/centre-for-dpi/vc-adapters/services/internal/store"
)

// App is the wired service.
type App struct {
	// Mux serves the Connect routes and the offer endpoint.
	Mux *http.ServeMux
	// Service holds the RPC implementation.
	Service *service.Service
	// Claims writes the VCA claims store. Nil when the configuration
	// names no directory.
	Claims *claims.Writer
	// ClaimsSweep is the interval of Sweep.
	ClaimsSweep time.Duration
	// Authz is the holder authorization server. Nil when the
	// configuration names no issuer for it.
	Authz *authz.Server
}

// Sweep deletes the expired rows of the claims store, the expired
// offers with the subjects they hold, and the expired records of the
// holder authorization server every interval until ctx ends (ADR-056
// decision 4). A write sweeps the rows too, so a row never outlives its
// end by more than one interval.
func (a *App) Sweep(ctx context.Context, log *slog.Logger) {
	if a.Claims == nil {
		return
	}
	ticker := time.NewTicker(a.ClaimsSweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := a.Claims.Sweep(); err != nil {
				log.Warn("the sweep of the claims store failed", "error", err)
			}
			if _, err := a.Service.SweepOffers(ctx); err != nil {
				log.Warn("the sweep of the offers failed", "error", err)
			}
			if a.Authz != nil {
				if _, err := a.Authz.Sweep(ctx); err != nil {
					log.Warn("the sweep of the holder authorization server failed", "error", err)
				}
			}
		}
	}
}

// Deps are the side effects the wiring needs. Tests inject fakes.
type Deps struct {
	// HTTP replaces the transport that calls Inji.
	HTTP *http.Client
	// Store replaces the state store.
	Store store.KeyValue
	// Log receives the start messages. Nil means slog.Default.
	Log *slog.Logger
}

// Build wires the adapter from cfg.
func Build(cfg config.Config, deps Deps) (*App, error) {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	backend := deps.Store
	if backend == nil {
		var err error
		if backend, err = openStore(cfg); err != nil {
			return nil, err
		}
	}
	certify := inji.NewCertify(dpgClient(cfg, deps, cfg.CertifyURL), cfg.MetadataPath)
	var writer *claims.Writer
	if cfg.ClaimsDir != "" {
		writer = &claims.Writer{Dir: cfg.ClaimsDir}
	}
	verify := inji.NewVerify(dpgClient(cfg, deps, cfg.VerifyURL), cfg.VerifyClientID, cfg.VerifyURL)
	svc, err := service.New(service.Options{
		Certify:             certify,
		Verify:              verify,
		Mimoto:              inji.NewMimoto(dpgClient(cfg, deps, cfg.MimotoURL)),
		MimotoProvider:      cfg.MimotoProvider,
		InjiWebURL:          cfg.WebURL,
		Store:               backend,
		DpgVersion:          cfg.DpgVersion,
		PublicURL:           cfg.PublicURL,
		OfferIssuer:         cfg.OfferIssuer,
		AuthorizationServer: cfg.AuthorizationServer,
		AuthzIssuer:         authzIssuer(cfg),
		OfferTTL:            cfg.OfferTTL,
		Versions:            cfg.Versions(),
		Profiles:            cfg.Profiles(),
		RenderingTemplateID: cfg.RenderingTemplateID,
		Plugins:             cfg.Plugins(),
		CADomain:            cfg.CADomain,

		Claims:            writer,
		IARIdentityClaims: cfg.IdentityClaims(),

		PresentationDuringIssuance: cfg.PresentationDuringIssuance,
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(backendv1connect.NewCapabilityServiceHandler(svc))
	mux.Handle(backendv1connect.NewIssuerBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewHolderBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewVerifierBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewCatalogBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewTenantBackendServiceHandler(svc))
	mux.Handle(backendv1connect.NewNotificationBackendServiceHandler(svc))
	// The credential offer endpoint is standards defined, so it stays a
	// plain HTTP handler (ADR-003 decision 7).
	mux.HandleFunc("GET /offers/{id}", offerHandler(svc))
	// Certify reads the presentation definition of a presentation during
	// issuance over HTTP on the compose network (ADR-051 decision 6).
	// The proxy does not publish it.
	mux.HandleFunc("GET /iar/presentation-definition.json", definitionHandler(svc))
	var holder *authz.Server
	if issuer := authzIssuer(cfg); issuer != "" {
		if holder, err = buildAuthz(cfg, deps, backend, svc); err != nil {
			return nil, err
		}
		// The issuer page names the data source of a claim without an
		// offer through the issuer RPCs of the service (ADR-052
		// decision 3).
		svc.UseSignIn(holder)
		// A wallet and Inji Web reach the server under the public URL of
		// the adapter. The proxy of the pair publishes the path (ADR-052
		// decision 1).
		prefix := pathOf(issuer)
		mux.Handle(prefix+"/", http.StripPrefix(prefix, holder.Handler()))
		// vca dpg rotate-authz-key reaches the rotation of the token key
		// on the host port of the adapter. The proxy does not publish it
		// (ADR-056 decision 6).
		mux.Handle(authz.RotatePath, holder.RotationHandler())
		// RFC 8414 section 3 puts the metadata before the path of the
		// issuer. The proxy publishes these paths too.
		for _, path := range holder.WellKnownPaths() {
			mux.Handle("GET "+path, holder.MetadataHandler())
		}
	}
	if cfg.CertifyURL != "" && cfg.PublicURL == "" {
		deps.Log.Warn("no public URL, so the authorization code channel is off",
			"setting", config.Prefix+"PUBLIC_URL")
	}
	if cfg.CertifyURL != "" && cfg.ClaimsDir == "" {
		deps.Log.Warn("no claims store, so Inji Certify has no subject to issue",
			"setting", config.Prefix+"CLAIMS_DIR")
	}
	if cfg.MimotoURL != "" && cfg.StoreFile == "" {
		deps.Log.Warn("no store file, so a restart forgets the Mimoto sessions and every holder signs in again",
			"setting", config.Prefix+"STORE_FILE")
	}
	deps.Log.Info("Inji adapter ready",
		"certify", cfg.CertifyURL != "", "verify", cfg.VerifyURL != "", "mimoto", cfg.MimotoURL != "")
	return &App{Mux: mux, Service: svc, Claims: writer, ClaimsSweep: cfg.ClaimsSweep, Authz: holder}, nil
}

// authzIssuer returns the issuer of the holder authorization server, or
// empty when the adapter serves no issuer role or names no issuer.
func authzIssuer(cfg config.Config) string {
	if cfg.CertifyURL == "" {
		return ""
	}
	return strings.TrimRight(strings.TrimSpace(cfg.AuthzIssuer), "/")
}

// pathOf returns the path of an issuer URL, where the handler mounts.
func pathOf(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return strings.TrimRight(u.Path, "/")
}

// buildAuthz wires the holder authorization server (ADR-052): the
// provider registry in the store of the adapter, seeded with the holder
// provider that setup names, the login flow, the wallet clients, and
// the data source of a claim without an offer.
func buildAuthz(cfg config.Config, deps Deps, backend store.KeyValue, svc *service.Service) (*authz.Server, error) {
	issuer := authzIssuer(cfg)
	if pathOf(issuer) == "" {
		return nil, fmt.Errorf("app: %sAUTHZ_ISSUER needs a path such as /authz, so the server does not take the root", config.Prefix)
	}
	if cfg.AuthzKeySecret == "" {
		return nil, fmt.Errorf("app: %sAUTHZ_KEY_SECRET is empty; it seals the token key of the holder authorization server", config.Prefix)
	}
	clients, err := authz.ParseClients(cfg.WalletClients)
	if err != nil {
		return nil, err
	}
	registry, err := oidcflow.NewRegistry(store.NewJSON(backend), nil)
	if err != nil {
		return nil, err
	}
	if cfg.HolderOIDCDiscoveryURL != "" && cfg.HolderOIDCClientID != "" {
		if err := registry.Seed(oidcflow.SeedProvider(oidcflow.Seed{
			DiscoveryURL: cfg.HolderOIDCDiscoveryURL, ClientID: cfg.HolderOIDCClientID,
			PublicURL: cfg.HolderOIDCPublicURL, InternalAuthority: cfg.HolderOIDCInternalAuthority,
			Roles: []string{"holder"}, Scopes: []string{"openid", "email", "profile"},
		})); err != nil {
			return nil, fmt.Errorf("app: seed the holder provider: %w", err)
		}
		if err := syncVerifiedClaims(registry, cfg.VerifiedClaims()); err != nil {
			return nil, err
		}
	} else {
		deps.Log.Warn("no holder provider is seeded, so a holder signs in only at a provider an admin adds",
			"setting", config.Prefix+"HOLDER_OIDC_DISCOVERY_URL")
	}
	client := deps.HTTP
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	var lookup authz.Lookup
	if cfg.DataSourceURL != "" {
		// The token opens Lookup of the data source of the same pair,
		// which holds the same session key (ADR-052 decision 3).
		lookup = authz.DataSource{
			Client: datasourcev1connect.NewDataSourceServiceClient(client, cfg.DataSourceURL),
			Token:  servicetoken.Derive(cfg.AuthzKeySecret, servicetoken.DataSourceLookup),
		}
	}
	return authz.New(context.Background(), authz.Options{
		Issuer: issuer, Audience: cfg.Audience(), Store: backend, KeySecret: []byte(cfg.AuthzKeySecret),
		Clients: clients, Registry: registry, Flow: &oidcflow.Flow{Cache: oidcflow.NewCache(client, 0), Client: client},
		Offers: svc, Lookup: lookup, Log: deps.Log,
	})
}

// syncVerifiedClaims makes the seeded holder provider list the claims
// of the setting. Seed keeps a record it finds, so each start writes
// the list, and an empty setting clears it (ADR-056 decision 2).
func syncVerifiedClaims(registry *oidcflow.Registry, verified []string) error {
	// Seed wrote the record or found it, so it exists.
	p, err := registry.Get(oidcflow.SeedID)
	if err != nil || slices.Equal(p.VerifiedClaims, verified) {
		return err
	}
	p.VerifiedClaims = verified
	if _, err := registry.Put(p); err != nil {
		return fmt.Errorf("app: write the verified claims of the holder provider: %w", err)
	}
	return nil
}

// definitionHandler serves the presentation definition that the issuer
// set, or 404 before one exists.
func definitionHandler(svc *service.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		definition, ok := svc.PresentationDefinition(r.Context())
		if !ok {
			http.Error(w, "no credential to present is configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := w.Write(definition); err != nil {
			return
		}
	}
}

// offerHandler serves one hosted credential offer to a wallet.
func offerHandler(svc *service.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		document, ok := svc.HostedOffer(r.Context(), r.PathValue("id"))
		if !ok {
			http.Error(w, "the offer does not exist or it expired", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if _, err := w.Write([]byte(document)); err != nil {
			return
		}
	}
}

// openStore returns the state store of the service.
func openStore(cfg config.Config) (store.KeyValue, error) {
	if cfg.StoreFile == "" {
		return store.Memory(), nil
	}
	return store.File(cfg.StoreFile)
}

// dpgClient returns a client for one Inji service, or nil when the
// configuration names no URL for it.
func dpgClient(cfg config.Config, deps Deps, baseURL string) *dpgclient.Client {
	if baseURL == "" {
		return nil
	}
	return dpgclient.New(dpgclient.Options{
		BaseURL:  baseURL,
		Timeout:  cfg.Timeout,
		Retries:  cfg.Retries,
		MaxBytes: cfg.MaxBytes,
		HTTP:     deps.HTTP,
	})
}
